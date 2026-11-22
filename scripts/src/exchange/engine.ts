// The engine (SPEC.md §5): a deterministic state machine with the circuits' semantics. It executes
// actions against its copy of the exchange state and, for every segment, records the circuit
// inputs (witness) and the transition the circuit must prove. Divergence between engine and
// circuit makes a batch unprovable, so proveBatch compares them segment by segment.
import type { Barretenberg } from '@aztec-foundation/bb.js';
import { R, daAbsorb, hex } from '../lib.ts';
import { type BatchWitness, type Running, type SegmentWitness, assert, batchStart, copyRunning, runningToNoir } from '../pipeline.ts';
import { type Point, type Sig, sigToNoir, verify, zeroSig } from './grumpkin.ts';
import * as M from './model.ts';
import type { ProtocolAccount } from './params.ts';
import * as X from './rules.ts';
import { type BookSibling, BookTree, MerkleTree } from './tree.ts';

export type AccountRecord = { index: bigint; pub: M.AccountPub; priv: M.AccountPriv; kEnc: bigint };
/** An index update for one market, with the signatures of the publishers that signed it. */
export type OracleUpdate = { market: bigint; price: bigint; external: bigint; time: bigint; sigs: (Sig | undefined)[] };
/** An action as one of its account's keys signed it (SPEC.md §7.1): the master key (MASTER_KEY) or a session-key slot. */
export type SignedAction = { kind: bigint; account: bigint; keyId: bigint; nonce: bigint; p: bigint[]; sig: Sig; pk: { x: bigint; y: bigint } };
export type Rejection = { action: SignedAction; reason: string };
/** A liquidation step (SPEC.md §8.5), as the operator chooses it. A close's size defaults to what
 * the book can absorb within the limit in one step budget. */
export type LiqStep =
  | { kind: 'cancel'; account: bigint; market: number; index: bigint }
  | { kind: 'close'; account: bigint; market: number; lots?: bigint }
  | { kind: 'takeover'; account: bigint; market: number }
  | { kind: 'deficit'; account: bigint }
  | { kind: 'adl'; account: bigint; market: number; counterparty: bigint };
type LiqPlan = { kind: bigint; account: bigint; market: number; other: bigint; lots: bigint; side: bigint; price: bigint; seq: bigint };
type BookOrder = X.Order & { market: bigint };

const PRIORITY_PER_SEGMENT = 4;
const TRADE_PER_SEGMENT = 2;
const UPDATES_PER_BLOCK = 4;
const REFRESH_PER_SEGMENT = 4;
const LIQ_PER_SEGMENT = 2;
const FORCED_CANCELS = 4;
const FILLS = 2;
const zeros = (n: number) => Array<string>(n).fill(hex(0n));
const siblingsToNoir = (path: BookSibling[]) => path.map((s) => ({ hash: hex(s.hash), ask: s.ask.toString(), bid: s.bid.toString() }));
const emptyBookPath = () => siblingsToNoir(Array.from({ length: M.BOOK_HEIGHT }, () => ({ hash: 0n, ask: 0n, bid: 0n })));
const emptyOrder = () => ({ side: hex(0n), account_index: '0', lots: '0', expiry: '0' });
const orderToNoir = (o: { side: bigint; account: bigint; lots: bigint; expiry: bigint }) => ({
  side: hex(o.side),
  account_index: o.account.toString(),
  lots: o.lots.toString(),
  expiry: o.expiry.toString(),
});
const pad = <T>(xs: T[], n: number, f: () => T) => [...xs, ...Array.from({ length: n - xs.length }, f)];

export class Engine {
  readonly api: Barretenberg;
  readonly h: M.H;
  readonly params: M.Params;
  readonly vkTreeRoot: bigint;
  domain = 0n;
  accounts!: MerkleTree;
  activity!: MerkleTree;
  books: BookTree[] = [];
  accts = new Map<bigint, AccountRecord>();
  actv = new Map<bigint, M.Activity>();
  markets: M.Market[] = [];
  refreshCursor = 0n;
  numAccounts = 0n;
  feesPending = 0n;
  insurancePending = 0n;
  insuranceMicro = 0n;
  /** Resting orders, per market, by book index. */
  orders: Map<bigint, BookOrder>[] = [];
  /** Session keys per account: the slots in use and the account's keys tree (SPEC.md §6.4). */
  keys = new Map<bigint, Map<number, M.Key>>();
  keyTrees = new Map<bigint, MerkleTree>();
  /** Encryption keys the operator received at registration, by commitment (SPEC.md §10.1). */
  keyring = new Map<bigint, bigint>();
  /** Actions the engine refused, with the reason (they were never sequenced). */
  rejected: Rejection[] = [];
  /**
   * Rules this engine skips, to build consistent but non-compliant witnesses for adversarial tests
   * (a malicious operator's engine). Empty in any real use.
   */
  relax = new Set<'fills' | 'oracle-sigs' | 'liq'>();

  // The batch being built.
  running!: Running;
  private batchStartRunning!: Running;
  daPayload: bigint[] = [];
  wdRecords: bigint[] = [];
  segments: SegmentWitness[] = [];

  private constructor(api: Barretenberg, params: M.Params, vkTreeRoot: bigint) {
    this.api = api;
    this.h = M.hasher(api);
    this.params = params;
    this.vkTreeRoot = vkTreeRoot;
  }

  /** An engine at genesis, holding the protocol accounts (insurance at 0, fee at 1). */
  static async create(api: Barretenberg, params: M.Params, vkTreeRoot: bigint, protocol: ProtocolAccount[]): Promise<Engine> {
    const e = new Engine(api, params, vkTreeRoot);
    await M.initModel(e.h);
    e.accounts = await new MerkleTree(e.h, M.ACCOUNTS_HEIGHT, M.DS.ACCT_NODE).init();
    e.activity = await new MerkleTree(e.h, M.ACCOUNTS_HEIGHT, M.DS.ACTV_NODE).init();
    for (let m = 0; m < M.MARKETS; m++) {
      e.books.push(await new BookTree(api, M.BOOK_HEIGHT).init());
      e.orders.push(new Map());
      e.markets.push(M.genesisMarket(e.books[m].root));
    }
    for (const [i, a] of protocol.entries()) {
      const idx = BigInt(i);
      const rec: AccountRecord = { index: idx, pub: { ...a.pub }, priv: M.emptyPriv(0n), kEnc: a.kEnc };
      e.accts.set(idx, rec);
      e.actv.set(idx, M.newActivity());
      await e.initKeys(idx);
      e.keyring.set(a.pub.encCommitment, a.kEnc);
      await e.accounts.set(idx, await M.accountLeaf(e.h, rec.pub, rec.priv));
      await e.activity.set(idx, await M.activityHash(e.h, M.newActivity()));
    }
    e.numAccounts = BigInt(protocol.length);
    e.domain = await M.domainOf(e.h, params);
    return e;
  }

  state(): M.State {
    return {
      accountsRoot: this.accounts.root,
      activityRoot: this.activity.root,
      markets: this.markets.map((m, i) => ({ ...m, bookRoot: this.books[i].root })),
      refreshCursor: this.refreshCursor,
      numAccounts: this.numAccounts,
      feesPending: this.feesPending,
      insurancePending: this.insurancePending,
      insuranceMicro: this.insuranceMicro,
    };
  }

  trees(): Promise<bigint> {
    return M.treesOf(this.h, this.state());
  }

  /** Starts a batch from the chain tip (the Bridge's priority head and cursor, and last time). */
  async beginBatch(batch: bigint, priorityHead: bigint, priorityCursor: bigint, lastTime: bigint) {
    this.running = batchStart(await this.trees(), priorityHead, priorityCursor, lastTime, batch);
    this.batchStartRunning = copyRunning(this.running);
    this.daPayload = [];
    this.wdRecords = [];
    this.segments = [];
  }

  async endBatch(): Promise<BatchWitness> {
    const st = this.state();
    const marketData = M.marketData(st.markets);
    return {
      batchNumber: this.running.batch,
      start: this.batchStartRunning,
      segments: this.segments,
      endState: M.stateToNoir(st),
      endAccountsRoot: st.accountsRoot,
      marketData,
      marketDataHash: await M.marketDataHash(this.h, marketData),
      withdrawalRecords: [...this.wdRecords],
      withdrawalsRoot: await this.withdrawalsRoot(),
      daPayload: [...this.daPayload],
    };
  }

  private async withdrawalsRoot(): Promise<bigint> {
    let layer = [...this.wdRecords, ...Array<bigint>(M.MAX_WD_BATCH - this.wdRecords.length).fill(0n)];
    while (layer.length > 1) {
      const next: bigint[] = [];
      for (let i = 0; i < layer.length; i += 2) next.push(await this.h([M.DS.WD_NODE, layer[i], layer[i + 1]]));
      layer = next;
    }
    return layer[0];
  }

  private async absorb(x: bigint) {
    const [da, len] = await daAbsorb(this.api, this.running.da, this.running.daLen, x);
    this.running.da = da;
    this.running.daLen = len;
    this.daPayload.push(x);
  }

  private async emitCiphertexts(rec: AccountRecord, daNonce: bigint, pos: number) {
    const pt = M.plaintext(rec.priv);
    for (let i = 0; i < pt.length; i++) {
      await this.absorb((pt[i] + (await M.keystream(this.h, rec.kEnc, rec.index, daNonce, pos, i))) % R);
    }
  }

  /** A change entry (public part unchanged). */
  private async emitChange(rec: AccountRecord, leaf: bigint, daNonce: bigint) {
    const pos = this.running.daLen;
    for (const x of [M.TAG.CHANGE, rec.index, leaf]) await this.absorb(x);
    await this.emitCiphertexts(rec, daNonce, pos);
  }

  /** A full entry with the public part in clear (registration, refresh). */
  private async emitFull(tag: bigint, rec: AccountRecord, leaf: bigint, daNonce: bigint) {
    const pos = this.running.daLen;
    for (const x of [tag, rec.index, leaf, rec.pub.owner, rec.pub.masterAuth, rec.pub.encCommitment, rec.pub.class]) await this.absorb(x);
    await this.emitCiphertexts(rec, daNonce, pos);
  }

  /** Writes an account's new private part with the blind for the current DA position. */
  private async writeAccount(rec: AccountRecord, priv: M.AccountPriv, daNonce: bigint) {
    rec.priv = { ...priv, blind: await M.blindOf(this.h, rec.kEnc, rec.index, daNonce, this.running.daLen) };
    const leaf = await M.accountLeaf(this.h, rec.pub, rec.priv);
    await this.accounts.set(rec.index, leaf);
    return leaf;
  }

  private async appendWithdrawal(recipient: bigint, amount: bigint, salt: bigint) {
    const r = this.running;
    const record = await M.withdrawalRecord(this.h, recipient, amount, salt, r.batch, r.withdrawalsCount);
    r.withdrawals = await this.h([M.DS.WD_CHAIN, r.withdrawals, record]);
    r.withdrawalsCount += 1;
    r.withdrawalsAmount += amount;
    this.wdRecords.push(record);
    await this.absorb(M.TAG.WD);
    await this.absorb(record);
    return record;
  }

  private async finishSegment(pkg: string, label: string, inputs: Record<string, unknown>) {
    this.running.state = await this.trees();
    this.segments.push({ pkg, label, inputs, expectedEnd: copyRunning(this.running) });
  }

  private base(start: Running, state: M.State) {
    return {
      vk_tree_root: hex(this.vkTreeRoot),
      params: M.paramsToNoir(this.params),
      start: runningToNoir(start),
      state: M.stateToNoir(state),
    };
  }

  // ---- Blocks, oracle updates and ticks (seg_block) ----

  /** The best order on one side of a market's book, as a witness for a tick (SPEC.md §6.5). */
  private topOfBook(m: number, side: bigint) {
    const best = this.best(m, side);
    if (!best) {
      const slot = side === M.SIDE.ASK ? X.RIGHTMOST : X.LEFTMOST;
      return { price: 0n, witness: { has: false, price: '0', seq: '0', order: emptyOrder(), path: siblingsToNoir(this.books[m].path(slot)) } };
    }
    const index = X.orderIndex(best.side, best.price, best.seq);
    return {
      price: best.price,
      witness: { has: true, price: best.price.toString(), seq: best.seq.toString(), order: orderToNoir(best), path: siblingsToNoir(this.books[m].path(index)) },
    };
  }

  /** Block segment: opens an L3 block at `time`, with up to four signed index updates. */
  async block(time: bigint, updates: OracleUpdate[] = []) {
    assert(updates.length <= UPDATES_PER_BLOCK, 'too many updates for one block segment');
    const start = copyRunning(this.running);
    const before = this.state();
    const r = this.running;
    assert(time >= r.time, 'block time regressed');
    r.time = time;
    r.actionLog = await M.logAppend(this.h, r.actionLog, await M.blockHash(this.h, time), M.LOG.BLOCK);
    const witnesses: unknown[] = [];
    for (const u of updates) {
      const m = Number(u.market);
      const mp = this.params.markets[m];
      assert(m < M.MARKETS && mp.imrPpm > 0n, 'market not listed');
      const msg = await M.oracleMessage(this.h, this.domain, u.market, u.price, u.external, u.time);
      let count = 0n;
      for (let j = 0; j < M.N_ORACLES; j++) {
        const s = u.sigs[j];
        if (!s) continue;
        assert(await verify(this.h, { x: this.params.oraclePkX[j], y: this.params.oraclePkY[j] }, s, msg), `bad oracle signature ${j}`);
        count++;
      }
      if (!this.relax.has('oracle-sigs')) assert(count >= this.params.oracleK, 'not enough oracle signatures');
      const mk = this.markets[m];
      assert(u.time > mk.indexTime && u.time <= time, 'oracle update time');
      assert(u.price > 0n && u.price < X.MAX_PRICE && u.external > 0n && u.external < X.MAX_PRICE, 'oracle price out of range');
      const old = mk.indexPrice;
      assert(old === 0n || X.abs(u.price - old) * X.PPM <= old * mp.maxJumpPpm, 'oracle jump too large');
      const bid = this.topOfBook(m, M.SIDE.BID);
      const ask = this.topOfBook(m, M.SIDE.ASK);
      this.markets[m] = { ...X.tick(mk, mp, this.params.fundingInterval, u.price, u.external, u.time, bid.price, ask.price, time), bookRoot: this.books[m].root };
      r.actionLog = await M.logAppend(this.h, r.actionLog, msg, M.LOG.ORACLE);
      witnesses.push({
        market: u.market.toString(),
        price: u.price.toString(),
        external: u.external.toString(),
        time: u.time.toString(),
        signed: Array.from({ length: M.N_ORACLES }, (_, j) => !!u.sigs[j]),
        sigs: Array.from({ length: M.N_ORACLES }, (_, j) => (u.sigs[j] ? sigToNoir(u.sigs[j]!) : zeroSig())),
        bid: bid.witness,
        ask: ask.witness,
      });
    }
    const emptyTop = () => ({ has: false, price: '0', seq: '0', order: emptyOrder(), path: emptyBookPath() });
    const emptyUpdate = () => ({
      market: '0',
      price: '0',
      external: '0',
      time: '0',
      signed: Array(M.N_ORACLES).fill(false),
      sigs: Array.from({ length: M.N_ORACLES }, zeroSig),
      bid: emptyTop(),
      ask: emptyTop(),
    });
    const label = updates.length ? ` ${updates.map((u) => `m${u.market}=${u.price}`).join(' ')}` : '';
    await this.finishSegment('seg_block', `block t=${time}${label}`, {
      ...this.base(start, before),
      block_time: time.toString(),
      n: updates.length,
      updates: pad(witnesses, UPDATES_PER_BLOCK, emptyUpdate),
    });
  }

  // ---- Priority requests (seg_priority) ----

  /**
   * Executes queued priority requests in order: runs of registrations, deposits and forced
   * withdrawals PRIORITY_PER_SEGMENT per seg_priority segment, forced closes and cancellations one
   * per seg_forced segment.
   */
  async priority(reqs: M.Request[]) {
    const needsBook = (q: M.Request) => q.kind === M.KIND.FORCED_CLOSE || q.kind === M.KIND.FORCED_CANCEL_ALL;
    let i = 0;
    while (i < reqs.length) {
      if (needsBook(reqs[i])) {
        await this.forcedSegment(reqs[i++]);
        continue;
      }
      const run: M.Request[] = [];
      while (i < reqs.length && run.length < PRIORITY_PER_SEGMENT && !needsBook(reqs[i])) run.push(reqs[i++]);
      await this.prioritySegment(run);
    }
  }

  private async prioritySegment(reqs: M.Request[]) {
    const start = copyRunning(this.running);
    const before = this.state();
    const r = this.running;
    for (const q of reqs) {
      const entry = await M.requestEntry(this.h, q);
      r.priorityHead = await M.nextHead(this.h, r.priorityHead, entry);
      r.actionLog = await M.logAppend(this.h, r.actionLog, entry, M.LOG.PRIORITY);
    }
    r.priorityCursor += BigInt(reqs.length);
    const daNonce = await M.segmentNonce(this.h, start.batch, r.actionLog, start.daLen);
    await this.absorb(M.TAG.SEG);
    await this.absorb(daNonce);
    const items: unknown[] = [];
    for (const q of reqs) items.push(await this.applyRequest(q, daNonce));
    const kinds = reqs.map((q) => (q.kind === M.KIND.REGISTER ? 'register' : q.kind === M.KIND.DEPOSIT ? 'deposit' : 'forced withdraw')).join(', ');
    await this.finishSegment('seg_priority', `priority [${kinds}]`, {
      ...this.base(start, before),
      n: reqs.length,
      items: pad(items, PRIORITY_PER_SEGMENT, () => this.emptyItem()),
    });
  }

  private emptyItem() {
    return {
      req: M.requestToNoir({ kind: 0n, a: 0n, b: 0n, sender: 0n, time: 0n }),
      account_index: '0',
      acct_pub: M.pubToNoir(M.zeroPub()),
      acct_priv: M.privToNoir(M.emptyPriv()),
      acct_path: zeros(M.ACCOUNTS_HEIGHT),
      actv: M.activityToNoir(M.newActivity()),
      actv_path: zeros(M.ACCOUNTS_HEIGHT),
      k_enc: hex(0n),
    };
  }

  private async applyRequest(q: M.Request, daNonce: bigint) {
    const item = { ...this.emptyItem(), req: M.requestToNoir(q) };
    if (q.kind === M.KIND.REGISTER) {
      const idx = this.numAccounts;
      const kEnc = this.keyring.get(q.b);
      assert(kEnc !== undefined, `no encryption key delivered for commitment ${hex(q.b)}`);
      const rec: AccountRecord = { index: idx, pub: { owner: q.sender, masterAuth: q.a, encCommitment: q.b, class: M.CLASS.USER }, priv: M.emptyPriv(), kEnc };
      Object.assign(item, {
        account_index: idx.toString(),
        acct_path: this.accounts.path(idx).map(hex),
        actv_path: this.activity.path(idx).map(hex),
        k_enc: hex(kEnc),
      });
      const leaf = await this.writeAccount(rec, M.emptyPriv(), daNonce);
      const act = M.newActivity();
      await this.activity.set(idx, await M.activityHash(this.h, act));
      this.accts.set(idx, rec);
      this.actv.set(idx, act);
      await this.initKeys(idx);
      this.numAccounts += 1n;
      await this.emitFull(M.TAG.FULL, rec, leaf, daNonce);
      return item;
    }
    if (q.kind === M.KIND.FORCED_WITHDRAW) return this.applyForcedWithdraw(q, item, daNonce);
    assert(q.kind === M.KIND.DEPOSIT, 'unknown request kind');
    const amount = q.b;
    const rec = q.a < this.numAccounts ? this.accts.get(q.a)! : undefined;
    // A credit that would take collateral out of range is refunded, as for a missing account.
    const credited = !!rec && rec.priv.collateral + amount < X.MAX_COLLATERAL;
    if (rec) {
      Object.assign(item, {
        account_index: q.a.toString(),
        acct_pub: M.pubToNoir(rec.pub),
        acct_priv: M.privToNoir(rec.priv),
        acct_path: this.accounts.path(q.a).map(hex),
        k_enc: hex(rec.kEnc),
      });
    }
    if (!credited) {
      await this.appendWithdrawal(q.sender, amount, await M.requestEntry(this.h, q));
      return item;
    }
    const priv = M.copyPriv(rec!.priv);
    priv.collateral += amount;
    const leaf = await this.writeAccount(rec!, priv, daNonce);
    await this.emitChange(rec!, leaf, daNonce);
    return item;
  }

  /** ForcedWithdraw (seg_priority `forced_withdraw`): the owner's free collateral, to `b`. */
  private async applyForcedWithdraw(q: M.Request, item: any, daNonce: bigint) {
    if (q.a >= this.numAccounts) return item;
    const rec = this.accts.get(q.a)!;
    const act = this.actv.get(q.a)!;
    Object.assign(item, {
      account_index: q.a.toString(),
      acct_pub: M.pubToNoir(rec.pub),
      acct_priv: M.privToNoir(rec.priv),
      actv: M.activityToNoir(act),
      actv_path: this.activity.path(q.a).map(hex),
      acct_path: this.accounts.path(q.a).map(hex),
      k_enc: hex(rec.kEnc),
    });
    let amount = 0n;
    if (rec.pub.owner === q.sender && X.exposureFresh(rec.priv, act, this.markets, this.params.maxAge, this.running.time)) {
      const im = X.initialMargin(rec.priv, act, this.markets, this.params);
      const free = X.equity(rec.priv, this.markets) - (im + X.PPM - 1n) / X.PPM;
      const limit = free < rec.priv.collateral ? free : rec.priv.collateral;
      if (limit > 0n) amount = limit;
    }
    if (amount > 0n) {
      const leaf = await this.writeAccount(rec, { ...M.copyPriv(rec.priv), collateral: rec.priv.collateral - amount }, daNonce);
      await this.emitChange(rec, leaf, daNonce);
      const salt = await this.h([M.DS.WDSALT, rec.kEnc, this.running.batch, BigInt(this.running.withdrawalsCount)]);
      await this.appendWithdrawal(q.b, amount, salt);
    }
    return item;
  }

  /**
   * Forced segment (seg_forced): one ForcedClose or ForcedCancelAll. A request that is not the
   * owner's, or whose fields are out of range, is consumed without effect.
   */
  private async forcedSegment(q: M.Request) {
    const start = copyRunning(this.running);
    const before = this.state();
    const r = this.running;
    const entry = await M.requestEntry(this.h, q);
    r.priorityHead = await M.nextHead(this.h, r.priorityHead, entry);
    r.priorityCursor += 1n;
    r.actionLog = await M.logAppend(this.h, r.actionLog, entry, M.LOG.PRIORITY);
    const daNonce = await M.segmentNonce(this.h, start.batch, r.actionLog, start.daLen);
    await this.absorb(M.TAG.SEG);
    await this.absorb(daNonce);
    const emptyCancel = () => ({ market: '0', side: hex(0n), price: '0', seq: '0', lots: '0', expiry: '0', path: emptyBookPath() });
    const w: any = {
      req: M.requestToNoir(q),
      account_index: '0',
      acct_pub: M.pubToNoir(M.zeroPub()),
      acct_priv: M.privToNoir(M.emptyPriv()),
      k_enc: hex(0n),
      acct_path: zeros(M.ACCOUNTS_HEIGHT),
      actv: M.activityToNoir(M.newActivity()),
      actv_path: zeros(M.ACCOUNTS_HEIGHT),
      n_fills: 0,
      fills: Array.from({ length: FILLS }, () => this.emptyFill()),
      probe_path: emptyBookPath(),
      n_cancels: 0,
      cancels: Array.from({ length: FORCED_CANCELS }, emptyCancel),
    };
    let effect = 'no effect';
    const idx = q.a;
    if (idx < this.numAccounts) {
      const rec = this.accts.get(idx)!;
      const act0 = this.actv.get(idx)!;
      Object.assign(w, { account_index: idx.toString(), acct_pub: M.pubToNoir(rec.pub), acct_priv: M.privToNoir(rec.priv), k_enc: hex(rec.kEnc), actv: M.activityToNoir(act0) });
      const authorized = rec.pub.owner === q.sender;
      let priv = M.copyPriv(rec.priv);
      let act = M.copyActivity(act0);
      let traded = false;
      if (authorized && q.kind === M.KIND.FORCED_CLOSE) {
        const m = Number(q.b);
        const worst = q.c ?? 0n;
        const valid = q.b < BigInt(M.MARKETS) && worst > 0n && worst < X.MAX_PRICE && this.params.markets[m].imrPpm > 0n;
        const pos = valid ? rec.priv.positions[m] : undefined;
        if (valid && pos && pos.size !== 0n) {
          const mp = this.params.markets[m];
          const side = pos.size > 0n ? M.SIDE.ASK : M.SIDE.BID;
          const t = { index: idx, priv, act, traded: false };
          const matched = await this.matchOrder(m, side, worst, X.abs(pos.size), t, daNonce, mp.makerFeePpm, mp.takerFeePpm);
          if (matched.remaining > 0n && matched.fills.length < FILLS) {
            w.probe_path = siblingsToNoir(this.books[m].path(X.orderIndex(side, worst, this.markets[m].nextSeq)));
          }
          this.markets[m].bookRoot = this.books[m].root;
          priv = t.priv;
          act = t.act;
          traded = t.traded;
          Object.assign(w, { n_fills: matched.fills.length, fills: pad(matched.fills, FILLS, () => this.emptyFill()) });
          effect = `closed ${X.abs(pos.size) - matched.remaining} of ${X.abs(pos.size)}`;
        }
      }
      if (authorized && q.kind === M.KIND.FORCED_CANCEL_ALL) {
        const due = act0.openOrders < BigInt(FORCED_CANCELS) ? Number(act0.openOrders) : FORCED_CANCELS;
        const cancels: unknown[] = [];
        for (let m = 0; m < M.MARKETS && cancels.length < due; m++) {
          for (const [index, o] of [...this.orders[m].entries()]) {
            if (cancels.length >= due) break;
            if (o.account !== idx) continue;
            cancels.push({ market: m.toString(), side: hex(o.side), price: o.price.toString(), seq: o.seq.toString(), lots: o.lots.toString(), expiry: o.expiry.toString(), path: siblingsToNoir(this.books[m].path(index)) });
            await this.books[m].set(index, 0n, 0n, 0n);
            this.orders[m].delete(index);
            this.markets[m].bookRoot = this.books[m].root;
            if (o.side === M.SIDE.BID) act.openBid[m] -= o.lots;
            else act.openAsk[m] -= o.lots;
            act.openOrders -= 1n;
          }
        }
        assert(cancels.length === due, 'forced cancel-all could not find the account orders');
        Object.assign(w, { n_cancels: cancels.length, cancels: pad(cancels, FORCED_CANCELS, emptyCancel) });
        effect = `cancelled ${cancels.length}`;
      }
      w.actv_path = this.activity.path(idx).map(hex);
      this.actv.set(idx, act);
      await this.activity.set(idx, await M.activityHash(this.h, act));
      w.acct_path = this.accounts.path(idx).map(hex);
      if (traded) {
        const leaf = await this.writeAccount(rec, priv, daNonce);
        await this.emitChange(rec, leaf, daNonce);
      }
    }
    const kind = q.kind === M.KIND.FORCED_CLOSE ? 'forced close' : 'forced cancel-all';
    await this.finishSegment('seg_forced', `${kind} ${idx} (${effect})`, { ...this.base(start, before), ...w });
  }

  // ---- Maintenance: sweep and refresh (seg_refresh) ----

  private refreshItem(rec?: AccountRecord) {
    if (!rec) return { pub_part: M.pubToNoir(M.zeroPub()), priv_part: M.privToNoir(M.emptyPriv()), path: zeros(M.ACCOUNTS_HEIGHT), k_enc: hex(0n) };
    return { pub_part: M.pubToNoir(rec.pub), priv_part: M.privToNoir(rec.priv), path: this.accounts.path(rec.index).map(hex), k_enc: hex(rec.kEnc) };
  }

  /**
   * Maintenance segment (SPEC.md §8.6, §9.5): optionally sweeps collected fees into the fee account
   * and whole micro-units of funding remainders into the insurance account, then republishes the
   * next `refresh` accounts after the refresh cursor under fresh keystreams.
   */
  async maintenance(opts: { sweep?: boolean; refresh?: number }) {
    const n = opts.refresh ?? 0;
    assert(n <= REFRESH_PER_SEGMENT && BigInt(n) <= this.numAccounts, 'refresh count');
    const start = copyRunning(this.running);
    const before = this.state();
    const daNonce = await M.segmentNonce(this.h, start.batch, start.actionLog, start.daLen);
    await this.absorb(M.TAG.SEG);
    await this.absorb(daNonce);
    const protocol: unknown[] = [];
    const swept: string[] = [];
    if (opts.sweep) {
      for (const idx of [M.INSURANCE_INDEX, M.FEE_INDEX]) {
        const rec = this.accts.get(idx)!;
        protocol.push(this.refreshItem(rec));
        const credit = idx === M.INSURANCE_INDEX ? this.insurancePending + this.insuranceMicro / X.MICRO : this.feesPending;
        const priv = M.copyPriv(rec.priv);
        priv.collateral += credit;
        assert(X.abs(priv.collateral) < X.MAX_COLLATERAL, 'collateral out of range');
        const leaf = await this.writeAccount(rec, priv, daNonce);
        await this.emitChange(rec, leaf, daNonce);
        swept.push(`${idx === M.INSURANCE_INDEX ? 'insurance' : 'fees'} +${credit}`);
      }
      this.insuranceMicro %= X.MICRO;
      this.insurancePending = 0n;
      this.feesPending = 0n;
    } else {
      protocol.push(this.refreshItem(), this.refreshItem());
    }
    const items: unknown[] = [];
    const indices: bigint[] = [];
    for (let i = 0; i < n; i++) {
      const rec = this.accts.get(this.refreshCursor)!;
      items.push(this.refreshItem(rec));
      await this.emitFull(M.TAG.REFRESH, rec, await M.accountLeaf(this.h, rec.pub, rec.priv), daNonce);
      indices.push(rec.index);
      this.refreshCursor = rec.index + 1n === this.numAccounts ? 0n : rec.index + 1n;
    }
    const label = [opts.sweep ? `sweep (${swept.join(', ')})` : '', n ? `refresh [${indices.join(', ')}]` : ''].filter(Boolean).join(', ');
    await this.finishSegment('seg_refresh', label || 'maintenance', {
      ...this.base(start, before),
      sweep: !!opts.sweep,
      protocol,
      n,
      items: pad(items, REFRESH_PER_SEGMENT, () => this.refreshItem()),
    });
  }

  /** Convenience: refresh only. */
  refresh(n: number) {
    return this.maintenance({ refresh: n });
  }

  // ---- Trading (seg_trade, SPEC.md §8) ----

  snapshot() {
    return {
      accounts: this.accounts.snapshot(),
      activity: this.activity.snapshot(),
      books: this.books.map((b) => b.snapshot()),
      accts: new Map([...this.accts].map(([k, v]) => [k, { ...v, pub: { ...v.pub }, priv: M.copyPriv(v.priv) }])),
      actv: new Map([...this.actv].map(([k, v]) => [k, M.copyActivity(v)])),
      orders: this.orders.map((o) => new Map([...o].map(([k, v]) => [k, { ...v }]))),
      keys: new Map([...this.keys].map(([k, v]) => [k, new Map([...v].map(([i, x]) => [i, { ...x }]))])),
      keyTrees: new Map([...this.keyTrees].map(([k, t]) => [k, t.snapshot()])),
      markets: this.markets.map((m) => ({ ...m })),
      feesPending: this.feesPending,
      insurancePending: this.insurancePending,
      insuranceMicro: this.insuranceMicro,
      running: copyRunning(this.running),
      daPayload: [...this.daPayload],
      wdRecords: [...this.wdRecords],
    };
  }

  restore(s: ReturnType<Engine['snapshot']>) {
    this.accounts.restore(s.accounts);
    this.activity.restore(s.activity);
    this.books.forEach((b, i) => b.restore(s.books[i]));
    this.accts = s.accts;
    this.actv = s.actv;
    this.orders = s.orders;
    this.keys = s.keys;
    for (const [k, t] of this.keyTrees) {
      const saved = s.keyTrees.get(k);
      if (saved) t.restore(saved);
      else this.keyTrees.delete(k);
    }
    this.markets = s.markets;
    this.feesPending = s.feesPending;
    this.insurancePending = s.insurancePending;
    this.insuranceMicro = s.insuranceMicro;
    this.running = s.running;
    this.daPayload = s.daPayload;
    this.wdRecords = s.wdRecords;
  }

  /**
   * Executes signed actions in order, TRADE_PER_SEGMENT per segment. An action the rules reject
   * (bad signature, nonce, margin, more fills than a segment allows...) is dropped and recorded
   * in `rejected`, as a gateway would refuse it before sequencing.
   */
  async trade(actions: SignedAction[]) {
    const queue = [...actions];
    while (queue.length) {
      // Fill a segment from the queue; a rejected action is dropped and its slot refilled.
      const batch: SignedAction[] = [];
      for (;;) {
        while (batch.length < TRADE_PER_SEGMENT && queue.length) batch.push(queue.shift()!);
        if (!batch.length) break;
        const snap = this.snapshot();
        try {
          await this.tradeSegment(batch);
          break;
        } catch (e: any) {
          this.restore(snap);
          const k = e.actionIndex ?? 0;
          this.rejected.push({ action: batch[k], reason: String(e.message ?? e) });
          batch.splice(k, 1);
        }
      }
    }
  }

  private async tradeSegment(actions: SignedAction[]) {
    const start = copyRunning(this.running);
    const before = this.state();
    const r = this.running;
    for (const a of actions) {
      r.actionLog = await M.logAppend(this.h, r.actionLog, await X.actionMsg(this.h, this.domain, a.kind, a.account, a.keyId, a.nonce, a.p), M.LOG.SIGNED);
    }
    const daNonce = await M.segmentNonce(this.h, start.batch, r.actionLog, start.daLen);
    await this.absorb(M.TAG.SEG);
    await this.absorb(daNonce);
    const items: unknown[] = [];
    for (const [i, a] of actions.entries()) {
      try {
        items.push(await this.execAction(a, daNonce));
      } catch (e: any) {
        e.actionIndex = i;
        throw e;
      }
    }
    const names: Record<string, string> = { [X.KIND_ACT.WITHDRAW.toString()]: 'withdraw', [X.KIND_ACT.ADD_KEY.toString()]: 'add key', [X.KIND_ACT.REVOKE_KEY.toString()]: 'revoke key' };
    const labels = actions.map((a) => {
      const by = a.keyId === M.MASTER_KEY ? '' : ` by key ${a.keyId}`;
      return (a.kind === X.KIND_ACT.PLACE ? `place m${a.p[0]}` : a.kind === X.KIND_ACT.CANCEL ? `cancel m${a.p[0]}` : names[a.kind.toString()]) + by;
    });
    await this.finishSegment('seg_trade', `trade [${labels.join(', ')}]`, {
      ...this.base(start, before),
      n: actions.length,
      actions: pad(items, TRADE_PER_SEGMENT, () => this.emptyAction()),
    });
  }

  private emptyFill() {
    return {
      index: hex(0n),
      price: '0',
      seq: '0',
      order: emptyOrder(),
      book_path: emptyBookPath(),
      maker_pub: M.pubToNoir(M.zeroPub()),
      maker_priv: M.privToNoir(M.emptyPriv()),
      maker_acct_path: zeros(M.ACCOUNTS_HEIGHT),
      maker_k_enc: hex(0n),
      maker_actv: M.activityToNoir(M.newActivity()),
      maker_actv_path: zeros(M.ACCOUNTS_HEIGHT),
    };
  }

  private emptyAction() {
    return {
      kind: hex(0n),
      account_index: '0',
      key_id: '0',
      nonce: '0',
      p: zeros(X.ACTION_PAYLOAD),
      pk_x: hex(0n),
      pk_y: hex(0n),
      sig: zeroSig(),
      key: M.keyToNoir(M.emptyKey()),
      key_path: zeros(M.KEYS_HEIGHT),
      taker_pub: M.pubToNoir(M.zeroPub()),
      taker_priv: M.privToNoir(M.emptyPriv()),
      taker_k_enc: hex(0n),
      taker_acct_path: zeros(M.ACCOUNTS_HEIGHT),
      taker_actv: M.activityToNoir(M.newActivity()),
      taker_actv_path: zeros(M.ACCOUNTS_HEIGHT),
      n_fills: 0,
      fills: Array.from({ length: FILLS }, () => this.emptyFill()),
      rest_path: emptyBookPath(),
      cancel_lots: '0',
      cancel_expiry: '0',
    };
  }

  /** The best resting order on `side` of market m: the lowest ask or the highest bid (SPEC.md §6.5). */
  private best(m: number, side: bigint): BookOrder | undefined {
    let best: [bigint, BookOrder] | undefined;
    for (const [idx, o] of this.orders[m]) {
      if (o.side !== side) continue;
      if (!best || (side === M.SIDE.ASK ? idx < best[0] : idx > best[0])) best = [idx, o];
    }
    return best?.[1];
  }

  private crosses(side: bigint, price: bigint, o: BookOrder | undefined) {
    return !!o && (side === M.SIDE.BID ? o.price <= price : o.price >= price);
  }

  private shiftOi(m: number, before: bigint, after: bigint) {
    const long = (x: bigint) => (x > 0n ? x : 0n);
    const short = (x: bigint) => (x < 0n ? -x : 0n);
    this.markets[m].oiLong += long(after) - long(before);
    this.markets[m].oiShort += short(after) - short(before);
  }

  /** Gives a new account an empty keys tree. */
  private async initKeys(index: bigint) {
    this.keys.set(index, new Map());
    this.keyTrees.set(index, await new MerkleTree(this.h, M.KEYS_HEIGHT, M.DS.KEY_NODE).init());
  }

  keyOf(account: bigint, slot: number): M.Key {
    return this.keys.get(account)?.get(slot) ?? M.emptyKey();
  }

  private async writeKey(account: bigint, slot: number, k: M.Key) {
    this.keys.get(account)!.set(slot, k);
    const tree = this.keyTrees.get(account)!;
    await tree.set(BigInt(slot), await M.keyLeaf(this.h, k));
    return tree.root;
  }

  private async execAction(a: SignedAction, daNonce: bigint) {
    const rec = this.accts.get(a.account);
    const oldAct = this.actv.get(a.account);
    if (!rec || !oldAct) throw new Error('no such account');
    const msg = await X.actionMsg(this.h, this.domain, a.kind, a.account, a.keyId, a.nonce, a.p);
    // Authorization (SPEC.md §7.2): the master key, or a session key within its scope.
    const act = M.copyActivity(oldAct);
    let keyWitness = { key: M.keyToNoir(M.emptyKey()), key_path: zeros(M.KEYS_HEIGHT) };
    if (a.keyId === M.MASTER_KEY) {
      if ((await M.masterAuthOf(this.h, a.pk.x, a.pk.y)) !== rec.pub.masterAuth) throw new Error("signing key is not the account's");
      if (!(await verify(this.h, a.pk, a.sig, msg))) throw new Error('bad signature');
      if (oldAct.nonce + 1n !== a.nonce) throw new Error('nonce');
      act.nonce = a.nonce;
    } else {
      const slot = Number(a.keyId);
      if (a.keyId < 0n || slot >= M.KEY_SLOTS) throw new Error('key slot');
      const key = this.keyOf(a.account, slot);
      if (key.pkX !== a.pk.x || key.pkY !== a.pk.y || (a.pk.x === 0n && a.pk.y === 0n)) throw new Error("signing key is not the slot's");
      if (!(await verify(this.h, a.pk, a.sig, msg))) throw new Error('bad signature');
      if (key.nonce + 1n !== a.nonce) throw new Error('nonce');
      if (this.running.time > key.expiry) throw new Error('session key expired');
      if (a.kind !== X.KIND_ACT.PLACE && a.kind !== X.KIND_ACT.CANCEL) throw new Error('session keys only place and cancel');
      if (a.p[0] >= BigInt(M.MARKETS) || ((key.marketMask >> a.p[0]) & 1n) !== 1n) throw new Error('market not allowed for the session key');
      if (a.kind === X.KIND_ACT.PLACE && a.p[2] * a.p[3] > key.maxNotional) throw new Error("order above the session key's notional limit");
      keyWitness = { key: M.keyToNoir(key), key_path: this.keyTrees.get(a.account)!.path(BigInt(slot)).map(hex) };
      act.keysRoot = await this.writeKey(a.account, slot, { ...key, nonce: a.nonce });
    }
    const common = {
      kind: hex(a.kind),
      account_index: a.account.toString(),
      key_id: a.keyId.toString(),
      nonce: a.nonce.toString(),
      p: a.p.map(hex),
      pk_x: hex(a.pk.x),
      pk_y: hex(a.pk.y),
      sig: sigToNoir(a.sig),
      ...keyWitness,
      taker_pub: M.pubToNoir(rec.pub),
      taker_priv: M.privToNoir(rec.priv),
      taker_k_enc: hex(rec.kEnc),
      taker_actv: M.activityToNoir(oldAct),
    };
    if (a.kind === X.KIND_ACT.PLACE) return { ...this.emptyAction(), ...common, ...(await this.execPlace(a, rec, oldAct, act, daNonce)) };
    if (a.kind === X.KIND_ACT.CANCEL) return { ...this.emptyAction(), ...common, ...(await this.execCancel(a, act)) };
    if (a.kind === X.KIND_ACT.WITHDRAW) return { ...this.emptyAction(), ...common, ...(await this.execWithdraw(a, rec, act, daNonce)) };
    if (a.kind === X.KIND_ACT.ADD_KEY || a.kind === X.KIND_ACT.REVOKE_KEY) return { ...this.emptyAction(), ...common, ...(await this.execSetKey(a, act)) };
    throw new Error('unknown action kind');
  }

  /** AddKey and RevokeKey (seg_trade `set_key`): master only; the slot keeps its nonce. */
  private async execSetKey(a: SignedAction, act: M.Activity) {
    const slot = Number(a.p[0]);
    if (a.p[0] < 0n || slot >= M.KEY_SLOTS) throw new Error('key slot');
    const old = this.keyOf(a.account, slot);
    const keyPath = this.keyTrees.get(a.account)!.path(BigInt(slot)).map(hex);
    let k: M.Key;
    if (a.kind === X.KIND_ACT.ADD_KEY) {
      if (a.p[1] === 0n && a.p[2] === 0n) throw new Error('empty key');
      k = { pkX: a.p[1], pkY: a.p[2], marketMask: a.p[3], maxNotional: a.p[4], expiry: a.p[5], nonce: old.nonce };
    } else {
      k = { ...M.emptyKey(), nonce: old.nonce };
    }
    const acctPath = this.accounts.path(a.account).map(hex);
    act.keysRoot = await this.writeKey(a.account, slot, k);
    const actvPath = this.activity.path(a.account).map(hex);
    this.actv.set(a.account, act);
    await this.activity.set(a.account, await M.activityHash(this.h, act));
    return { key: M.keyToNoir(old), key_path: keyPath, taker_acct_path: acctPath, taker_actv_path: actvPath };
  }

  private async execPlace(a: SignedAction, rec: AccountRecord, oldAct: M.Activity, act: M.Activity, daNonce: bigint) {
    const [mk, side, price, lots, tif, reduceOnly, expiry] = a.p;
    const m = Number(mk);
    if (mk < 0n || m >= M.MARKETS || this.params.markets[m].imrPpm === 0n) throw new Error('market not listed');
    const mp = this.params.markets[m];
    if (side !== M.SIDE.BID && side !== M.SIDE.ASK) throw new Error('side');
    if (price <= 0n || price >= X.MAX_PRICE || lots <= 0n || lots >= X.MAX_LOTS) throw new Error('price or lots out of range');
    if (![X.TIF.GTC, X.TIF.IOC, X.TIF.FOK, X.TIF.POST_ONLY, X.TIF.GTT].includes(tif as any)) throw new Error('time in force');
    if (reduceOnly !== 0n && reduceOnly !== 1n) throw new Error('reduce-only flag');
    const rests = tif === X.TIF.GTC || tif === X.TIF.POST_ONLY || tif === X.TIF.GTT;
    if (a.p[7] !== 0n) throw new Error('expiry');
    if ((tif === X.TIF.GTT) !== (expiry !== 0n)) throw new Error('only GTT orders expire');
    if (expiry !== 0n && expiry <= this.running.time) throw new Error('order already expired');
    if (reduceOnly === 1n && rests) throw new Error('reduce-only orders cannot rest');
    const mark = this.markets[m].markPrice;
    if (mark === 0n) throw new Error('no mark price');
    if (X.abs(price - mark) * X.PPM > mark * mp.priceBandPpm) throw new Error('limit price outside the band');

    const taker = M.copyPriv(rec.priv);
    const sizeBefore = rec.priv.positions[m].size;
    const book = this.books[m];
    const t = { index: a.account, priv: taker, act, traded: false };
    const matched = await this.matchOrder(m, side, price, lots, t, daNonce, mp.makerFeePpm, mp.takerFeePpm, tif === X.TIF.POST_ONLY);
    const { fills } = matched;
    const remaining = matched.remaining;
    const traded = t.traded;
    if (tif === X.TIF.FOK && remaining !== 0n) throw new Error('fill-or-kill order not filled');
    if (reduceOnly === 1n) {
      if (sizeBefore === 0n || sizeBefore > 0n !== (side === M.SIDE.ASK)) throw new Error('reduce-only order must reduce');
      if (lots - remaining > X.abs(sizeBefore)) throw new Error('reduce-only order would flip the position');
    }

    let restPath = emptyBookPath();
    if (remaining > 0n) {
      const best = this.best(m, side === M.SIDE.BID ? M.SIDE.ASK : M.SIDE.BID);
      if (!this.relax.has('fills') && this.crosses(side, price, best)) throw new Error(`order needs more than ${FILLS} matching steps`);
      const seq = this.markets[m].nextSeq;
      const slot = X.orderIndex(side, price, seq);
      restPath = siblingsToNoir(book.path(slot));
      if (rests) {
        await book.set(slot, await X.orderLeaf(this.h, side, a.account, remaining, expiry), X.askLots({ side, lots: remaining }), X.bidLots({ side, lots: remaining }));
        this.orders[m].set(slot, { side, account: a.account, lots: remaining, price, seq, market: mk, expiry });
        this.markets[m].nextSeq = seq + 1n;
        if (side === M.SIDE.BID) act.openBid[m] += remaining;
        else act.openAsk[m] += remaining;
        act.openOrders += 1n;
        if (act.openOrders > X.MAX_OPEN_ORDERS) throw new Error('too many open orders');
      }
    }
    this.markets[m].bookRoot = book.root;

    const acctPath = this.accounts.path(a.account).map(hex);
    if (traded) {
      const leaf = await this.writeAccount(rec, taker, daNonce);
      await this.emitChange(rec, leaf, daNonce);
    }
    const actvPath = this.activity.path(a.account).map(hex);
    this.actv.set(a.account, act);
    await this.activity.set(a.account, await M.activityHash(this.h, act));

    const wBefore = X.worst(sizeBefore, oldAct.openBid[m], oldAct.openAsk[m]);
    const wAfter = X.worst(rec.priv.positions[m].size, act.openBid[m], act.openAsk[m]);
    if (wAfter > wBefore) {
      if (!X.exposureFresh(rec.priv, act, this.markets, this.params.maxAge, this.running.time)) throw new Error('index too old for a risk-increasing order');
      if (!X.covers(X.equity(rec.priv, this.markets), X.initialMargin(rec.priv, act, this.markets, this.params))) throw new Error('insufficient margin');
    }
    return {
      taker_acct_path: acctPath,
      taker_actv_path: actvPath,
      n_fills: fills.length,
      fills: pad(fills, FILLS, () => this.emptyFill()),
      rest_path: restPath,
    };
  }

  /**
   * Matches up to `lots` on `side` with limit `limit` against the best opposite orders of market m,
   * in up to FILLS steps (matching.nr `match_order`). Makers are written and published here; the
   * taker `t` is updated in memory. Returns the step witnesses, the unfilled lots and the notional.
   */
  private async matchOrder(
    m: number,
    side: bigint,
    limit: bigint,
    lots: bigint,
    t: { index: bigint; priv: M.AccountPriv; act: M.Activity; traded: boolean },
    daNonce: bigint,
    makerFeePpm: bigint,
    takerFeePpm: bigint,
    postOnly = false,
  ) {
    let remaining = lots;
    let notional = 0n;
    const fills: unknown[] = [];
    const book = this.books[m];
    while (remaining > 0n && fills.length < FILLS) {
      const best = this.best(m, side === M.SIDE.BID ? M.SIDE.ASK : M.SIDE.BID);
      if (!this.crosses(side, limit, best)) break;
      if (postOnly) throw new Error('post-only order would take liquidity');
      const o = best!;
      const index = X.orderIndex(o.side, o.price, o.seq);
      const fillWitness: any = { ...this.emptyFill(), index: hex(index), price: o.price.toString(), seq: o.seq.toString(), order: orderToNoir(o), book_path: siblingsToNoir(book.path(index)) };
      if (o.account === t.index) {
        // Self-trade prevention: the taker's own resting order is cancelled.
        await book.set(index, 0n, 0n, 0n);
        this.orders[m].delete(index);
        if (o.side === M.SIDE.BID) t.act.openBid[m] -= o.lots;
        else t.act.openAsk[m] -= o.lots;
        t.act.openOrders -= 1n;
        fills.push(fillWitness);
        continue;
      }
      if (X.expired(o, this.running.time)) {
        // An expired GTT order is removed instead of filled; its owner's open lots shrink.
        const oact = this.actv.get(o.account)!;
        Object.assign(fillWitness, { maker_actv: M.activityToNoir(oact), maker_actv_path: this.activity.path(o.account).map(hex) });
        await book.set(index, 0n, 0n, 0n);
        this.orders[m].delete(index);
        const nact = M.copyActivity(oact);
        if (o.side === M.SIDE.BID) nact.openBid[m] -= o.lots;
        else nact.openAsk[m] -= o.lots;
        nact.openOrders -= 1n;
        this.actv.set(o.account, nact);
        await this.activity.set(o.account, await M.activityHash(this.h, nact));
        fills.push(fillWitness);
        continue;
      }
      const maker = this.accts.get(o.account)!;
      const mact = this.actv.get(o.account)!;
      Object.assign(fillWitness, {
        maker_pub: M.pubToNoir(maker.pub),
        maker_priv: M.privToNoir(maker.priv),
        maker_acct_path: this.accounts.path(o.account).map(hex),
        maker_k_enc: hex(maker.kEnc),
        maker_actv: M.activityToNoir(mact),
        maker_actv_path: this.activity.path(o.account).map(hex),
      });
      fills.push(fillWitness);
      const q = remaining < o.lots ? remaining : o.lots;
      const left = o.lots - q;
      await book.set(index, await X.orderLeaf(this.h, o.side, o.account, left, o.expiry), X.askLots({ side: o.side, lots: left }), X.bidLots({ side: o.side, lots: left }));
      if (left === 0n) this.orders[m].delete(index);
      else this.orders[m].set(index, { ...o, lots: left });

      // Maker: funding, fill, fee, leaf, open lots.
      const cum = this.markets[m].cumFunding;
      const mpriv = M.copyPriv(maker.priv);
      const [mc, mpos, mdust] = X.settleFunding(mpriv.collateral, mpriv.positions[m], cum);
      this.insuranceMicro += mdust;
      const dm = o.side === M.SIDE.BID ? q : -q;
      const [ms, me, mpnl] = X.fill(mpos.size, mpos.entry, dm, o.price);
      const mfee = X.fee(q, o.price, makerFeePpm);
      this.shiftOi(m, mpos.size, ms);
      mpriv.positions[m] = { size: ms, entry: me, funding: mpos.funding };
      mpriv.collateral = mc + mpnl - mfee;
      if (X.abs(mpriv.collateral) >= X.MAX_COLLATERAL) throw new Error('collateral out of range');
      this.feesPending += mfee;
      const mleaf = await this.writeAccount(maker, mpriv, daNonce);
      await this.emitChange(maker, mleaf, daNonce);
      const nact = M.copyActivity(mact);
      if (o.side === M.SIDE.BID) nact.openBid[m] -= q;
      else nact.openAsk[m] -= q;
      if (left === 0n) nact.openOrders -= 1n;
      this.actv.set(maker.index, nact);
      await this.activity.set(maker.index, await M.activityHash(this.h, nact));

      // Taker, in memory.
      if (!t.traded) {
        const [c, pos, dust] = X.settleFunding(t.priv.collateral, t.priv.positions[m], cum);
        t.priv.collateral = c;
        t.priv.positions[m] = pos;
        this.insuranceMicro += dust;
        t.traded = true;
      }
      const tpos = t.priv.positions[m];
      const [ts, te, tpnl] = X.fill(tpos.size, tpos.entry, -dm, o.price);
      const tfee = X.fee(q, o.price, takerFeePpm);
      this.shiftOi(m, tpos.size, ts);
      t.priv.positions[m] = { size: ts, entry: te, funding: tpos.funding };
      t.priv.collateral = t.priv.collateral + tpnl - tfee;
      if (X.abs(t.priv.collateral) >= X.MAX_COLLATERAL) throw new Error('collateral out of range');
      this.feesPending += tfee;
      notional += q * o.price;
      remaining -= q;
    }
    if (this.markets[m].oiLong !== this.markets[m].oiShort) throw new Error('open interest out of balance');
    return { fills, remaining, notional };
  }

  private async execCancel(a: SignedAction, act: M.Activity) {
    const [mk, side, price, seq] = a.p;
    const m = Number(mk);
    if (mk < 0n || m >= M.MARKETS) throw new Error('market');
    const index = X.orderIndex(side, price, seq);
    const o = this.orders[m].get(index);
    if (!o || o.account !== a.account) throw new Error('no such order');
    const acctPath = this.accounts.path(a.account).map(hex);
    const restPath = siblingsToNoir(this.books[m].path(index));
    await this.books[m].set(index, 0n, 0n, 0n);
    this.orders[m].delete(index);
    this.markets[m].bookRoot = this.books[m].root;
    const nact: M.Activity = { ...M.copyActivity(act), openOrders: act.openOrders - 1n };
    if (side === M.SIDE.BID) nact.openBid[m] -= o.lots;
    else nact.openAsk[m] -= o.lots;
    const actvPath = this.activity.path(a.account).map(hex);
    this.actv.set(a.account, nact);
    await this.activity.set(a.account, await M.activityHash(this.h, nact));
    return { taker_acct_path: acctPath, taker_actv_path: actvPath, rest_path: restPath, cancel_lots: o.lots.toString(), cancel_expiry: o.expiry.toString() };
  }

  private async execWithdraw(a: SignedAction, rec: AccountRecord, act: M.Activity, daNonce: bigint) {
    const [amount, recipient] = a.p;
    if (amount <= 0n || amount >= X.MAX_COLLATERAL) throw new Error('withdrawal amount out of range');
    const old = M.copyPriv(rec.priv);
    if (old.collateral < amount) throw new Error('collateral below the amount');
    if (!X.exposureFresh(old, act, this.markets, this.params.maxAge, this.running.time)) throw new Error('index too old for a withdrawal');
    if (!X.covers(X.equity(old, this.markets) - amount, X.initialMargin(old, act, this.markets, this.params))) throw new Error('insufficient margin');
    const acctPath = this.accounts.path(a.account).map(hex);
    const leaf = await this.writeAccount(rec, { ...old, collateral: old.collateral - amount }, daNonce);
    await this.emitChange(rec, leaf, daNonce);
    const salt = await this.h([M.DS.WDSALT, rec.kEnc, this.running.batch, BigInt(this.running.withdrawalsCount)]);
    await this.appendWithdrawal(recipient, amount, salt);
    const nact: M.Activity = M.copyActivity(act);
    const actvPath = this.activity.path(a.account).map(hex);
    this.actv.set(a.account, nact);
    await this.activity.set(a.account, await M.activityHash(this.h, nact));
    return { taker_acct_path: acctPath, taker_actv_path: actvPath };
  }

  // ---- Liquidation (seg_liquidate, SPEC.md §8.5) ----

  /** An account's equity and margin requirements at current marks. */
  health(index: bigint) {
    const rec = this.accts.get(index)!;
    const eq = X.equity(rec.priv, this.markets);
    const mm = X.maintenanceMargin(rec.priv, this.markets, this.params);
    const cm = X.closeoutMargin(rec.priv, this.markets, this.params);
    return { equity: eq, mm, cm, liquidatable: X.below(eq, mm), closeout: X.below(eq, cm) };
  }

  /**
   * Lots a close in market m could fill within `limit` in one step budget, capped at `max`. An
   * expired order uses a step without filling anything, as matching removes it.
   */
  private fillable(m: number, side: bigint, limit: bigint, max: bigint) {
    const opposite = [...this.orders[m].entries()]
      .filter(([, o]) => o.side !== side && this.crosses(side, limit, o))
      .sort(([a], [b]) => (side === M.SIDE.BID ? (a < b ? -1 : 1) : a > b ? -1 : 1))
      .slice(0, FILLS);
    const total = opposite.reduce((t, [, o]) => t + (X.expired(o, this.running.time) ? 0n : o.lots), 0n);
    return total < max ? total : max;
  }

  private emptyStep() {
    const emptyAcct = { pub: M.pubToNoir(M.zeroPub()), priv: M.privToNoir(M.emptyPriv()), path: zeros(M.ACCOUNTS_HEIGHT) };
    return {
      kind: hex(0n),
      account_index: '0',
      market: '0',
      acct_pub: emptyAcct.pub,
      acct_priv: emptyAcct.priv,
      acct_k_enc: hex(0n),
      acct_path: emptyAcct.path,
      actv: M.activityToNoir(M.newActivity()),
      actv_path: zeros(M.ACCOUNTS_HEIGHT),
      side: hex(0n),
      price: '0',
      seq: '0',
      cancel_lots: '0',
      cancel_expiry: '0',
      lots: '0',
      n_fills: 0,
      fills: Array.from({ length: FILLS }, () => this.emptyFill()),
      book_path: emptyBookPath(),
      other_index: '0',
      other_pub: emptyAcct.pub,
      other_priv: emptyAcct.priv,
      other_k_enc: hex(0n),
      other_path: emptyAcct.path,
      ins_actv: M.activityToNoir(M.newActivity()),
      ins_actv_path: zeros(M.ACCOUNTS_HEIGHT),
      ins_pub: emptyAcct.pub,
      ins_priv: emptyAcct.priv,
      ins_path: emptyAcct.path,
    };
  }

  /** The action-log message of a planned step (seg_liquidate `step_message`). */
  private liqMessage(p: LiqPlan) {
    return this.h([M.DS.LIQ, p.kind, p.account, BigInt(p.market), p.other, p.lots, p.side, p.price, p.seq]);
  }

  /**
   * Executes liquidation steps, LIQ_PER_SEGMENT per segment. A step whose precondition does not hold
   * throws: liquidations are the operator's own actions.
   */
  async liquidate(steps: LiqStep[]) {
    for (let i = 0; i < steps.length; i += LIQ_PER_SEGMENT) await this.liquidationSegment(steps.slice(i, i + LIQ_PER_SEGMENT));
  }

  private async liquidationSegment(steps: LiqStep[]) {
    // The circuit logs every step before executing any, but a step's parameters (a close's size)
    // depend on the steps before it: plan in a dry run, roll back, then execute the plans.
    const snap = this.snapshot();
    const plans: LiqPlan[] = [];
    try {
      for (const st of steps) plans.push((await this.execLiq(st, 0n)).plan);
    } finally {
      this.restore(snap);
    }
    const start = copyRunning(this.running);
    const before = this.state();
    for (const p of plans) this.running.actionLog = await M.logAppend(this.h, this.running.actionLog, await this.liqMessage(p), M.LOG.LIQUIDATE);
    const daNonce = await M.segmentNonce(this.h, start.batch, this.running.actionLog, start.daLen);
    await this.absorb(M.TAG.SEG);
    await this.absorb(daNonce);
    const items: unknown[] = [];
    for (const [i, st] of steps.entries()) {
      const { witness, plan } = await this.execLiq(st, daNonce);
      assert(plan.lots === plans[i].lots, 'liquidation plan changed between runs');
      items.push(witness);
    }
    await this.finishSegment('seg_liquidate', `liquidate [${steps.map((x) => `${x.kind} ${x.account}`).join(', ')}]`, {
      ...this.base(start, before),
      n: steps.length,
      steps: pad(items, LIQ_PER_SEGMENT, () => this.emptyStep()),
    });
  }

  private async execLiq(step: LiqStep, daNonce: bigint): Promise<{ witness: any; plan: LiqPlan }> {
    const idx = step.account;
    const m = 'market' in step ? step.market : 0;
    const rec = this.accts.get(idx);
    const act0 = this.actv.get(idx);
    if (!rec || !act0) throw new Error('no such account');
    // A precondition the circuit enforces; a relaxed engine skips it to build adversarial witnesses.
    const need = (ok: boolean, msg: string) => {
      if (!ok && !this.relax.has('liq')) throw new Error(msg);
    };
    need(rec.pub.class === M.CLASS.USER, 'only user accounts are liquidated');
    const a0 = M.copyPriv(rec.priv);
    need(X.exposureFresh(a0, act0, this.markets, this.params.maxAge, this.running.time), 'index too old for a liquidation');
    const eq = X.equity(a0, this.markets);
    const mm = X.maintenanceMargin(a0, this.markets, this.params);
    const cm = X.closeoutMargin(a0, this.markets, this.params);
    const kind = X.LIQ[step.kind.toUpperCase() as keyof typeof X.LIQ];
    const plan: LiqPlan = { kind, account: idx, market: m, other: 0n, lots: 0n, side: 0n, price: 0n, seq: 0n };
    const w: any = {
      ...this.emptyStep(),
      kind: hex(kind),
      account_index: idx.toString(),
      market: m.toString(),
      acct_pub: M.pubToNoir(rec.pub),
      acct_priv: M.privToNoir(a0),
      acct_k_enc: hex(rec.kEnc),
      actv: M.activityToNoir(act0),
    };
    let a = M.copyPriv(a0);
    let act = M.copyActivity(act0);
    let writeA = false;
    let otherRec: AccountRecord | undefined;
    let other: M.AccountPriv | undefined;
    const insRec = this.accts.get(M.INSURANCE_INDEX)!;
    const insAct = this.actv.get(M.INSURANCE_INDEX)!;
    const usesInsurance = step.kind === 'takeover' || step.kind === 'deficit' || step.kind === 'adl';
    const noOrders = () => need(act0.openOrders === 0n, 'orders must be cancelled first');
    const insuranceCovers = (ins: M.AccountPriv) =>
      X.exposureFresh(ins, insAct, this.markets, this.params.maxAge, this.running.time) &&
      X.covers(X.equity(ins, this.markets), X.initialMargin(ins, insAct, this.markets, this.params));

    if (step.kind === 'cancel') {
      need(X.below(eq, mm), 'account is not liquidatable');
      const o = this.orders[m].get(step.index);
      if (!o || o.account !== idx) throw new Error('no such order');
      Object.assign(plan, { side: o.side, price: o.price, seq: o.seq });
      Object.assign(w, { side: hex(o.side), price: o.price.toString(), seq: o.seq.toString(), cancel_lots: o.lots.toString(), cancel_expiry: o.expiry.toString(), book_path: siblingsToNoir(this.books[m].path(step.index)) });
      await this.books[m].set(step.index, 0n, 0n, 0n);
      this.orders[m].delete(step.index);
      this.markets[m].bookRoot = this.books[m].root;
      if (o.side === M.SIDE.BID) act.openBid[m] -= o.lots;
      else act.openAsk[m] -= o.lots;
      act.openOrders -= 1n;
    } else if (step.kind === 'close') {
      need(X.below(eq, mm), 'account is not liquidatable');
      noOrders();
      const pos = a0.positions[m];
      if (pos.size === 0n) throw new Error('no position in the market');
      const mp = this.params.markets[m];
      const side = pos.size > 0n ? M.SIDE.ASK : M.SIDE.BID;
      // A relaxed engine ignores the limit and takes whatever the book offers.
      const limit = this.relax.has('liq') ? (side === M.SIDE.ASK ? 1n : X.MAX_PRICE - 1n) : X.closeLimit(pos.size, this.markets[m].markPrice, mp.mmrPpm, eq, mm);
      const lots = step.lots ?? this.fillable(m, side, limit, X.abs(pos.size));
      if (lots <= 0n || lots > X.abs(pos.size)) throw new Error('close size');
      plan.lots = lots;
      const t = { index: idx, priv: a, act, traded: false };
      const matched = await this.matchOrder(m, side, limit, lots, t, daNonce, mp.makerFeePpm, 0n);
      if (matched.remaining > 0n) {
        if (!this.relax.has('fills') && this.crosses(side, limit, this.best(m, side === M.SIDE.BID ? M.SIDE.ASK : M.SIDE.BID))) {
          throw new Error(`close needs more than ${FILLS} matching steps`);
        }
        w.book_path = siblingsToNoir(this.books[m].path(X.orderIndex(side, limit, this.markets[m].nextSeq)));
      }
      this.markets[m].bookRoot = this.books[m].root;
      a = t.priv;
      act = t.act;
      const left = X.equity(a, this.markets);
      const cap = left > 0n ? left : 0n;
      const f = X.liqFee(matched.notional, mp.liqFeePpm);
      const charged = f < cap ? f : cap;
      a.collateral -= charged;
      this.insurancePending += charged;
      writeA = t.traded;
      Object.assign(w, { lots: lots.toString(), n_fills: matched.fills.length, fills: pad(matched.fills, FILLS, () => this.emptyFill()) });
    } else if (step.kind === 'takeover') {
      need(X.below(eq, cm), 'account is above close-out margin');
      noOrders();
      const pos = a0.positions[m];
      if (pos.size === 0n) throw new Error('no position in the market');
      const u = X.upnl(pos, this.markets[m]);
      a0.positions.forEach((p, k) => need(p.size === 0n || u <= X.upnl(p, this.markets[k]), 'not the lowest unrealized PnL'));
      const t = X.takeover(a0, insRec.priv, this.markets[m], m);
      this.shiftOi(m, ...t.sizes.a);
      this.shiftOi(m, ...t.sizes.ins);
      this.insuranceMicro += t.dust;
      a = t.a;
      other = t.ins;
      otherRec = insRec;
      need(insuranceCovers(other), 'insurance below initial margin');
      writeA = true;
    } else if (step.kind === 'deficit') {
      noOrders();
      need(a0.positions.every((p) => p.size === 0n), 'positions remain');
      need(a0.collateral < 0n, 'no deficit');
      other = M.copyPriv(insRec.priv);
      other.collateral += a0.collateral;
      otherRec = insRec;
      a.collateral = 0n;
      need(insuranceCovers(other), 'insurance below initial margin');
      writeA = true;
    } else {
      need(X.below(eq, cm), 'account is above close-out margin');
      noOrders();
      const c = this.accts.get(step.counterparty);
      if (!c) throw new Error('no such counterparty');
      need(c.pub.class === M.CLASS.USER && c.index !== idx, 'counterparty must be another user account');
      const pos = a0.positions[m];
      const cpos = c.priv.positions[m];
      if (pos.size === 0n) throw new Error('no position in the market');
      need(cpos.size !== 0n && cpos.size > 0n !== pos.size > 0n, 'counterparty not opposite');
      need(X.exposureFresh(insRec.priv, insAct, this.markets, this.params.maxAge, this.running.time), 'index too old for the insurance account');
      need(!insuranceCovers(X.takeover(a0, insRec.priv, this.markets[m], m).ins), 'insurance can absorb');
      Object.assign(w, { ins_pub: M.pubToNoir(insRec.pub), ins_priv: M.privToNoir(insRec.priv), ins_path: this.accounts.path(M.INSURANCE_INDEX).map(hex) });
      const market = this.markets[m];
      const q = X.abs(pos.size) < X.abs(cpos.size) ? X.abs(pos.size) : X.abs(cpos.size);
      const price = X.bankruptcyPrice(pos.size, market.markPrice, eq);
      const [ac, apos, d1] = X.settleFunding(a0.collateral, pos, market.cumFunding);
      const [cc, cpos2, d2] = X.settleFunding(c.priv.collateral, cpos, market.cumFunding);
      const da = pos.size > 0n ? -q : q;
      const [as, ae, apnl] = X.fill(apos.size, apos.entry, da, price);
      const [cs, ce, cpnl] = X.fill(cpos2.size, cpos2.entry, -da, price);
      this.shiftOi(m, apos.size, as);
      this.shiftOi(m, cpos2.size, cs);
      this.insuranceMicro += d1 + d2;
      a.positions[m] = { size: as, entry: ae, funding: apos.funding };
      a.collateral = ac + apnl;
      other = M.copyPriv(c.priv);
      other.positions[m] = { size: cs, entry: ce, funding: cpos2.funding };
      other.collateral = cc + cpnl;
      if (X.abs(a.collateral) >= X.MAX_COLLATERAL || X.abs(other.collateral) >= X.MAX_COLLATERAL) throw new Error('collateral out of range');
      otherRec = c;
      writeA = true;
    }
    if (this.markets[m].oiLong !== this.markets[m].oiShort) throw new Error('open interest out of balance');

    // The liquidated account's activity, then the insurance account's (read only).
    w.actv_path = this.activity.path(idx).map(hex);
    this.actv.set(idx, act);
    await this.activity.set(idx, await M.activityHash(this.h, act));
    if (usesInsurance) Object.assign(w, { ins_actv: M.activityToNoir(insAct), ins_actv_path: this.activity.path(M.INSURANCE_INDEX).map(hex) });
    // The liquidated account's leaf, then the other account's.
    w.acct_path = this.accounts.path(idx).map(hex);
    if (writeA) {
      const leaf = await this.writeAccount(rec, a, daNonce);
      await this.emitChange(rec, leaf, daNonce);
    }
    if (otherRec && other) {
      plan.other = otherRec.index;
      Object.assign(w, { other_index: otherRec.index.toString(), other_pub: M.pubToNoir(otherRec.pub), other_priv: M.privToNoir(otherRec.priv), other_k_enc: hex(otherRec.kEnc), other_path: this.accounts.path(otherRec.index).map(hex) });
      const leaf = await this.writeAccount(otherRec, other, daNonce);
      await this.emitChange(otherRec, leaf, daNonce);
    }
    return { witness: w, plan };
  }

  /**
   * Plans and executes the whole waterfall for one account (SPEC.md §8.5): cancel its orders, close
   * positions against the book while liquidity lies within the limit, then hand positions to the
   * insurance account (lowest unrealized PnL first) or, when the insurance account cannot absorb
   * them, auto-deleverage against `counterparty(market)`, and finally let the insurance account
   * absorb any deficit. Returns the steps taken.
   */
  async liquidateAccount(index: bigint, counterparty?: (market: number) => bigint | undefined): Promise<LiqStep[]> {
    const snap = this.snapshot();
    const steps: LiqStep[] = [];
    const run = async (s: LiqStep) => {
      await this.execLiq(s, 0n);
      steps.push(s);
    };
    try {
      for (let guard = 0; guard < 64; guard++) {
        const h = this.health(index);
        const rec = this.accts.get(index)!;
        const act = this.actv.get(index)!;
        if (!h.liquidatable) break;
        if (act.openOrders > 0n) {
          const m = this.orders.findIndex((o) => [...o.values()].some((x) => x.account === index));
          const [oi] = [...this.orders[m].entries()].find(([, x]) => x.account === index)!;
          await run({ kind: 'cancel', account: index, market: m, index: oi });
          continue;
        }
        const open = rec.priv.positions.map((p, m) => ({ p, m })).filter(({ p }) => p.size !== 0n);
        const closable = open.find(({ p, m }) => {
          const side = p.size > 0n ? M.SIDE.ASK : M.SIDE.BID;
          const limit = X.closeLimit(p.size, this.markets[m].markPrice, this.params.markets[m].mmrPpm, h.equity, h.mm);
          return this.fillable(m, side, limit, X.abs(p.size)) > 0n;
        });
        if (closable) {
          await run({ kind: 'close', account: index, market: closable.m });
          continue;
        }
        if (open.length && h.closeout) {
          const lowest = open.reduce((x, y) => (X.upnl(y.p, this.markets[y.m]) < X.upnl(x.p, this.markets[x.m]) ? y : x));
          const ins = this.accts.get(M.INSURANCE_INDEX)!;
          const insAct = this.actv.get(M.INSURANCE_INDEX)!;
          const fresh = (p: M.AccountPriv) => X.exposureFresh(p, insAct, this.markets, this.params.maxAge, this.running.time);
          const t = X.takeover(rec.priv, ins.priv, this.markets[lowest.m], lowest.m);
          const absorbs = fresh(t.ins) && X.covers(X.equity(t.ins, this.markets), X.initialMargin(t.ins, insAct, this.markets, this.params));
          if (absorbs) await run({ kind: 'takeover', account: index, market: lowest.m });
          else if (!fresh(ins.priv)) break;
          else {
            const c = counterparty?.(lowest.m);
            if (c === undefined) break;
            await run({ kind: 'adl', account: index, market: lowest.m, counterparty: c });
          }
          continue;
        }
        if (!open.length && rec.priv.collateral < 0n) {
          await run({ kind: 'deficit', account: index });
          continue;
        }
        break;
      }
    } finally {
      this.restore(snap);
    }
    await this.liquidate(steps);
    return steps;
  }

  /** Equity of an account at current marks (for tests and reports). */
  equityOf(index: bigint) {
    return X.equity(this.accts.get(index)!.priv, this.markets);
  }
}

/** Client side: an account signs an action with its master key (SPEC.md §7.1). */
export async function signAction(h: M.H, domain: bigint, keys: { sk: bigint; pk: Point }, kind: bigint, account: bigint, nonce: bigint, p: bigint[], keyId = M.MASTER_KEY): Promise<SignedAction> {
  const { sign } = await import('./grumpkin.ts');
  const payload = [...p, ...Array(X.ACTION_PAYLOAD - p.length).fill(0n)];
  const msg = await X.actionMsg(h, domain, kind, account, keyId, nonce, payload);
  return { kind, account, keyId, nonce, p: payload, sig: await sign(h, keys.sk, msg), pk: { x: keys.pk!.x, y: keys.pk!.y } };
}

/** Oracle side: the publishers with the given indices sign an index update (SPEC.md §8.4). */
export async function signUpdate(h: M.H, domain: bigint, sks: bigint[], signers: number[], market: bigint, price: bigint, external: bigint, time: bigint): Promise<OracleUpdate> {
  const { sign } = await import('./grumpkin.ts');
  const msg = await M.oracleMessage(h, domain, market, price, external, time);
  const sigs: (Sig | undefined)[] = Array(M.N_ORACLES).fill(undefined);
  for (const j of signers) sigs[j] = await sign(h, sks[j], msg);
  return { market, price, external, time, sigs };
}
