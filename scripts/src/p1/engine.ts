// The P1 engine (SPEC.md §5): a deterministic state machine with the circuits' semantics. It
// executes actions against its copy of the exchange state and, for every segment, records the
// circuit inputs (witness) and the transition the circuit must prove. Divergence between engine
// and circuit makes a batch unprovable, so proveBatch compares them segment by segment.
import type { Barretenberg } from '@aztec-foundation/bb.js';
import { R, daAbsorb, hex } from '../lib.ts';
import { type BatchWitness, type Running, type SegmentWitness, assert, batchStart, copyRunning, runningToNoir } from '../pipeline.ts';
import { type Point, type Sig, sigToNoir, zeroSig } from './grumpkin.ts';
import * as M from './model.ts';
import * as X from './rules.ts';
import { type BookSibling, BookTree, MerkleTree } from './tree.ts';

export type AccountRecord = { index: bigint; pub: M.AccountPub; priv: M.AccountPriv; kEnc: bigint };
export type OracleUpdate = { price: bigint; time: bigint; sig: Sig };
/** An action as its account signed it (SPEC.md §7.1). */
export type SignedAction = { kind: bigint; account: bigint; nonce: bigint; p: bigint[]; sig: Sig; pk: { x: bigint; y: bigint } };
export type Rejection = { action: SignedAction; reason: string };

const PRIORITY_PER_SEGMENT = 4;
const TRADE_PER_SEGMENT = 2;
const FILLS = 2;
const zeros = (n: number) => Array<string>(n).fill(hex(0n));
const siblingsToNoir = (path: BookSibling[]) => path.map((s) => ({ hash: hex(s.hash), ask: s.ask.toString(), bid: s.bid.toString() }));
const emptyBookPath = () => siblingsToNoir(Array.from({ length: M.BOOK_HEIGHT }, () => ({ hash: 0n, ask: 0n, bid: 0n })));

export class Engine {
  readonly api: Barretenberg;
  readonly h: M.H;
  readonly params: M.Params;
  readonly vkTreeRoot: bigint;
  domain = 0n;
  accounts!: MerkleTree;
  activity!: MerkleTree;
  book!: BookTree;
  accts = new Map<bigint, AccountRecord>();
  actv = new Map<bigint, M.Activity>();
  market!: M.Market;
  refreshCursor = 0n;
  numAccounts = 0n;
  /** Resting orders by book index. */
  orders = new Map<bigint, X.Order>();
  /** Encryption keys the operator received at registration, by commitment (SPEC.md §10.1). */
  keyring = new Map<bigint, bigint>();
  /** Actions the engine refused, with the reason (they were never sequenced). */
  rejected: Rejection[] = [];

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

  static async create(api: Barretenberg, params: M.Params, vkTreeRoot: bigint): Promise<Engine> {
    const e = new Engine(api, params, vkTreeRoot);
    e.accounts = await new MerkleTree(e.h, M.ACCOUNTS_HEIGHT, M.DS.ACCT_NODE).init();
    e.activity = await new MerkleTree(e.h, M.ACCOUNTS_HEIGHT, M.DS.ACTV_NODE).init();
    e.book = await new BookTree(api, M.BOOK_HEIGHT).init();
    e.market = { bookRoot: e.book.root, indexPrice: 0n, indexTime: 0n, nextSeq: 0n, oiLong: 0n, oiShort: 0n };
    e.domain = await M.domainOf(e.h, params);
    return e;
  }

  state(): M.State {
    return {
      accountsRoot: this.accounts.root,
      activityRoot: this.activity.root,
      market: { ...this.market, bookRoot: this.book.root },
      refreshCursor: this.refreshCursor,
      numAccounts: this.numAccounts,
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
    return {
      batchNumber: this.running.batch,
      start: this.batchStartRunning,
      segments: this.segments,
      endState: M.stateToNoir(st),
      endAccountsRoot: st.accountsRoot,
      marketDataHash: await M.marketDataHash(this.h, st.market.indexPrice, st.market.indexTime),
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

  private async emitAccount(tag: bigint, rec: AccountRecord, leaf: bigint, daNonce: bigint) {
    const pos = this.running.daLen;
    const pt = M.plaintext(rec.priv);
    for (const x of [tag, rec.index, leaf, rec.pub.owner, rec.pub.masterAuth, rec.pub.encCommitment, rec.pub.class]) {
      await this.absorb(x);
    }
    for (let i = 0; i < pt.length; i++) {
      await this.absorb((pt[i] + (await M.keystream(this.h, rec.kEnc, rec.index, daNonce, pos, i))) % R);
    }
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

  /** Block segment: opens an L3 block at `time`, optionally with a signed index update. */
  async block(time: bigint, update?: OracleUpdate) {
    const start = copyRunning(this.running);
    const before = this.state();
    const r = this.running;
    assert(time >= r.time, 'block time regressed');
    r.time = time;
    r.actionLog = await M.logAppend(this.h, r.actionLog, await M.blockHash(this.h, time), M.LOG.BLOCK);
    if (update) {
      const msg = await M.oracleMessage(this.h, this.domain, update.price, update.time);
      assert(update.time > this.market.indexTime && update.time <= time, 'oracle update time');
      this.market.indexPrice = update.price;
      this.market.indexTime = update.time;
      r.actionLog = await M.logAppend(this.h, r.actionLog, msg, M.LOG.ORACLE);
    }
    await this.finishSegment('seg_block', `block t=${time}${update ? ` index=${update.price}` : ''}`, {
      ...this.base(start, before),
      block_time: time.toString(),
      has_update: !!update,
      update: update
        ? { price: update.price.toString(), time: update.time.toString(), sig: sigToNoir(update.sig) }
        : { price: '0', time: '0', sig: zeroSig() },
    });
  }

  /** Executes queued priority requests in order, PRIORITY_PER_SEGMENT per segment. */
  async priority(reqs: M.Request[]) {
    for (let i = 0; i < reqs.length; i += PRIORITY_PER_SEGMENT) await this.prioritySegment(reqs.slice(i, i + PRIORITY_PER_SEGMENT));
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
    while (items.length < PRIORITY_PER_SEGMENT) items.push(this.emptyItem());
    const kinds = reqs.map((q) => (q.kind === M.KIND.REGISTER ? 'register' : 'deposit')).join(', ');
    await this.finishSegment('seg_priority', `priority [${kinds}]`, { ...this.base(start, before), n: reqs.length, items });
  }

  private emptyItem() {
    return {
      req: M.requestToNoir({ kind: 0n, a: 0n, b: 0n, sender: 0n, time: 0n }),
      account_index: '0',
      acct_pub: M.pubToNoir(M.zeroPub()),
      acct_priv: M.privToNoir(M.zeroPriv()),
      acct_path: zeros(M.ACCOUNTS_HEIGHT),
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
      const pub: M.AccountPub = { owner: q.sender, masterAuth: q.a, encCommitment: q.b, class: M.CLASS_USER };
      const priv: M.AccountPriv = { collateral: 0n, size: 0n, entry: 0n, blind: await M.blindOf(this.h, kEnc, idx, daNonce, this.running.daLen) };
      const leaf = await M.accountLeaf(this.h, pub, priv);
      Object.assign(item, {
        account_index: idx.toString(),
        acct_path: this.accounts.path(idx).map(hex),
        actv_path: this.activity.path(idx).map(hex),
        k_enc: hex(kEnc),
      });
      await this.accounts.set(idx, leaf);
      const act = M.newActivity();
      await this.activity.set(idx, await M.activityHash(this.h, act));
      const rec = { index: idx, pub, priv, kEnc };
      this.accts.set(idx, rec);
      this.actv.set(idx, act);
      this.numAccounts += 1n;
      await this.emitAccount(M.TAG.CHANGE, rec, leaf, daNonce);
      return item;
    }
    assert(q.kind === M.KIND.DEPOSIT, 'unknown request kind');
    const amount = q.b;
    const exists = q.a < this.numAccounts;
    if (!exists) {
      await this.appendWithdrawal(q.sender, amount, await M.requestEntry(this.h, q));
      return item;
    }
    const rec = this.accts.get(q.a)!;
    Object.assign(item, {
      account_index: q.a.toString(),
      acct_pub: M.pubToNoir(rec.pub),
      acct_priv: M.privToNoir(rec.priv),
      acct_path: this.accounts.path(q.a).map(hex),
      k_enc: hex(rec.kEnc),
    });
    rec.priv = {
      ...rec.priv,
      collateral: rec.priv.collateral + amount,
      blind: await M.blindOf(this.h, rec.kEnc, rec.index, daNonce, this.running.daLen),
    };
    const leaf = await M.accountLeaf(this.h, rec.pub, rec.priv);
    await this.accounts.set(rec.index, leaf);
    await this.emitAccount(M.TAG.CHANGE, rec, leaf, daNonce);
    return item;
  }

  /**
   * Refresh segment (SPEC.md §9.5): republishes the next `n` accounts after the refresh cursor,
   * wrapping around, each as its unchanged leaf with the opening encrypted under a fresh keystream.
   */
  async refresh(n: number) {
    assert(n <= 4 && BigInt(n) <= this.numAccounts, 'refresh count');
    const start = copyRunning(this.running);
    const before = this.state();
    const daNonce = await M.segmentNonce(this.h, start.batch, start.actionLog, start.daLen);
    await this.absorb(M.TAG.SEG);
    await this.absorb(daNonce);
    const items: unknown[] = [];
    const indices: bigint[] = [];
    for (let i = 0; i < n; i++) {
      const idx = this.refreshCursor;
      const rec = this.accts.get(idx)!;
      const leaf = await M.accountLeaf(this.h, rec.pub, rec.priv);
      items.push({ pub_part: M.pubToNoir(rec.pub), priv_part: M.privToNoir(rec.priv), path: this.accounts.path(idx).map(hex), k_enc: hex(rec.kEnc) });
      await this.emitAccount(M.TAG.REFRESH, rec, leaf, daNonce);
      indices.push(idx);
      this.refreshCursor = idx + 1n === this.numAccounts ? 0n : idx + 1n;
    }
    while (items.length < 4) {
      items.push({ pub_part: M.pubToNoir(M.zeroPub()), priv_part: M.privToNoir(M.zeroPriv()), path: zeros(M.ACCOUNTS_HEIGHT), k_enc: hex(0n) });
    }
    await this.finishSegment('seg_refresh', `refresh [${indices.join(', ')}]`, { ...this.base(start, before), n, items });
  }

  // ---- Trading (SPEC.md §8) ----

  private snapshot() {
    return {
      accounts: this.accounts.snapshot(),
      activity: this.activity.snapshot(),
      book: this.book.snapshot(),
      accts: new Map([...this.accts].map(([k, v]) => [k, { ...v, pub: { ...v.pub }, priv: { ...v.priv } }])),
      actv: new Map([...this.actv].map(([k, v]) => [k, { ...v }])),
      orders: new Map([...this.orders].map(([k, v]) => [k, { ...v }])),
      market: { ...this.market },
      running: copyRunning(this.running),
      daPayload: [...this.daPayload],
      wdRecords: [...this.wdRecords],
    };
  }

  private restore(s: ReturnType<Engine['snapshot']>) {
    this.accounts.restore(s.accounts);
    this.activity.restore(s.activity);
    this.book.restore(s.book);
    this.accts = s.accts;
    this.actv = s.actv;
    this.orders = s.orders;
    this.market = s.market;
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
    let queue = [...actions];
    while (queue.length) {
      let batch = queue.slice(0, TRADE_PER_SEGMENT);
      queue = queue.slice(TRADE_PER_SEGMENT);
      for (;;) {
        const snap = this.snapshot();
        try {
          if (batch.length) await this.tradeSegment(batch);
          break;
        } catch (e: any) {
          this.restore(snap);
          const k = e.actionIndex ?? 0;
          this.rejected.push({ action: batch[k], reason: String(e.message ?? e) });
          batch = batch.filter((_, i) => i !== k);
          if (!batch.length) break;
        }
      }
    }
  }

  private async tradeSegment(actions: SignedAction[]) {
    const start = copyRunning(this.running);
    const before = this.state();
    const r = this.running;
    for (const a of actions) {
      r.actionLog = await M.logAppend(this.h, r.actionLog, await X.actionMsg(this.h, this.domain, a.kind, a.account, a.nonce, a.p), M.LOG.SIGNED);
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
    const labels = actions.map((a) => (a.kind === X.KIND_ACT.PLACE ? 'place' : a.kind === X.KIND_ACT.CANCEL ? 'cancel' : 'withdraw'));
    while (items.length < TRADE_PER_SEGMENT) items.push(this.emptyAction());
    await this.finishSegment('seg_trade', `trade [${labels.join(', ')}]`, { ...this.base(start, before), n: actions.length, actions: items });
  }

  private emptyFill() {
    return {
      index: hex(0n),
      price: '0',
      seq: '0',
      order: { side: hex(0n), account_index: '0', lots: '0' },
      book_path: emptyBookPath(),
      maker_pub: M.pubToNoir(M.zeroPub()),
      maker_priv: M.privToNoir(M.zeroPriv()),
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
      nonce: '0',
      p: zeros(4),
      pk_x: hex(0n),
      pk_y: hex(0n),
      sig: zeroSig(),
      taker_pub: M.pubToNoir(M.zeroPub()),
      taker_priv: M.privToNoir(M.zeroPriv()),
      taker_k_enc: hex(0n),
      taker_acct_path: zeros(M.ACCOUNTS_HEIGHT),
      taker_actv: M.activityToNoir(M.newActivity()),
      taker_actv_path: zeros(M.ACCOUNTS_HEIGHT),
      n_fills: 0,
      fills: Array.from({ length: FILLS }, () => this.emptyFill()),
      rest_path: emptyBookPath(),
      cancel_lots: '0',
    };
  }

  /** The best resting order on the other side of `side`, if any (SPEC.md §6.5). */
  private bestOpposite(side: bigint): X.Order | undefined {
    let best: [bigint, X.Order] | undefined;
    for (const [idx, o] of this.orders) {
      if (o.side === side) continue;
      if (!best || (side === M.SIDE.BID ? idx < best[0] : idx > best[0])) best = [idx, o];
    }
    return best?.[1];
  }

  private shiftOi(before: bigint, after: bigint) {
    const long = (x: bigint) => (x > 0n ? x : 0n);
    const short = (x: bigint) => (x < 0n ? -x : 0n);
    this.market.oiLong += long(after) - long(before);
    this.market.oiShort += short(after) - short(before);
  }

  private async execAction(a: SignedAction, daNonce: bigint) {
    const rec = this.accts.get(a.account);
    const act = this.actv.get(a.account);
    if (!rec || !act) throw new Error('no such account');
    if ((await M.masterAuthOf(this.h, a.pk.x, a.pk.y)) !== rec.pub.masterAuth) throw new Error("signing key is not the account's");
    const { verify } = await import('./grumpkin.ts');
    const msg = await X.actionMsg(this.h, this.domain, a.kind, a.account, a.nonce, a.p);
    if (!(await verify(this.h, a.pk, a.sig, msg))) throw new Error('bad signature');
    if (act.nonce + 1n !== a.nonce) throw new Error('nonce');
    const common = {
      kind: hex(a.kind),
      account_index: a.account.toString(),
      nonce: a.nonce.toString(),
      p: a.p.map(hex),
      pk_x: hex(a.pk.x),
      pk_y: hex(a.pk.y),
      sig: sigToNoir(a.sig),
      taker_pub: M.pubToNoir(rec.pub),
      taker_priv: M.privToNoir(rec.priv),
      taker_k_enc: hex(rec.kEnc),
      taker_actv: M.activityToNoir(act),
    };
    if (a.kind === X.KIND_ACT.PLACE) return { ...this.emptyAction(), ...common, ...(await this.execPlace(a, rec, act, daNonce)) };
    if (a.kind === X.KIND_ACT.CANCEL) return { ...this.emptyAction(), ...common, ...(await this.execCancel(a, rec, act)) };
    if (a.kind === X.KIND_ACT.WITHDRAW) return { ...this.emptyAction(), ...common, ...(await this.execWithdraw(a, rec, act, daNonce)) };
    throw new Error('unknown action kind');
  }

  private async execPlace(a: SignedAction, rec: AccountRecord, act: M.Activity, daNonce: bigint) {
    const [side, price, lots, tif] = a.p;
    if (side !== M.SIDE.BID && side !== M.SIDE.ASK) throw new Error('side');
    if (price <= 0n || price >= X.MAX_PRICE || lots <= 0n || lots >= X.MAX_LOTS) throw new Error('price or lots out of range');
    if (tif !== X.TIF.GTC && tif !== X.TIF.IOC) throw new Error('time in force');
    const mark = this.market.indexPrice;
    if (mark === 0n) throw new Error('no index price');
    if (X.abs(price - mark) * X.PPM > mark * this.params.priceBandPpm) throw new Error('limit price outside the band');
    const oldPriv = { ...rec.priv };
    const oldAct = { ...act };
    let { size, entry, collateral } = rec.priv;
    let remaining = lots;
    const fills: unknown[] = [];
    while (remaining > 0n && fills.length < FILLS) {
      const best = this.bestOpposite(side);
      if (!best || !(side === M.SIDE.BID ? best.price <= price : best.price >= price)) break;
      if (best.account === a.account) throw new Error('self trade');
      const index = X.orderIndex(best.side, best.price, best.seq);
      const maker = this.accts.get(best.account)!;
      const mact = this.actv.get(best.account)!;
      fills.push({
        index: hex(index),
        price: best.price.toString(),
        seq: best.seq.toString(),
        order: { side: hex(best.side), account_index: best.account.toString(), lots: best.lots.toString() },
        book_path: siblingsToNoir(this.book.path(index)),
        maker_pub: M.pubToNoir(maker.pub),
        maker_priv: M.privToNoir(maker.priv),
        maker_acct_path: this.accounts.path(best.account).map(hex),
        maker_k_enc: hex(maker.kEnc),
        maker_actv: M.activityToNoir(mact),
        maker_actv_path: this.activity.path(best.account).map(hex),
      });
      const q = remaining < best.lots ? remaining : best.lots;
      const left = best.lots - q;
      await this.book.set(index, await X.orderLeaf(this.h, best.side, best.account, left), X.askLots({ side: best.side, lots: left }), X.bidLots({ side: best.side, lots: left }));
      if (left === 0n) this.orders.delete(index);
      else this.orders.set(index, { ...best, lots: left });

      const dm = best.side === M.SIDE.BID ? q : -q;
      const [ms, me, mpnl] = X.fill(maker.priv.size, maker.priv.entry, dm, best.price);
      const mcoll = maker.priv.collateral + mpnl;
      if (X.abs(mcoll) >= X.MAX_COLLATERAL) throw new Error('collateral out of range');
      const makerOldSize = maker.priv.size;
      maker.priv = { collateral: mcoll, size: ms, entry: me, blind: await M.blindOf(this.h, maker.kEnc, maker.index, daNonce, this.running.daLen) };
      const mleaf = await M.accountLeaf(this.h, maker.pub, maker.priv);
      await this.accounts.set(maker.index, mleaf);
      await this.emitAccount(M.TAG.CHANGE, maker, mleaf, daNonce);
      const nact = { ...mact };
      if (best.side === M.SIDE.BID) nact.openBid -= q;
      else nact.openAsk -= q;
      if (left === 0n) nact.openOrders -= 1n;
      this.actv.set(maker.index, nact);
      await this.activity.set(maker.index, await M.activityHash(this.h, nact));

      const [ts, te, tpnl] = X.fill(size, entry, -dm, best.price);
      this.shiftOi(makerOldSize, ms);
      this.shiftOi(size, ts);
      size = ts;
      entry = te;
      collateral += tpnl;
      if (X.abs(collateral) >= X.MAX_COLLATERAL) throw new Error('collateral out of range');
      remaining -= q;
    }
    if (this.market.oiLong !== this.market.oiShort) throw new Error('open interest out of balance');

    const nact: M.Activity = { ...act, nonce: a.nonce };
    let restPath = emptyBookPath();
    if (remaining > 0n) {
      const best = this.bestOpposite(side);
      if (best && (side === M.SIDE.BID ? best.price <= price : best.price >= price)) throw new Error(`order needs more than ${FILLS} fills`);
      const seq = this.market.nextSeq;
      const slot = X.orderIndex(side, price, seq);
      restPath = siblingsToNoir(this.book.path(slot));
      if (tif === X.TIF.GTC) {
        await this.book.set(slot, await X.orderLeaf(this.h, side, a.account, remaining), X.askLots({ side, lots: remaining }), X.bidLots({ side, lots: remaining }));
        this.orders.set(slot, { side, account: a.account, lots: remaining, price, seq });
        this.market.nextSeq = seq + 1n;
        if (side === M.SIDE.BID) nact.openBid += remaining;
        else nact.openAsk += remaining;
        nact.openOrders += 1n;
      }
    }

    const acctPath = this.accounts.path(a.account).map(hex);
    if (fills.length > 0) {
      rec.priv = { collateral, size, entry, blind: await M.blindOf(this.h, rec.kEnc, rec.index, daNonce, this.running.daLen) };
      const leaf = await M.accountLeaf(this.h, rec.pub, rec.priv);
      await this.accounts.set(rec.index, leaf);
      await this.emitAccount(M.TAG.CHANGE, rec, leaf, daNonce);
    }
    const actvPath = this.activity.path(a.account).map(hex);
    this.actv.set(a.account, nact);
    await this.activity.set(a.account, await M.activityHash(this.h, nact));

    const wBefore = X.worst(oldPriv.size, oldAct.openBid, oldAct.openAsk);
    const wAfter = X.worst(rec.priv.size, nact.openBid, nact.openAsk);
    if (wAfter > wBefore) {
      if (this.market.indexTime + this.params.maxAge < this.running.time) throw new Error('index too old for a risk-increasing order');
      if (!X.meetsIm(X.equity(rec.priv.collateral, rec.priv.size, rec.priv.entry, mark), wAfter, mark, this.params.imrPpm)) {
        throw new Error('insufficient margin');
      }
    }
    while (fills.length < FILLS) fills.push(this.emptyFill());
    return {
      taker_acct_path: acctPath,
      taker_actv_path: actvPath,
      n_fills: fills.filter((f: any) => f.order.lots !== '0').length,
      fills,
      rest_path: restPath,
    };
  }

  private async execCancel(a: SignedAction, rec: AccountRecord, act: M.Activity) {
    const [side, price, seq] = a.p;
    const index = X.orderIndex(side, price, seq);
    const o = this.orders.get(index);
    if (!o || o.account !== a.account) throw new Error('no such order');
    const acctPath = this.accounts.path(a.account).map(hex);
    const restPath = siblingsToNoir(this.book.path(index));
    await this.book.set(index, 0n, 0n, 0n);
    this.orders.delete(index);
    const nact: M.Activity = { ...act, nonce: a.nonce, openOrders: act.openOrders - 1n };
    if (side === M.SIDE.BID) nact.openBid -= o.lots;
    else nact.openAsk -= o.lots;
    const actvPath = this.activity.path(a.account).map(hex);
    this.actv.set(a.account, nact);
    await this.activity.set(a.account, await M.activityHash(this.h, nact));
    return { taker_acct_path: acctPath, taker_actv_path: actvPath, rest_path: restPath, cancel_lots: o.lots.toString() };
  }

  private async execWithdraw(a: SignedAction, rec: AccountRecord, act: M.Activity, daNonce: bigint) {
    const [amount, recipient] = a.p;
    if (amount <= 0n || amount >= X.MAX_COLLATERAL) throw new Error('withdrawal amount out of range');
    const old = { ...rec.priv };
    if (old.collateral < amount) throw new Error('collateral below the amount');
    const mark = this.market.indexPrice;
    const open = X.worst(old.size, act.openBid, act.openAsk);
    if (open > 0n && this.market.indexTime + this.params.maxAge < this.running.time) throw new Error('index too old for a withdrawal');
    if (!X.meetsIm(X.equity(old.collateral, old.size, old.entry, mark) - amount, open, mark, this.params.imrPpm)) throw new Error('insufficient margin');
    const acctPath = this.accounts.path(a.account).map(hex);
    rec.priv = { ...old, collateral: old.collateral - amount, blind: await M.blindOf(this.h, rec.kEnc, rec.index, daNonce, this.running.daLen) };
    const leaf = await M.accountLeaf(this.h, rec.pub, rec.priv);
    await this.accounts.set(rec.index, leaf);
    await this.emitAccount(M.TAG.CHANGE, rec, leaf, daNonce);
    const salt = await this.h([M.DS.WDSALT, rec.kEnc, this.running.batch, BigInt(this.running.withdrawalsCount)]);
    await this.appendWithdrawal(recipient, amount, salt);
    const nact: M.Activity = { ...act, nonce: a.nonce };
    const actvPath = this.activity.path(a.account).map(hex);
    this.actv.set(a.account, nact);
    await this.activity.set(a.account, await M.activityHash(this.h, nact));
    return { taker_acct_path: acctPath, taker_actv_path: actvPath };
  }
}

/** Client side: an account signs an action with its master key (SPEC.md §7.1). */
export async function signAction(h: M.H, domain: bigint, keys: { sk: bigint; pk: Point }, kind: bigint, account: bigint, nonce: bigint, p: bigint[]): Promise<SignedAction> {
  const { sign } = await import('./grumpkin.ts');
  const msg = await X.actionMsg(h, domain, kind, account, nonce, p);
  return { kind, account, nonce, p, sig: await sign(h, keys.sk, msg), pk: { x: keys.pk!.x, y: keys.pk!.y } };
}
