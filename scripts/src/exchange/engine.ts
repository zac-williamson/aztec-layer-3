// The engine (SPEC.md §5): a deterministic state machine with the circuits' semantics. It executes
// actions against its copy of the exchange state and, for every segment, records the circuit
// inputs (witness) and the transition the circuit must prove. Divergence between engine and
// circuit makes a batch unprovable, so proveBatch compares them segment by segment.
import type { Barretenberg } from '@aztec-foundation/bb.js';
import { DS as DS0, R, SHAPE, daAbsorb, hex } from '../lib.ts';
import { type BatchWitness, type ClientProof, type Prover, type Running, type SegmentWitness, assert, batchStart, copyRunning, runningToNoir } from '../pipeline.ts';
import { type Point, type Sig, sigToNoir, verify, zeroSig } from './grumpkin.ts';
import type { P256Key } from './p256.ts';
import { sha256 } from './webauthn.ts';

/** SHA-256 of a relying party ID, as a passkey's authenticator data carries it. */
const rpIdHash = (rpId: string) => BigInt(`0x${Buffer.from(sha256(new TextEncoder().encode(rpId))).toString('hex')}`);
import * as M from './model.ts';
import type { ProtocolAccount } from './params.ts';
import * as X from './rules.ts';
import { JMap, NullBook, NullTree, Orders, Undo, isNullPath } from './journal.ts';
import { type BookSibling, BookTree, MerkleTree } from './tree.ts';

export type AccountRecord = { index: bigint; pub: M.AccountPub; priv: M.AccountPriv; kEnc: bigint };
/** An index update for one market, with the signatures of the publishers that signed it. */
export type OracleUpdate = { market: bigint; price: bigint; external: bigint; time: bigint; sigs: (Sig | undefined)[] };
/**
 * An action as one of its account's keys signed it (SPEC.md §7.1): the master key (MASTER_KEY) or
 * a session-key slot. `seq` is the sequencer's number for it, assigned when it is sequenced.
 */
export type SignedAction = {
  kind: bigint;
  account: bigint;
  keyId: bigint;
  nonce: bigint;
  p: bigint[];
  sig: Sig;
  pk: { x: bigint; y: bigint };
  seq?: bigint;
  /**
   * The gateway's checks, made before sequencing (P2.24): the action's message, its signer's
   * master authorization and whether the signature verifies. The engine computes what is missing.
   */
  prepared?: { msg: bigint; masterAuth: bigint; ok: boolean };
};
/** One fill, maker by maker, as the sequencer reports it (P2.24). */
export type FillEvent = { market: number; side: bigint; price: bigint; lots: bigint; maker: bigint; taker: bigint; makerLeft: bigint };
/** What a sequenced action did, for its owner's execution report (P2.24). */
export type Execution = { fills: FillEvent[]; rested?: { market: number; side: bigint; price: bigint; seq: bigint; lots: bigint } };
type Scalars = {
  markets: M.Market[];
  feesPending: bigint;
  insurancePending: bigint;
  insuranceMicro: bigint;
  lastSeq: bigint;
  refreshCursor: bigint;
  cycleStart: bigint;
  numAccounts: bigint;
  running: Running;
  lengths: number[];
};
/** A sequencer-mode savepoint, or the witness builder's deep copy. */
export type Snapshot = ({ lite: true; mark: number } & Scalars) | ReturnType<Engine['fullSnapshot']>;
/** A receipt (SPEC.md §11): an action's message and sequence number, where its leaf sits in the batch. */
export type Receipt = { msg: bigint; seq: bigint; segment: number; slot: number };
/**
 * A master action a client proof authorizes (SPEC.md §7.4), as the client hands it to the
 * operator: the action's opening and the proof, whose public inputs are the action's message, the
 * account and the account's auth binding. Lane-P accounts grant and revoke session keys this way.
 */
export type ProvenAction = { kind: bigint; account: bigint; nonce: bigint; p: bigint[]; proof: ClientProof };
export type Rejection = { action: SignedAction | ProvenAction; reason: string };
/** A liquidation step (SPEC.md §8.5), as the operator chooses it. A close's size defaults to what
 * the book can absorb within the limit in one step budget. */
export type LiqStep =
  | { kind: 'cancel'; account: bigint }
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
const CLEANUPS_PER_SEGMENT = 4;
/** Fee-tier changes per maintenance segment (seg_refresh TC). */
const TIERS_PER_SEGMENT = 2;
const LIQ_PER_SEGMENT = 2;
const FILLS = 2;
const CLIENT_PER_SEGMENT = SHAPE.MAX_CLIENT_PROOFS;
const zeros = (n: number) => Array<string>(n).fill(hex(0n));
const noirCache = new WeakMap<object, any>();
/** A null tree's shared path is encoded once (sequencer mode keeps no Merkle state). */
const cached = <T>(path: object, f: () => T): T => {
  if (!isNullPath(path)) return f();
  let c = noirCache.get(path);
  if (!c) noirCache.set(path, (c = f()));
  return c;
};
const siblingsToNoir = (path: BookSibling[]) => cached(path, () => path.map((s) => ({ hash: hex(s.hash), ask: s.ask.toString(), bid: s.bid.toString() })));
const hexPath = (path: bigint[]): string[] => cached(path, () => path.map(hex));
/** Sequencer mode's witness hasher: witnesses are never built there. */
const zeroHash: M.H = async () => 0n;
/** The empty book path's encoding, built once: every empty fill and probe slot shares it. */
const EMPTY_BOOK_PATH = siblingsToNoir(Array.from({ length: M.BOOK_HEIGHT }, () => ({ hash: 0n, ask: 0n, bid: 0n })));
const emptyBookPath = () => EMPTY_BOOK_PATH;
const emptyOrder = () => ({ side: hex(0n), account_index: '0', lots: '0', expiry: '0', epoch: '0', display: false, reduce_only: false });
const orderToNoir = (o: { side: bigint; account: bigint; lots: bigint; expiry: bigint; epoch: bigint; display?: boolean; reduceOnly?: boolean }) => ({
  side: hex(o.side),
  account_index: o.account.toString(),
  lots: o.lots.toString(),
  expiry: o.expiry.toString(),
  epoch: o.epoch.toString(),
  display: !!o.display,
  reduce_only: !!o.reduceOnly,
});
const pad = <T>(xs: T[], n: number, f: () => T) => [...xs, ...Array.from({ length: n - xs.length }, f)];
const emptyTrigger = () => ({ dir: hex(0n), side: hex(0n), account_index: '0', lots: '0', limit: '0', epoch: '0', entry: false });
const triggerToNoir = (t: { dir: bigint; side: bigint; account: bigint; lots: bigint; limit: bigint; epoch: bigint; entry?: boolean }) => ({
  dir: hex(t.dir),
  side: hex(t.side),
  account_index: t.account.toString(),
  lots: t.lots.toString(),
  limit: t.limit.toString(),
  epoch: t.epoch.toString(),
  entry: !!t.entry,
});
const emptyTriggerTop = () => ({ has: false, price: '0', seq: '0', trigger: emptyTrigger(), path: emptyBookPath() });
const emptyOwner = () => ({ owner_actv: M.activityToNoir(M.newActivity()), owner_actv_path: zeros(M.ACCOUNTS_HEIGHT) });
const emptyOwnerActv = () => ({ actv: M.activityToNoir(M.newActivity()), actv_path: zeros(M.ACCOUNTS_HEIGHT) });

export class Engine {
  readonly api: Barretenberg;
  /** The witness hasher: leaves, roots, DA and logs. Sequencer mode makes it return zero. */
  readonly h: M.H;
  /**
   * The hasher for the hashes that decide outcomes: signatures, signers' master authorizations,
   * oracle messages, deposit openings and client proofs.
   */
  readonly hs: M.H;
  /**
   * Sequencer mode (P2.24, SPEC.md §5): the engine decides every action as the witness builder's
   * engine will, but keeps no Merkle trees and builds no DA or witnesses, and applies each action,
   * block or request atomically, undoing a refused one through `undo`.
   */
  readonly lite: boolean;
  readonly undo = new Undo();
  /** Called for every fill, maker by maker, and for an order that rests (the sequencer's execution reports). */
  onFill?: (f: FillEvent) => void;
  onRest?: (r: NonNullable<Execution['rested']>) => void;
  readonly params: M.Params;
  readonly vkTreeRoot: bigint;
  /**
   * The VK hash of every client circuit in the VK tree's client subtree, by package: lane-P master
   * authorizations commit to one of them (SPEC.md §7.1, §7.4).
   */
  readonly clientVks: Map<string, bigint>;
  domain = 0n;
  accounts!: MerkleTree;
  activity!: MerkleTree;
  books: BookTree[] = [];
  accts = new JMap<bigint, AccountRecord>(this.undo);
  actv = new JMap<bigint, M.Activity>(this.undo);
  markets: M.Market[] = [];
  refreshCursor = 0n;
  /** L3 time at which the refresh cursor last wrapped (SPEC.md §9.5). */
  cycleStart = 0n;
  /** The sequencer's number of the last signed action executed (SPEC.md §11). */
  lastSeq = 0n;
  /** Receipts of the batch being built. */
  receipts: Receipt[] = [];
  numAccounts = 0n;
  feesPending = 0n;
  insurancePending = 0n;
  insuranceMicro = 0n;
  /** Resting orders, per market, by book index. */
  orders: Orders<BookOrder>[] = [];
  /** Trigger trees and resting triggers, per market, by tree index (SPEC.md §6.5). */
  triggerTrees: BookTree[] = [];
  triggers: JMap<bigint, X.Trigger>[] = [];
  /** Session keys per account: the slots in use and the account's keys tree (SPEC.md §6.4). */
  keys = new JMap<bigint, JMap<number, M.Key>>(this.undo);
  keyTrees = new JMap<bigint, MerkleTree>(this.undo);
  /** Encryption keys the operator received at registration, by commitment (SPEC.md §10.1). */
  keyring = new JMap<bigint, bigint>(this.undo);
  /** Actions the engine refused, with the reason (they were never sequenced). */
  rejected: Rejection[] = [];
  /**
   * Rules this engine skips, to build consistent but non-compliant witnesses for adversarial tests
   * (a malicious operator's engine). Empty in any real use.
   */
  relax = new Set<'fills' | 'oracle-sigs' | 'liq' | 'client-auth' | 'cleanup' | 'triggers' | 'rekey-owner' | 'revoked-keys' | 'tiers' | 'entry-margin'>();

  // The batch being built.
  running!: Running;
  private batchStartRunning!: Running;
  daPayload: bigint[] = [];
  wdRecords: bigint[] = [];
  segments: SegmentWitness[] = [];

  private constructor(api: Barretenberg, params: M.Params, vkTreeRoot: bigint, clientVks: Record<string, bigint>, lite: boolean) {
    this.api = api;
    this.lite = lite;
    this.hs = M.hasher(api);
    this.h = lite ? zeroHash : this.hs;
    this.params = params;
    this.vkTreeRoot = vkTreeRoot;
    this.clientVks = new Map(Object.entries(clientVks));
  }

  /**
   * An engine at genesis, holding the protocol accounts (insurance at 0, fee at 1). Client-proof
   * actions need the build's client circuits (Prover.clientVks).
   */
  static async create(
    api: Barretenberg,
    params: M.Params,
    vkTreeRoot: bigint,
    protocol: ProtocolAccount[],
    clientVks: Record<string, bigint> = {},
    opts: { lite?: boolean } = {},
  ): Promise<Engine> {
    const e = new Engine(api, params, vkTreeRoot, clientVks, !!opts.lite);
    await M.initModel(e.hs);
    const tree = (height: number, ds: bigint) => (e.lite ? (new NullTree(height) as unknown as MerkleTree) : new MerkleTree(e.h, height, ds));
    const book = () => (e.lite ? (new NullBook(M.BOOK_HEIGHT) as unknown as BookTree) : new BookTree(api, M.BOOK_HEIGHT));
    e.accounts = tree(M.ACCOUNTS_HEIGHT, M.DS.ACCT_NODE);
    e.activity = tree(M.ACCOUNTS_HEIGHT, M.DS.ACTV_NODE);
    for (let m = 0; m < M.MARKETS; m++) {
      e.books.push(book());
      e.orders.push(new Orders(e.undo));
      e.triggerTrees.push(book());
      e.triggers.push(new JMap(e.undo));
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
    e.domain = await M.domainOf(e.hs, params);
    return e;
  }

  state(): M.State {
    return {
      accountsRoot: this.accounts.root,
      activityRoot: this.activity.root,
      markets: this.markets.map((m, i) => ({ ...m, bookRoot: this.books[i].root })),
      refreshCursor: this.refreshCursor,
      cycleStart: this.cycleStart,
      lastSeq: this.lastSeq,
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
    this.receipts = [];
  }

  async endBatch(): Promise<BatchWitness> {
    const st = this.state();
    const marketData = M.marketData(st.markets, this.running.batch);
    return {
      batchNumber: this.running.batch,
      start: this.batchStartRunning,
      segments: this.segments,
      endState: M.stateToNoir(st),
      endAccountsRoot: st.accountsRoot,
      cycleStart: st.cycleStart,
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
    if (this.lite) return;
    const [da, len] = await daAbsorb(this.api, this.running.da, this.running.daLen, x);
    this.running.da = da;
    this.running.daLen = len;
    this.daPayload.push(x);
  }

  private async emitCiphertexts(rec: AccountRecord, daNonce: bigint, pos: number) {
    if (this.lite) return;
    const pt = M.plaintext(rec.priv);
    for (let i = 0; i < pt.length; i++) {
      await this.absorb((pt[i] + (await M.keystream(this.h, rec.kEnc, rec.index, daNonce, pos, i))) % R);
    }
  }

  /** A change entry (public part unchanged). */
  private async emitChange(rec: AccountRecord, leaf: bigint, daNonce: bigint) {
    if (this.lite) return;
    const pos = this.running.daLen;
    for (const x of [M.TAG.CHANGE, rec.index, leaf]) await this.absorb(x);
    await this.emitCiphertexts(rec, daNonce, pos);
  }

  /** A full entry with the public part in clear (registration, refresh). */
  private async emitFull(tag: bigint, rec: AccountRecord, leaf: bigint, daNonce: bigint) {
    if (this.lite) return;
    const pos = this.running.daLen;
    for (const x of [tag, rec.index, leaf, rec.pub.owner, rec.pub.masterAuth, rec.pub.encCommitment, rec.pub.class]) await this.absorb(x);
    await this.emitCiphertexts(rec, daNonce, pos);
  }

  /**
   * A displayed order's resting lots after a change, in clear (da.nr `emit_display`, SPEC.md §8.4,
   * [D1]); nothing for an undisplayed order. The entry never names the owner.
   */
  private async emitDisplay(m: number, o: { side: bigint; price: bigint; seq: bigint; display?: boolean }, lots: bigint) {
    if (!o.display || this.lite) return;
    for (const x of [M.TAG.DISPLAY, M.displayKey(BigInt(m), o.side, o.price, o.seq), lots]) await this.absorb(x);
  }

  /**
   * Replaces fields of an account record in place, as the record may be held elsewhere; in
   * sequencer mode the step's rollback restores them. Records are changed only through here.
   */
  private setRec(rec: AccountRecord, patch: Partial<Pick<AccountRecord, 'pub' | 'priv' | 'kEnc'>>) {
    if (this.undo.active) {
      const old = { pub: rec.pub, priv: rec.priv, kEnc: rec.kEnc };
      this.undo.push(() => Object.assign(rec, old));
    }
    Object.assign(rec, patch);
  }

  /** An account's leaf in the activity tree; witness-only, so sequencer mode skips it. */
  private async writeActivity(index: bigint, act: M.Activity) {
    if (this.lite) return;
    await this.activity.set(index, await M.activityHash(this.h, act));
  }

  /** Writes an account's new private part with the blind for the current DA position. */
  private async writeAccount(rec: AccountRecord, priv: M.AccountPriv, daNonce: bigint) {
    if (this.lite) {
      // The blind only enters the leaf and the DA, which sequencer mode does not build.
      this.setRec(rec, { priv: { ...priv, blind: 0n } });
      return 0n;
    }
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
    this.wdRecords.push(record);
    await this.absorb(M.TAG.WD);
    await this.absorb(record);
    return record;
  }

  private async finishSegment(pkg: string, label: string, inputs: Record<string, unknown>, receiptLeaves?: bigint[], clientProofs?: ClientProof[]) {
    if (this.lite) return;
    this.running.state = await this.trees();
    const receiptsRoot = receiptLeaves ? await this.h([DS0.RECEIPT_NODE, receiptLeaves[0], receiptLeaves[1]]) : 0n;
    this.segments.push({ pkg, label, inputs, expectedEnd: copyRunning(this.running), receiptsRoot, receiptLeaves, clientProofs });
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
      return { price: 0n, witness: { has: false, price: '0', seq: '0', order: emptyOrder(), path: siblingsToNoir(this.books[m].path(slot)), ...emptyOwner() } };
    }
    const index = X.orderIndex(best.side, best.price, best.seq);
    return {
      price: best.price,
      witness: {
        has: true,
        price: best.price.toString(),
        seq: best.seq.toString(),
        order: orderToNoir(best),
        path: siblingsToNoir(this.books[m].path(index)),
        owner_actv: M.activityToNoir(this.actv.get(best.account)!),
        owner_actv_path: hexPath(this.activity.path(best.account)),
      },
    };
  }

  /** The next trigger due as the mark rises (UP) or falls (DOWN), as a witness (SPEC.md §6.5). */
  private triggerTop(m: number, dir: bigint) {
    const ranked = [...this.triggers[m].entries()].filter(([, t]) => t.dir === dir).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const best = dir === X.DIR.UP ? ranked[0] : ranked[ranked.length - 1];
    if (!best) {
      const slot = dir === X.DIR.UP ? X.RIGHTMOST : X.LEFTMOST;
      return { price: 0n, witness: { ...emptyTriggerTop(), path: siblingsToNoir(this.triggerTrees[m].path(slot)) } };
    }
    const [index, t] = best;
    return {
      price: t.price,
      witness: { has: true, price: t.price.toString(), seq: t.seq.toString(), trigger: triggerToNoir(t), path: siblingsToNoir(this.triggerTrees[m].path(index)) },
    };
  }

  /** An order that can never fill: void (its owner cancelled all since) or expired at `time`. */
  private dead(o: X.Order, time: bigint) {
    return o.epoch !== this.actv.get(o.account)!.epoch || X.expired(o, time);
  }

  /**
   * Before a tick at `time`, removes dead orders from the top of the books it reads (SPEC.md §6.5):
   * a tick may use only live orders. An order that is dead only at `time`, being expired by then,
   * can be removed only once L3 time reaches it, so a block without updates comes first.
   */
  private async clearTops(time: bigint, markets: number[]) {
    for (;;) {
      // The dead orders at the top of each side, best first, down to its first live order.
      const dead: { market: number; index: bigint; o: X.Order }[] = [];
      for (const m of new Set(markets)) {
        for (const side of [M.SIDE.BID, M.SIDE.ASK]) {
          for (const index of this.orders[m].ranked(side)) {
            const o = this.orders[m].get(index)!;
            if (!this.dead(o, time)) break;
            dead.push({ market: m, index, o });
          }
        }
      }
      if (!dead.length) return;
      if (time > this.running.time && dead.some((d) => !this.dead(d.o, this.running.time))) await this.block(time, []);
      for (let i = 0; i < dead.length; i += CLEANUPS_PER_SEGMENT) await this.maintenance({ clean: dead.slice(i, i + CLEANUPS_PER_SEGMENT) });
    }
  }

  /** Block segment: opens an L3 block at `time`, with up to four signed index updates. */
  async block(time: bigint, updates: OracleUpdate[] = []) {
    return this.atomic(() => this.blockImpl(time, updates));
  }

  private async blockImpl(time: bigint, updates: OracleUpdate[] = []) {
    if (updates.length && !this.relax.has('cleanup')) await this.clearTops(time, updates.map((u) => Number(u.market)));
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
      const msg = await M.oracleMessage(this.hs, this.domain, u.market, u.price, u.external, u.time);
      let count = 0n;
      for (let j = 0; j < M.N_ORACLES; j++) {
        const s = u.sigs[j];
        if (!s) continue;
        assert(await verify(this.hs, { x: this.params.oraclePkX[j], y: this.params.oraclePkY[j] }, s, msg), `bad oracle signature ${j}`);
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
      // The tick flags the market while a trigger is due at the new mark (SPEC.md §6.5).
      const up = this.triggerTop(m, X.DIR.UP);
      const down = this.triggerTop(m, X.DIR.DOWN);
      this.markets[m].triggerPending = X.due(up.price, down.price, this.markets[m].markPrice);
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
        up: up.witness,
        down: down.witness,
      });
    }
    const emptyTop = () => ({ has: false, price: '0', seq: '0', order: emptyOrder(), path: emptyBookPath(), ...emptyOwner() });
    const emptyUpdate = () => ({
      market: '0',
      price: '0',
      external: '0',
      time: '0',
      signed: Array(M.N_ORACLES).fill(false),
      sigs: Array.from({ length: M.N_ORACLES }, zeroSig),
      bid: emptyTop(),
      ask: emptyTop(),
      up: emptyTriggerTop(),
      down: emptyTriggerTop(),
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
    return this.atomic(() => this.priorityImpl(reqs));
  }

  private async priorityImpl(reqs: M.Request[]) {
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
    const label = (q: M.Request) =>
      q.kind === M.KIND.REGISTER ? 'register' : q.kind === M.KIND.DEPOSIT ? 'deposit' : q.kind === M.KIND.REKEY ? 'rekey' : 'forced withdraw';
    const kinds = reqs.map(label).join(', ');
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
      dep_amount: '0',
      dep_salt: hex(0n),
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
        acct_path: hexPath(this.accounts.path(idx)),
        actv_path: hexPath(this.activity.path(idx)),
        k_enc: hex(kEnc),
      });
      const leaf = await this.writeAccount(rec, M.emptyPriv(), daNonce);
      const act = M.newActivity();
      await this.writeActivity(idx, act);
      this.accts.set(idx, rec);
      this.actv.set(idx, act);
      await this.initKeys(idx);
      this.numAccounts += 1n;
      await this.emitFull(M.TAG.FULL, rec, leaf, daNonce);
      return item;
    }
    if (q.kind === M.KIND.FORCED_WITHDRAW) return this.applyForcedWithdraw(q, item, daNonce);
    if (q.kind === M.KIND.REKEY) return this.applyRekey(q, item, daNonce);
    assert(q.kind === M.KIND.DEPOSIT, 'unknown request kind');
    // The queue holds a commitment to the amount; the opening came to the operator by constrained
    // delivery at deposit time (SPEC.md §10.3).
    const opening = q.deposit;
    assert(opening !== undefined, `no opening for the deposit committed in ${hex(q.b)}`);
    assert((await M.depositCommitment(this.hs, opening.amount, opening.salt)) === q.b, 'deposit opening does not match its commitment');
    const amount = opening.amount;
    Object.assign(item, { dep_amount: amount.toString(), dep_salt: hex(opening.salt) });
    const rec = q.a < this.numAccounts ? this.accts.get(q.a)! : undefined;
    // A credit that would take collateral out of range is refunded, as for a missing account.
    const credited = !!rec && rec.priv.collateral + amount < X.MAX_COLLATERAL;
    if (rec) {
      Object.assign(item, {
        account_index: q.a.toString(),
        acct_pub: M.pubToNoir(rec.pub),
        acct_priv: M.privToNoir(rec.priv),
        acct_path: hexPath(this.accounts.path(q.a)),
        k_enc: hex(rec.kEnc),
      });
    }
    if (!credited) {
      // Refunded to the deposit's refund address; the depositor's salt keeps the record hidden.
      await this.appendWithdrawal(q.c ?? 0n, amount, opening.salt);
      return item;
    }
    const priv = M.copyPriv(rec!.priv);
    priv.collateral += amount;
    const leaf = await this.writeAccount(rec!, priv, daNonce);
    await this.emitChange(rec!, leaf, daNonce);
    return item;
  }

  /**
   * Rekey (seg_priority `republish`, SPEC.md §7.3): from the account's owner, a new master
   * authorization (b) and encryption key (c, delivered through the Bridge); the key and order
   * epochs advance, so every session key is revoked and every order void. The account is
   * republished in full under the new key. A rekey from anyone else is consumed without effect.
   */
  private async applyRekey(q: M.Request, item: any, daNonce: bigint) {
    if (q.a >= this.numAccounts) return item;
    const rec = this.accts.get(q.a)!;
    const act = this.actv.get(q.a)!;
    const c = q.c ?? 0n;
    const kEnc = this.keyring.get(c);
    Object.assign(item, {
      account_index: q.a.toString(),
      acct_pub: M.pubToNoir(rec.pub),
      acct_priv: M.privToNoir(rec.priv),
      acct_path: hexPath(this.accounts.path(q.a)),
      actv: M.activityToNoir(act),
      actv_path: hexPath(this.activity.path(q.a)),
      k_enc: hex(kEnc ?? 0n),
    });
    if (rec.pub.owner !== q.sender && !this.relax.has('rekey-owner')) return item;
    assert(kEnc !== undefined, `no encryption key delivered for commitment ${hex(c)}`);
    this.setRec(rec, { pub: { ...rec.pub, masterAuth: q.b, encCommitment: c }, kEnc });
    const leaf = await this.writeAccount(rec, rec.priv, daNonce);
    const nact = { ...this.voidOrders(act), keyEpoch: act.keyEpoch + 1n };
    this.actv.set(q.a, nact);
    await this.writeActivity(q.a, nact);
    await this.emitFull(M.TAG.FULL, rec, leaf, daNonce);
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
      actv_path: hexPath(this.activity.path(q.a)),
      acct_path: hexPath(this.accounts.path(q.a)),
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
        // As a signed CancelAll: the order epoch advances, which voids every order at once.
        effect = `voided ${act.openOrders} orders`;
        act = this.voidOrders(act);
      }
      w.actv_path = hexPath(this.activity.path(idx));
      this.actv.set(idx, act);
      await this.writeActivity(idx, act);
      w.acct_path = hexPath(this.accounts.path(idx));
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
    if (!rec) return { pub_part: M.pubToNoir(M.zeroPub()), priv_part: M.privToNoir(M.emptyPriv()), path: zeros(M.ACCOUNTS_HEIGHT), k_enc: hex(0n), ...emptyOwnerActv() };
    return {
      pub_part: M.pubToNoir(rec.pub),
      priv_part: M.privToNoir(rec.priv),
      path: hexPath(this.accounts.path(rec.index)),
      k_enc: hex(rec.kEnc),
      actv: M.activityToNoir(this.actv.get(rec.index)!),
      actv_path: hexPath(this.activity.path(rec.index)),
    };
  }

  /**
   * The risk sweep at refresh (seg_refresh, SPEC.md §8.7): a user account whose exposure has fresh
   * indices and that is below maintenance margin must be liquidated before it is refreshed.
   */
  dueForLiquidation(index: bigint) {
    const rec = this.accts.get(index)!;
    const act = this.actv.get(index)!;
    if (rec.pub.class !== M.CLASS.USER || !X.exposureFresh(rec.priv, act, this.markets, this.params.maxAge, this.running.time)) return false;
    return X.below(X.equity(rec.priv, this.markets), X.maintenanceMargin(rec.priv, this.markets, this.params));
  }

  /**
   * Maintenance segment (SPEC.md §8.6, §9.5): optionally sweeps collected fees into the fee account
   * and whole micro-units of funding remainders into the insurance account, then republishes the
   * next `refresh` accounts after the refresh cursor under fresh keystreams.
   */
  /**
   * Maintenance segment: removes dead orders (`clean`), sweeps the protocol accounts' credits, and
   * refreshes the next accounts. A removal must be of a void or expired order unless the engine is
   * relaxed ('cleanup').
   */
  async maintenance(opts: { sweep?: boolean; refresh?: number; clean?: { market: number; index: bigint }[]; tiers?: { account: bigint; tier: bigint }[] }) {
    return this.atomic(() => this.maintenanceImpl(opts));
  }

  private async maintenanceImpl(opts: { sweep?: boolean; refresh?: number; clean?: { market: number; index: bigint }[]; tiers?: { account: bigint; tier: bigint }[] }) {
    const n = opts.refresh ?? 0;
    const clean = opts.clean ?? [];
    const tiers = opts.tiers ?? [];
    assert(tiers.length <= TIERS_PER_SEGMENT, 'too many tier changes');
    assert(n <= REFRESH_PER_SEGMENT && BigInt(n) <= this.numAccounts, 'refresh count');
    assert(clean.length <= CLEANUPS_PER_SEGMENT, 'too many removals');
    const start = copyRunning(this.running);
    const before = this.state();
    const removals: unknown[] = [];
    const removedDisplayed: { market: number; o: X.Order }[] = [];
    for (const c of clean) {
      const o = this.orders[c.market].get(c.index);
      assert(o, 'no such order to remove');
      const owner = this.actv.get(o.account)!;
      const isVoid = o.epoch !== owner.epoch;
      const isExpired = !isVoid && X.expired(o, this.running.time);
      assert(isVoid || isExpired || this.relax.has('cleanup'), 'order is live');
      removals.push({
        market: c.market.toString(),
        price: o.price.toString(),
        seq: o.seq.toString(),
        order: orderToNoir(o),
        path: siblingsToNoir(this.books[c.market].path(c.index)),
        owner_actv: M.activityToNoir(owner),
        owner_actv_path: hexPath(this.activity.path(o.account)),
      });
      await this.books[c.market].set(c.index, 0n, 0n, 0n);
      this.orders[c.market].delete(c.index);
      this.markets[c.market].bookRoot = this.books[c.market].root;
      if (o.display) removedDisplayed.push({ market: c.market, o });
      if (isExpired) {
        const nact = M.copyActivity(owner);
        if (!o.reduceOnly) {
          if (o.side === M.SIDE.BID) nact.openBid[c.market] -= o.lots;
          else nact.openAsk[c.market] -= o.lots;
        }
        nact.openOrders -= 1n;
        this.actv.set(o.account, nact);
        await this.writeActivity(o.account, nact);
      }
      const msg = await this.h([M.DS.CLEAN, BigInt(c.market), o.side, o.price, o.seq]);
      this.running.actionLog = await M.logAppend(this.h, this.running.actionLog, msg, M.LOG.CLEANUP);
    }
    // Fee tiers (SPEC.md §8.6): the operator's choice, logged; the circuit checks the tier exists.
    const tierChanges: unknown[] = [];
    for (const c of tiers) {
      const act = this.actv.get(c.account);
      assert(act, 'no such account');
      assert(c.tier < BigInt(M.FEE_TIERS) || this.relax.has('tiers'), 'fee tier');
      tierChanges.push({ account_index: c.account.toString(), tier: c.tier.toString(), actv: M.activityToNoir(act), actv_path: hexPath(this.activity.path(c.account)) });
      const nact = { ...M.copyActivity(act), feeTier: c.tier };
      this.actv.set(c.account, nact);
      await this.writeActivity(c.account, nact);
      this.running.actionLog = await M.logAppend(this.h, this.running.actionLog, await this.h([M.DS.TIER, c.account, c.tier]), M.LOG.TIER);
    }
    const daNonce = await M.segmentNonce(this.h, start.batch, this.running.actionLog, start.daLen);
    await this.absorb(M.TAG.SEG);
    await this.absorb(daNonce);
    for (const r of removedDisplayed) await this.emitDisplay(r.market, r.o, 0n);
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
      if (!this.relax.has('liq') && this.dueForLiquidation(rec.index)) throw new Error(`account ${rec.index} is due for liquidation`);
      items.push(this.refreshItem(rec));
      await this.emitFull(M.TAG.REFRESH, rec, await M.accountLeaf(this.h, rec.pub, rec.priv), daNonce);
      indices.push(rec.index);
      if (rec.index + 1n === this.numAccounts) {
        this.refreshCursor = 0n;
        this.cycleStart = this.running.time;
      } else {
        this.refreshCursor = rec.index + 1n;
      }
    }
    const label = [
      clean.length ? `remove ${clean.length} dead order${clean.length > 1 ? 's' : ''}` : '',
      tiers.length ? `fee tiers [${tiers.map((c) => `${c.account}: ${c.tier}`).join(', ')}]` : '',
      opts.sweep ? `sweep (${swept.join(', ')})` : '',
      n ? `refresh [${indices.join(', ')}]` : '',
    ]
      .filter(Boolean)
      .join(', ');
    await this.finishSegment('seg_refresh', label || 'maintenance', {
      ...this.base(start, before),
      n_clean: clean.length,
      removals: pad(removals, CLEANUPS_PER_SEGMENT, () => ({ market: '0', price: '0', seq: '0', order: emptyOrder(), path: emptyBookPath(), ...emptyOwner() })),
      n_tiers: tiers.length,
      tiers: pad(tierChanges, TIERS_PER_SEGMENT, () => ({ account_index: '0', tier: '0', actv: M.activityToNoir(M.newActivity()), actv_path: zeros(M.ACCOUNTS_HEIGHT) })),
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

  // ---- Sequencer mode (P2.24) ----

  /**
   * Runs `f` as one step. In sequencer mode, if it throws, everything it changed is undone; a
   * step inside another rolls back to its own savepoint. The witness builder's engine runs `f`
   * as it is: it only replays steps the sequencer applied.
   */
  async atomic<T>(f: () => Promise<T>): Promise<T> {
    if (!this.lite) return f();
    const outer = !this.undo.active;
    if (outer) this.undo.begin();
    const sp = this.snapshot();
    try {
      const v = await f();
      if (outer) this.undo.commit();
      return v;
    } catch (e) {
      this.restore(sp);
      if (outer) this.undo.commit();
      throw e;
    }
  }

  /**
   * Sequencer mode: applies one signed action atomically, giving it the next sequence number
   * (SPEC.md §11), or refuses it with nothing changed by throwing the reason. Returns its fills and
   * where its remainder rests.
   */
  async sequence(a: SignedAction): Promise<Execution> {
    if (!this.lite) throw new Error('sequence() is for sequencer mode');
    const x: Execution = { fills: [] };
    this.onFill = (f) => x.fills.push(f);
    this.onRest = (r) => (x.rested = r);
    try {
      await this.atomic(async () => {
        a.seq = this.lastSeq + 1n;
        await this.execAction(a, 0n);
        this.lastSeq = a.seq;
      });
      return x;
    } finally {
      this.onFill = undefined;
      this.onRest = undefined;
    }
  }

  // ---- Trading (seg_trade, SPEC.md §8) ----

  snapshot(): Snapshot {
    if (this.lite) {
      if (!this.undo.active) throw new Error('sequencer mode snapshots only inside an atomic step');
      return { lite: true, mark: this.undo.savepoint(), ...this.scalars() };
    }
    return this.fullSnapshot();
  }

  /** A deep copy of the whole state (the witness builder's engine). */
  fullSnapshot() {
    return {
      lite: false as const,
      accounts: this.accounts.snapshot(),
      activity: this.activity.snapshot(),
      books: this.books.map((b) => b.snapshot()),
      triggerTrees: this.triggerTrees.map((b) => b.snapshot()),
      triggers: this.triggers.map((t) => new JMap(this.undo, [...t].map(([k, v]) => [k, { ...v }] as const))),
      accts: new JMap(this.undo, [...this.accts].map(([k, v]) => [k, { ...v, pub: { ...v.pub }, priv: M.copyPriv(v.priv) }] as const)),
      actv: new JMap(this.undo, [...this.actv].map(([k, v]) => [k, M.copyActivity(v)] as const)),
      orders: this.orders.map((o) => o.clone()),
      keys: new JMap(this.undo, [...this.keys].map(([k, v]) => [k, new JMap(this.undo, [...v].map(([i, x]) => [i, { ...x }] as const))] as const)),
      keyTrees: new Map([...this.keyTrees].map(([k, t]) => [k, t.snapshot()])),
      markets: this.markets.map((m) => ({ ...m })),
      feesPending: this.feesPending,
      insurancePending: this.insurancePending,
      insuranceMicro: this.insuranceMicro,
      lastSeq: this.lastSeq,
      refreshCursor: this.refreshCursor,
      cycleStart: this.cycleStart,
      receipts: [...this.receipts],
      running: copyRunning(this.running),
      daPayload: [...this.daPayload],
      wdRecords: [...this.wdRecords],
    };
  }

  /** The scalars, markets and batch-building state a sequencer-mode savepoint restores. */
  private scalars(): Scalars {
    return {
      markets: this.markets.map((m) => ({ ...m })),
      feesPending: this.feesPending,
      insurancePending: this.insurancePending,
      insuranceMicro: this.insuranceMicro,
      lastSeq: this.lastSeq,
      refreshCursor: this.refreshCursor,
      cycleStart: this.cycleStart,
      numAccounts: this.numAccounts,
      running: this.running ? copyRunning(this.running) : this.running,
      lengths: [this.receipts.length, this.daPayload.length, this.wdRecords.length, this.segments.length, this.rejected.length],
    };
  }

  restore(s: Snapshot) {
    if (s.lite) {
      this.undo.rollbackTo(s.mark);
      this.markets = s.markets.map((m) => ({ ...m }));
      this.feesPending = s.feesPending;
      this.insurancePending = s.insurancePending;
      this.insuranceMicro = s.insuranceMicro;
      this.lastSeq = s.lastSeq;
      this.refreshCursor = s.refreshCursor;
      this.cycleStart = s.cycleStart;
      this.numAccounts = s.numAccounts;
      this.running = s.running ? copyRunning(s.running) : s.running;
      const [rc, da, wd, sg, rj] = s.lengths;
      this.receipts.length = rc;
      this.daPayload.length = da;
      this.wdRecords.length = wd;
      this.segments.length = sg;
      this.rejected.length = rj;
      return;
    }
    this.accounts.restore(s.accounts);
    this.activity.restore(s.activity);
    this.books.forEach((b, i) => b.restore(s.books[i]));
    this.triggerTrees.forEach((b, i) => b.restore(s.triggerTrees[i]));
    this.triggers = s.triggers;
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
    this.lastSeq = s.lastSeq;
    this.refreshCursor = s.refreshCursor;
    this.cycleStart = s.cycleStart;
    this.receipts = s.receipts;
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
    if (this.lite) {
      for (const a of actions) {
        try {
          await this.sequence(a);
        } catch (e: any) {
          this.rejected.push({ action: a, reason: String(e.message ?? e) });
        }
      }
      return;
    }
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
    // Each action gets the next sequence number and a receipt leaf (SPEC.md §11).
    const leaves = [0n, 0n];
    for (const [i, a] of actions.entries()) {
      a.seq = ++this.lastSeq;
      const msg = await X.actionMsg(this.h, this.domain, a.kind, a.account, a.keyId, a.nonce, a.p);
      leaves[i] = await this.h([DS0.RECEIPT, a.seq, msg]);
      this.receipts.push({ msg, seq: a.seq, segment: this.segments.length, slot: i });
      try {
        items.push({ ...(await this.execAction(a, daNonce)), seq: a.seq.toString() });
      } catch (e: any) {
        e.actionIndex = i;
        throw e;
      }
    }
    const names: Record<string, string> = {
      [X.KIND_ACT.WITHDRAW.toString()]: 'withdraw',
      [X.KIND_ACT.TRANSFER.toString()]: 'transfer',
      [X.KIND_ACT.ADD_KEY.toString()]: 'add key',
      [X.KIND_ACT.REVOKE_KEY.toString()]: 'revoke key',
      [X.KIND_ACT.SET_MASTER_AUTH.toString()]: 'set master auth',
    };
    const labels = actions.map((a) => {
      const by = a.keyId === M.MASTER_KEY ? '' : ` by key ${a.keyId}`;
      if (a.kind === X.KIND_ACT.CANCEL_ALL) return `cancel all${by}`;
      const book =
        a.kind === X.KIND_ACT.PLACE
          ? 'place'
          : a.kind === X.KIND_ACT.CANCEL
            ? 'cancel'
            : a.kind === X.KIND_ACT.MODIFY
              ? 'modify'
              : a.kind === X.KIND_ACT.PLACE_TRIGGER
                ? 'trigger'
                : a.kind === X.KIND_ACT.CANCEL_TRIGGER
                  ? 'cancel trigger'
                  : '';
      return (book ? `${book} m${a.p[0]}` : names[a.kind.toString()]) + by;
    });
    await this.finishSegment(
      'seg_trade',
      `trade [${labels.join(', ')}]`,
      { ...this.base(start, before), n: actions.length, actions: pad(items, TRADE_PER_SEGMENT, () => this.emptyAction()) },
      leaves,
    );
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
      seq: '0',
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
      cancel_display: false,
      cancel_reduce_only: false,
      dest_pub: M.pubToNoir(M.zeroPub()),
      dest_priv: M.privToNoir(M.emptyPriv()),
      dest_k_enc: hex(0n),
      dest_acct_path: zeros(M.ACCOUNTS_HEIGHT),
      trigger: emptyTrigger(),
      trigger_path: emptyBookPath(),
    };
  }

  // ---- Client-proof actions (tube, SPEC.md §7.4) ----

  /**
   * Executes master actions authorized by client proofs, CLIENT_PER_SEGMENT per P-segment. An
   * action the rules refuse (its proof does not control the account or authorizes another action,
   * a stale nonce, a kind other than AddKey, RevokeKey and Withdraw, a bad key slot, a withdrawal
   * the margin does not cover) is dropped and recorded in `rejected`, as the operator would refuse
   * it before aggregating its proof.
   */
  async proven(actions: ProvenAction[]) {
    return this.atomic(() => this.provenImpl(actions));
  }

  private async provenImpl(actions: ProvenAction[]) {
    const queue = [...actions];
    while (queue.length) await this.provenSegment(queue);
  }

  /**
   * One P-segment: takes actions from the front of `queue` until CLIENT_PER_SEGMENT apply. The
   * segment's aggregation folds the applied proofs' public inputs, as agg_app does, and the action
   * log records it; the segment nonce, and so every withdrawal's blind, depends on that log. So a
   * dry run first decides which actions apply (none depends on where the DA segment sits), then
   * the segment is logged, opened and executed. A segment with nothing to apply is dropped unless
   * `emitEmpty`.
   */
  async provenSegment(queue: ProvenAction[], emitEmpty = false) {
    assert(this.clientVks.size > 0, 'client-proof actions need the client circuits (Engine.create)');
    const start = copyRunning(this.running);
    const before = this.state();
    const dry = this.snapshot();
    const applied: ProvenAction[] = [];
    while (queue.length && applied.length < CLIENT_PER_SEGMENT) {
      const a = queue.shift()!;
      const snap = this.snapshot();
      try {
        await this.execProven(a, 0n);
        applied.push(a);
      } catch (e: any) {
        this.restore(snap);
        this.rejected.push({ action: a, reason: String(e.message ?? e) });
      }
    }
    this.restore(dry);
    if (!applied.length && !emitEmpty) return;
    let acc = 0n;
    for (const a of applied) acc = await this.h([DS0.AGG, acc, this.clientVks.get(a.proof.pkg)!, ...a.proof.publicInputs.map((x) => BigInt(x))]);
    const r = this.running;
    r.actionLog = await M.logAppend(this.h, r.actionLog, acc, BigInt(applied.length));
    const daNonce = await M.segmentNonce(this.h, start.batch, r.actionLog, start.daLen);
    await this.absorb(M.TAG.SEG);
    await this.absorb(daNonce);
    const items: unknown[] = [];
    for (const a of applied) items.push(await this.execProven(a, daNonce));
    const name = (a: ProvenAction) =>
      a.kind === X.KIND_ACT.WITHDRAW ? `withdraw ${a.account}` : `${a.kind === X.KIND_ACT.ADD_KEY ? 'add' : 'revoke'} key ${a.account}/${a.p[0]}`;
    await this.finishSegment(
      'tube',
      `proven [${applied.map(name).join(', ')}]`,
      {
        ...this.base(start, before),
        agg: { actions_hash: hex(acc), count: applied.length, vk_tree_root: hex(this.vkTreeRoot) },
        actions: pad(items, CLIENT_PER_SEGMENT, () => this.emptyClientAction()),
      },
      undefined,
      applied.map((a) => a.proof),
    );
  }

  /** The tube's checks, in its order, then the key slot write or the withdrawal (shared with seg_trade). */
  private async execProven(a: ProvenAction, daNonce: bigint) {
    const vkHash = this.clientVks.get(a.proof.pkg);
    if (vkHash === undefined) throw new Error('client circuit not in the VK tree');
    const [msg, account, binding] = a.proof.publicInputs.map((x) => BigInt(x));
    if (account !== a.account) throw new Error('the proof is for another account');
    const rec = this.accts.get(account);
    const oldAct = this.actv.get(account);
    if (!rec || !oldAct) throw new Error('account');
    if (!this.relax.has('client-auth') && (await M.masterAuthP(this.hs, vkHash, binding)) !== rec.pub.masterAuth) {
      throw new Error('client proof does not control the account');
    }
    if (msg !== (await X.actionMsg(this.hs, this.domain, a.kind, account, M.MASTER_KEY, a.nonce, a.p))) throw new Error('proof authorizes another action');
    if (oldAct.nonce + 1n !== a.nonce) throw new Error('nonce');
    const { ADD_KEY, REVOKE_KEY, WITHDRAW } = X.KIND_ACT;
    if (a.kind !== ADD_KEY && a.kind !== REVOKE_KEY && a.kind !== WITHDRAW) throw new Error('client proofs only manage session keys and withdraw');
    const act = M.copyActivity(oldAct);
    act.nonce = a.nonce;
    const priv = M.privToNoir(rec.priv);
    const w =
      a.kind === WITHDRAW
        ? { key: M.keyToNoir(M.emptyKey()), key_path: zeros(M.KEYS_HEIGHT), ...(await this.execWithdraw(a, rec, act, daNonce)) }
        : await this.execSetKey(a, act);
    return {
      vk_hash: hex(vkHash),
      msg: hex(msg),
      account_index: hex(account),
      auth_binding: hex(binding),
      kind: hex(a.kind),
      nonce: a.nonce.toString(),
      p: a.p.map(hex),
      acct_pub: M.pubToNoir(rec.pub),
      acct_priv: priv,
      acct_path: w.taker_acct_path,
      k_enc: hex(rec.kEnc),
      actv: M.activityToNoir(oldAct),
      actv_path: w.taker_actv_path,
      key: w.key,
      key_path: w.key_path,
    };
  }

  private emptyClientAction() {
    return {
      vk_hash: hex(0n),
      msg: hex(0n),
      account_index: hex(0n),
      auth_binding: hex(0n),
      kind: hex(0n),
      nonce: '0',
      p: zeros(X.ACTION_PAYLOAD),
      acct_pub: M.pubToNoir(M.zeroPub()),
      acct_priv: M.privToNoir(M.emptyPriv()),
      acct_path: zeros(M.ACCOUNTS_HEIGHT),
      k_enc: hex(0n),
      actv: M.activityToNoir(M.newActivity()),
      actv_path: zeros(M.ACCOUNTS_HEIGHT),
      key: M.keyToNoir(M.emptyKey()),
      key_path: zeros(M.KEYS_HEIGHT),
    };
  }

  /** The best resting order on `side` of market m: the lowest ask or the highest bid (SPEC.md §6.5). */
  private best(m: number, side: bigint): BookOrder | undefined {
    return this.orders[m].bestOn(side);
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
    this.keys.set(index, new JMap(this.undo));
    this.keyTrees.set(index, this.lite ? (new NullTree(M.KEYS_HEIGHT) as unknown as MerkleTree) : await new MerkleTree(this.h, M.KEYS_HEIGHT, M.DS.KEY_NODE).init());
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
    // The gateway's checks when it made them (P2.24); otherwise the engine's own.
    const msg = a.prepared?.msg ?? (await X.actionMsg(this.hs, this.domain, a.kind, a.account, a.keyId, a.nonce, a.p));
    const signed = async () => a.prepared?.ok ?? (await verify(this.hs, a.pk, a.sig, msg));
    // Authorization (SPEC.md §7.2): the master key, or a session key within its scope.
    const act = M.copyActivity(oldAct);
    let keyWitness: { key: unknown; key_path: string[] } | undefined;
    if (a.keyId === M.MASTER_KEY) {
      if ((a.prepared?.masterAuth ?? (await M.masterAuthOf(this.hs, a.pk.x, a.pk.y))) !== rec.pub.masterAuth) throw new Error("signing key is not the account's");
      if (!(await signed())) throw new Error('bad signature');
      if (oldAct.nonce + 1n !== a.nonce) throw new Error('nonce');
      act.nonce = a.nonce;
    } else {
      const slot = Number(a.keyId);
      if (a.keyId < 0n || slot >= M.KEY_SLOTS) throw new Error('key slot');
      const key = this.keyOf(a.account, slot);
      if (key.pkX !== a.pk.x || key.pkY !== a.pk.y || (a.pk.x === 0n && a.pk.y === 0n)) throw new Error("signing key is not the slot's");
      if (!(await signed())) throw new Error('bad signature');
      if (key.nonce + 1n !== a.nonce) throw new Error('nonce');
      if (this.running.time > key.expiry) throw new Error('session key expired');
      if (key.epoch !== oldAct.keyEpoch && !this.relax.has('revoked-keys')) throw new Error('session key revoked by a rekey');
      const { PLACE, CANCEL, MODIFY, CANCEL_ALL, PLACE_TRIGGER, CANCEL_TRIGGER } = X.KIND_ACT;
      if (![PLACE, CANCEL, MODIFY, CANCEL_ALL, PLACE_TRIGGER, CANCEL_TRIGGER].includes(a.kind as any)) throw new Error('session keys only place, cancel, modify and cancel all');
      if (a.kind !== CANCEL_ALL && (a.p[0] >= BigInt(M.MARKETS) || ((key.marketMask >> a.p[0]) & 1n) !== 1n)) throw new Error('market not allowed for the session key');
      if ((a.kind === PLACE || a.kind === PLACE_TRIGGER) && a.p[2] * a.p[3] > key.maxNotional) throw new Error("order above the session key's notional limit");
      if (!this.lite) keyWitness = { key: M.keyToNoir(key), key_path: hexPath(this.keyTrees.get(a.account)!.path(BigInt(slot))) };
      act.keysRoot = await this.writeKey(a.account, slot, { ...key, nonce: a.nonce });
    }
    if (this.lite) {
      // Sequencer mode builds no witness: the same rules, then nothing to return.
      await this.dispatch(a, rec, oldAct, act, daNonce);
      return {};
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
      ...(keyWitness ?? { key: M.keyToNoir(M.emptyKey()), key_path: zeros(M.KEYS_HEIGHT) }),
      taker_pub: M.pubToNoir(rec.pub),
      taker_priv: M.privToNoir(rec.priv),
      taker_k_enc: hex(rec.kEnc),
      taker_actv: M.activityToNoir(oldAct),
    };
    return { ...this.emptyAction(), ...common, ...(await this.dispatch(a, rec, oldAct, act, daNonce)) };
  }

  /** The rules of each kind of signed action, after its authorization. */
  private async dispatch(a: SignedAction, rec: AccountRecord, oldAct: M.Activity, act: M.Activity, daNonce: bigint): Promise<Record<string, unknown>> {
    if (a.kind === X.KIND_ACT.PLACE) return this.execPlace(a, rec, oldAct, act, daNonce);
    if (a.kind === X.KIND_ACT.CANCEL || a.kind === X.KIND_ACT.MODIFY) return this.execCancel(a, act);
    if (a.kind === X.KIND_ACT.WITHDRAW) return this.execWithdraw(a, rec, act, daNonce);
    if (a.kind === X.KIND_ACT.TRANSFER) return this.execTransfer(a, rec, act, daNonce);
    if (a.kind === X.KIND_ACT.CANCEL_ALL) return this.execCancelAll(a, act);
    if (a.kind === X.KIND_ACT.ADD_KEY || a.kind === X.KIND_ACT.REVOKE_KEY) return this.execSetKey(a, act);
    if (a.kind === X.KIND_ACT.PLACE_TRIGGER || a.kind === X.KIND_ACT.CANCEL_TRIGGER) return this.execTrigger(a, act);
    if (a.kind === X.KIND_ACT.SET_MASTER_AUTH) return this.execSetMasterAuth(a, rec, act, daNonce);
    throw new Error('unknown action kind');
  }

  /**
   * PlaceTrigger, p = (market, side, limit, lots, dir, trigger price), and CancelTrigger,
   * p = (market, dir, trigger price, seq) (seg_trade `trigger_action`, SPEC.md §6.5). A new trigger
   * must not be due at the current mark; it takes the market's next sequence number.
   */
  private async execTrigger(a: SignedAction, act: M.Activity) {
    const m = Number(a.p[0]);
    if (a.p[0] < 0n || m >= M.MARKETS) throw new Error('market');
    const mk = this.markets[m];
    const witness: Record<string, unknown> = {};
    const acctPath = hexPath(this.accounts.path(a.account));
    if (a.kind === X.KIND_ACT.PLACE_TRIGGER) {
      const [, side, limit, lots, dir, price, p6, p7] = a.p;
      if (this.params.markets[m].imrPpm === 0n) throw new Error('market not listed');
      if (side !== M.SIDE.BID && side !== M.SIDE.ASK) throw new Error('side');
      if (dir !== X.DIR.UP && dir !== X.DIR.DOWN) throw new Error('trigger direction');
      if (limit <= 0n || limit >= X.MAX_PRICE || lots <= 0n || lots >= X.MAX_LOTS || price <= 0n || price >= X.MAX_PRICE) throw new Error('trigger out of range');
      // p6 is the entry flag: a stop that opens a position (P2.20).
      if ((p6 !== 0n && p6 !== 1n) || p7 !== 0n) throw new Error('trigger payload');
      if (mk.markPrice === 0n) throw new Error('no mark price');
      if (dir === X.DIR.UP ? price <= mk.markPrice : price >= mk.markPrice) throw new Error('trigger already due');
      const seq = mk.nextSeq;
      const index = X.triggerIndex(dir, price, seq);
      witness.trigger_path = siblingsToNoir(this.triggerTrees[m].path(index));
      const t: X.Trigger = { dir, side, account: a.account, lots, limit, epoch: act.epoch, price, seq, entry: p6 === 1n };
      await this.triggerTrees[m].set(index, await X.triggerLeaf(this.h, t), dir === X.DIR.UP ? lots : 0n, dir === X.DIR.DOWN ? lots : 0n);
      this.triggers[m].set(index, t);
      mk.nextSeq = seq + 1n;
    } else {
      const [, dir, price, seq] = a.p;
      const index = X.triggerIndex(dir, price, seq);
      const t = this.triggers[m].get(index);
      if (!t || t.account !== a.account || t.dir !== dir) throw new Error("not the account's trigger");
      Object.assign(witness, { trigger: triggerToNoir(t), trigger_path: siblingsToNoir(this.triggerTrees[m].path(index)) });
      await this.triggerTrees[m].set(index, 0n, 0n, 0n);
      this.triggers[m].delete(index);
    }
    mk.triggerRoot = this.triggerTrees[m].root;
    const actvPath = hexPath(this.activity.path(a.account));
    this.actv.set(a.account, act);
    await this.writeActivity(a.account, act);
    return { taker_acct_path: acctPath, taker_actv_path: actvPath, ...witness };
  }

  // ---- Trigger firings (seg_trigger, SPEC.md §6.5) ----

  /** The next trigger due in market m, UP first, as [index, trigger], or undefined. */
  nextDue(m: number): [bigint, X.Trigger] | undefined {
    const mark = this.markets[m].markPrice;
    const ranked = [...this.triggers[m].entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const up = ranked.find(([, t]) => t.dir === X.DIR.UP);
    if (up && up[1].price <= mark) return up;
    const downs = ranked.filter(([, t]) => t.dir === X.DIR.DOWN);
    const down = downs[downs.length - 1];
    if (down && down[1].price >= mark) return down;
    return undefined;
  }

  /** Fires the triggers due in the given markets, one seg_trigger segment each, until none is. */
  async fireTriggers(markets: number[] = [...Array(M.MARKETS).keys()]) {
    return this.atomic(() => this.fireTriggersImpl(markets));
  }

  private async fireTriggersImpl(markets: number[] = [...Array(M.MARKETS).keys()]) {
    for (const m of markets) {
      for (let guard = 0; this.markets[m].triggerPending; guard++) {
        assert(guard < 64, `trigger firing in market ${m} does not converge`);
        const next = this.nextDue(m);
        assert(!!next, `market ${m} is flagged but no trigger is due`);
        await this.triggerSegment(m, next[0], next[1]);
      }
    }
  }

  /**
   * One firing: an IOC order at the trigger's limit. A reduce-only trigger fills at most the owner's
   * position on its other side; an entry trigger fills its lots and must then be affordable, or
   * the firing is undone and consumed without effect (seg_trigger). The rest stays in the tree only
   * when the matching steps ran out.
   */
  async triggerSegment(m: number, index: bigint, t: X.Trigger) {
    return this.atomic(() => this.triggerSegmentImpl(m, index, t));
  }

  private async triggerSegmentImpl(m: number, index: bigint, t: X.Trigger) {
    const start = copyRunning(this.running);
    const before = this.state();
    const r = this.running;
    r.actionLog = await M.logAppend(this.h, r.actionLog, await this.h([M.DS.FIRE, BigInt(m), index]), M.LOG.TRIGGER);
    const daNonce = await M.segmentNonce(this.h, start.batch, r.actionLog, start.daLen);
    await this.absorb(M.TAG.SEG);
    await this.absorb(daNonce);
    const mp = this.params.markets[m];
    const rec = this.accts.get(t.account)!;
    const act0 = this.actv.get(t.account)!;
    const w: Record<string, unknown> = {
      market: m.toString(),
      dir: hex(t.dir),
      price: t.price.toString(),
      seq: t.seq.toString(),
      trigger: triggerToNoir(t),
      trigger_path: siblingsToNoir(this.triggerTrees[m].path(index)),
      acct_pub: M.pubToNoir(rec.pub),
      acct_priv: M.privToNoir(rec.priv),
      k_enc: hex(rec.kEnc),
      actv: M.activityToNoir(act0),
      n_fills: 0,
      fills: Array.from({ length: FILLS }, () => this.emptyFill()),
      probe_path: emptyBookPath(),
    };
    const live = t.epoch === act0.epoch;
    const pos = rec.priv.positions[m].size;
    const held = t.side === M.SIDE.ASK && pos > 0n ? pos : t.side === M.SIDE.BID && pos < 0n ? -pos : 0n;
    const q = !live ? 0n : t.entry || t.lots < held ? t.lots : held;
    let priv = M.copyPriv(rec.priv);
    let act = M.copyActivity(act0);
    let traded = false;
    let left = 0n;
    let effect = live ? 'nothing to reduce' : 'void';
    const beforeFill = t.entry ? this.snapshot() : undefined;
    if (q > 0n) {
      const taker = { index: t.account, priv, act, traded: false };
      const matched = await this.matchOrder(m, t.side, t.limit, q, taker, daNonce, mp.makerFeePpm, mp.takerFeePpm);
      if (matched.remaining > 0n) {
        if (matched.fills.length < FILLS) w.probe_path = siblingsToNoir(this.books[m].path(X.orderIndex(t.side, t.limit, this.markets[m].nextSeq)));
        else left = matched.remaining;
      }
      this.markets[m].bookRoot = this.books[m].root;
      priv = taker.priv;
      act = taker.act;
      traded = taker.traded;
      Object.assign(w, { n_fills: matched.fills.length, fills: pad(matched.fills, FILLS, () => this.emptyFill()) });
      effect = `filled ${q - matched.remaining} of ${q}${left ? `, ${left} left to fire` : ''}`;
    }
    // An entry trigger that raised the owner's worst-case exposure must leave it above initial
    // margin at fresh indices; otherwise the firing is undone and the trigger consumed.
    if (t.entry && traded) {
      const wBefore = X.worst(rec.priv.positions[m].size, act0.openBid[m], act0.openAsk[m]);
      const wAfter = X.worst(priv.positions[m].size, act.openBid[m], act.openAsk[m]);
      const affordable =
        wAfter <= wBefore ||
        (X.exposureFresh(priv, act, this.markets, this.params.maxAge, this.running.time) &&
          X.covers(X.equity(priv, this.markets), X.initialMargin(priv, act, this.markets, this.params)));
      if (!affordable && !this.relax.has('entry-margin')) {
        this.restore(beforeFill!);
        priv = M.copyPriv(rec.priv);
        act = M.copyActivity(act0);
        traded = false;
        left = 0n;
        effect = 'unaffordable, consumed without effect';
      }
    }
    if (left > 0n) {
      const kept = { ...t, lots: left };
      await this.triggerTrees[m].set(index, await X.triggerLeaf(this.h, kept), t.dir === X.DIR.UP ? left : 0n, t.dir === X.DIR.DOWN ? left : 0n);
      this.triggers[m].set(index, kept);
    } else {
      await this.triggerTrees[m].set(index, 0n, 0n, 0n);
      this.triggers[m].delete(index);
    }
    this.markets[m].triggerRoot = this.triggerTrees[m].root;
    const up = this.triggerTop(m, X.DIR.UP);
    const down = this.triggerTop(m, X.DIR.DOWN);
    this.markets[m].triggerPending = X.due(up.price, down.price, this.markets[m].markPrice);
    Object.assign(w, { up: up.witness, down: down.witness });
    w.actv_path = hexPath(this.activity.path(t.account));
    this.actv.set(t.account, act);
    await this.writeActivity(t.account, act);
    w.acct_path = hexPath(this.accounts.path(t.account));
    if (traded) {
      const leaf = await this.writeAccount(rec, priv, daNonce);
      await this.emitChange(rec, leaf, daNonce);
    }
    const name = `${t.dir === X.DIR.UP ? 'UP' : 'DOWN'} ${t.side === M.SIDE.ASK ? 'sell' : 'buy'} m${m} @${t.price} for ${t.account}`;
    await this.finishSegment('seg_trigger', `fire ${name} (${effect})`, { ...this.base(start, before), ...w });
  }

  /** AddKey and RevokeKey (seg_trade `set_key`): master only; the slot keeps its nonce. */
  private async execSetKey(a: Pick<SignedAction, 'kind' | 'account' | 'p'>, act: M.Activity) {
    const slot = Number(a.p[0]);
    if (a.p[0] < 0n || slot >= M.KEY_SLOTS) throw new Error('key slot');
    const old = this.keyOf(a.account, slot);
    const keyPath = hexPath(this.keyTrees.get(a.account)!.path(BigInt(slot)));
    let k: M.Key;
    if (a.kind === X.KIND_ACT.ADD_KEY) {
      if (a.p[3] >= 1n << 32n || a.p[4] >= 1n << 64n || a.p[5] >= 1n << 64n) throw new Error('key parameters out of range');
      if (a.p[1] === 0n && a.p[2] === 0n) throw new Error('empty key');
      k = { pkX: a.p[1], pkY: a.p[2], marketMask: a.p[3], maxNotional: a.p[4], expiry: a.p[5], nonce: old.nonce, epoch: act.keyEpoch };
    } else {
      k = { ...M.emptyKey(), nonce: old.nonce, epoch: old.epoch };
    }
    const acctPath = hexPath(this.accounts.path(a.account));
    act.keysRoot = await this.writeKey(a.account, slot, k);
    const actvPath = hexPath(this.activity.path(a.account));
    this.actv.set(a.account, act);
    await this.writeActivity(a.account, act);
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
    const display = a.p[7];
    if (display !== 0n && display !== 1n) throw new Error('display flag');
    if ((tif === X.TIF.GTT) !== (expiry !== 0n)) throw new Error('only GTT orders expire');
    if (expiry !== 0n && expiry <= this.running.time) throw new Error('order already expired');
    if (reduceOnly === 1n && rests) {
      // A resting reduce-only order must fit within the position it reduces (P2.21).
      const size = rec.priv.positions[m].size;
      if (size === 0n || size > 0n !== (side === M.SIDE.ASK)) throw new Error('reduce-only order must reduce');
      if (lots > X.abs(size)) throw new Error('reduce-only order larger than the position');
    }
    if (this.markets[m].triggerPending && !this.relax.has('triggers')) throw new Error('triggers are due in this market');
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
        const o = { side, account: a.account, lots: remaining, price, seq, market: mk, expiry, epoch: act.epoch, display: display === 1n, reduceOnly: reduceOnly === 1n };
        await book.set(slot, await X.orderLeaf(this.h, side, a.account, remaining, expiry, act.epoch, o.display, o.reduceOnly), X.askLots(o), X.bidLots(o));
        this.orders[m].set(slot, o);
        await this.emitDisplay(m, o, remaining);
        this.markets[m].nextSeq = seq + 1n;
        this.onRest?.({ market: m, side, price, seq, lots: remaining });
        // A reduce-only order holds no open lots: it can never add exposure.
        if (!o.reduceOnly) {
          if (side === M.SIDE.BID) act.openBid[m] += remaining;
          else act.openAsk[m] += remaining;
        }
        act.openOrders += 1n;
        if (act.openOrders > X.MAX_OPEN_ORDERS) throw new Error('too many open orders');
      }
    }
    this.markets[m].bookRoot = book.root;

    const acctPath = hexPath(this.accounts.path(a.account));
    if (traded) {
      const leaf = await this.writeAccount(rec, taker, daNonce);
      await this.emitChange(rec, leaf, daNonce);
    }
    const actvPath = hexPath(this.activity.path(a.account));
    this.actv.set(a.account, act);
    await this.writeActivity(a.account, act);

    const wBefore = X.worst(sizeBefore, oldAct.openBid[m], oldAct.openAsk[m]);
    const wAfter = X.worst(rec.priv.positions[m].size, act.openBid[m], act.openAsk[m]);
    if (wAfter > wBefore) {
      if (!X.exposureFresh(rec.priv, act, this.markets, this.params.maxAge, this.running.time)) throw new Error('index too old for a risk-increasing order');
      if (!X.covers(X.equity(rec.priv, this.markets), X.initialMargin(rec.priv, act, this.markets, this.params))) throw new Error('insufficient margin');
    }
    if (this.lite) return {};
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
      const fillWitness: any = this.lite ? {} : { ...this.emptyFill(), index: hex(index), price: o.price.toString(), seq: o.seq.toString(), order: orderToNoir(o), book_path: siblingsToNoir(book.path(index)) };
      if (o.account === t.index) {
        // Self-trade prevention: the taker's own resting order is cancelled; only a live one still
        // counts toward its open lots.
        await book.set(index, 0n, 0n, 0n);
        this.orders[m].delete(index);
        await this.emitDisplay(m, o, 0n);
        if (o.epoch === t.act.epoch) {
          if (!o.reduceOnly) {
            if (o.side === M.SIDE.BID) t.act.openBid[m] -= o.lots;
            else t.act.openAsk[m] -= o.lots;
          }
          t.act.openOrders -= 1n;
        }
        fills.push(fillWitness);
        continue;
      }
      if (o.epoch !== this.actv.get(o.account)!.epoch) {
        // A void order (its owner cancelled all since) is removed; the owner's activity is proved unchanged.
        const oact = this.actv.get(o.account)!;
        if (!this.lite) Object.assign(fillWitness, { maker_actv: M.activityToNoir(oact), maker_actv_path: hexPath(this.activity.path(o.account)) });
        await book.set(index, 0n, 0n, 0n);
        this.orders[m].delete(index);
        await this.emitDisplay(m, o, 0n);
        fills.push(fillWitness);
        continue;
      }
      if (X.expired(o, this.running.time)) {
        // An expired GTT order is removed instead of filled; its owner's open lots shrink.
        const oact = this.actv.get(o.account)!;
        if (!this.lite) Object.assign(fillWitness, { maker_actv: M.activityToNoir(oact), maker_actv_path: hexPath(this.activity.path(o.account)) });
        await book.set(index, 0n, 0n, 0n);
        this.orders[m].delete(index);
        await this.emitDisplay(m, o, 0n);
        const nact = M.copyActivity(oact);
        if (!o.reduceOnly) {
          if (o.side === M.SIDE.BID) nact.openBid[m] -= o.lots;
          else nact.openAsk[m] -= o.lots;
        }
        nact.openOrders -= 1n;
        this.actv.set(o.account, nact);
        await this.writeActivity(o.account, nact);
        fills.push(fillWitness);
        continue;
      }
      const maker = this.accts.get(o.account)!;
      const mact = this.actv.get(o.account)!;
      if (!this.lite) Object.assign(fillWitness, {
        maker_pub: M.pubToNoir(maker.pub),
        maker_priv: M.privToNoir(maker.priv),
        maker_acct_path: hexPath(this.accounts.path(o.account)),
        maker_k_enc: hex(maker.kEnc),
        maker_actv: M.activityToNoir(mact),
        maker_actv_path: hexPath(this.activity.path(o.account)),
      });
      fills.push(fillWitness);
      // A reduce-only order fills at most its owner's position on its other side and keeps at
      // most that; with nothing to reduce it is trimmed away (matching.nr, P2.21).
      const held = X.heldFor(o.side, maker.priv.positions[m].size);
      if (o.reduceOnly && held === 0n) {
        await book.set(index, 0n, 0n, 0n);
        this.orders[m].delete(index);
        await this.emitDisplay(m, o, 0n);
        const nact = { ...M.copyActivity(mact), openOrders: mact.openOrders - 1n };
        this.actv.set(o.account, nact);
        await this.writeActivity(o.account, nact);
        continue;
      }
      const avail = o.reduceOnly && held < o.lots ? held : o.lots;
      const q = remaining < avail ? remaining : avail;
      const left = avail - q;
      await book.set(index, await X.orderLeaf(this.h, o.side, o.account, left, o.expiry, o.epoch, o.display, o.reduceOnly), X.askLots({ side: o.side, lots: left }), X.bidLots({ side: o.side, lots: left }));
      if (left === 0n) this.orders[m].delete(index);
      else this.orders[m].set(index, { ...o, lots: left });
      await this.emitDisplay(m, o, left);

      // Maker: funding, fill, fee, leaf, open lots.
      const cum = this.markets[m].cumFunding;
      const mpriv = M.copyPriv(maker.priv);
      const [mc, mpos, mdust] = X.settleFunding(mpriv.collateral, mpriv.positions[m], cum);
      this.insuranceMicro += mdust;
      const dm = o.side === M.SIDE.BID ? q : -q;
      const [ms, me, mpnl] = X.fill(mpos.size, mpos.entry, dm, o.price);
      const mfee = X.tierFee(q, o.price, makerFeePpm, this.params.feeTiers[Number(mact.feeTier)].makerPpm);
      this.shiftOi(m, mpos.size, ms);
      mpriv.positions[m] = { size: ms, entry: me, funding: mpos.funding };
      mpriv.collateral = mc + mpnl - mfee;
      if (X.abs(mpriv.collateral) >= X.MAX_COLLATERAL) throw new Error('collateral out of range');
      this.feesPending += mfee;
      const mleaf = await this.writeAccount(maker, mpriv, daNonce);
      await this.emitChange(maker, mleaf, daNonce);
      const nact = M.copyActivity(mact);
      if (!o.reduceOnly) {
        if (o.side === M.SIDE.BID) nact.openBid[m] -= q;
        else nact.openAsk[m] -= q;
      }
      if (left === 0n) nact.openOrders -= 1n;
      this.actv.set(maker.index, nact);
      await this.writeActivity(maker.index, nact);

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
      const tfee = X.tierFee(q, o.price, takerFeePpm, this.params.feeTiers[Number(t.act.feeTier)].takerPpm);
      this.shiftOi(m, tpos.size, ts);
      t.priv.positions[m] = { size: ts, entry: te, funding: tpos.funding };
      t.priv.collateral = t.priv.collateral + tpnl - tfee;
      if (X.abs(t.priv.collateral) >= X.MAX_COLLATERAL) throw new Error('collateral out of range');
      this.feesPending += tfee;
      notional += q * o.price;
      remaining -= q;
      this.markets[m] = M.recordPrint(this.markets[m], this.running.batch, o.price, q);
      this.onFill?.({ market: m, side, price: o.price, lots: q, maker: o.account, taker: t.index, makerLeft: left });
    }
    if (this.markets[m].oiLong !== this.markets[m].oiShort) throw new Error('open interest out of balance');
    return { fills, remaining, notional };
  }

  /** CancelOrder, or ModifyOrder, which reduces the order in place and keeps its queue position. */
  private async execCancel(a: SignedAction, act: M.Activity) {
    const [mk, side, price, seq, newLots] = a.p;
    const modify = a.kind === X.KIND_ACT.MODIFY;
    const m = Number(mk);
    if (mk < 0n || m >= M.MARKETS) throw new Error('market');
    const index = X.orderIndex(side, price, seq);
    const o = this.orders[m].get(index);
    if (!o || o.account !== a.account || o.epoch !== act.epoch) throw new Error('no such order');
    const lots = modify ? newLots : 0n;
    if (modify && !(lots > 0n && lots < o.lots)) throw new Error('a modification only reduces an order');
    const acctPath = hexPath(this.accounts.path(a.account));
    const restPath = siblingsToNoir(this.books[m].path(index));
    if (modify) {
      await this.books[m].set(index, await X.orderLeaf(this.h, side, a.account, lots, o.expiry, o.epoch, o.display, o.reduceOnly), X.askLots({ side, lots }), X.bidLots({ side, lots }));
      this.orders[m].set(index, { ...o, lots });
    } else {
      await this.books[m].set(index, 0n, 0n, 0n);
      this.orders[m].delete(index);
    }
    await this.emitDisplay(m, o, lots);
    this.markets[m].bookRoot = this.books[m].root;
    const nact: M.Activity = { ...M.copyActivity(act), openOrders: modify ? act.openOrders : act.openOrders - 1n };
    if (!o.reduceOnly) {
      if (side === M.SIDE.BID) nact.openBid[m] -= o.lots - lots;
      else nact.openAsk[m] -= o.lots - lots;
    }
    const actvPath = hexPath(this.activity.path(a.account));
    this.actv.set(a.account, nact);
    await this.writeActivity(a.account, nact);
    return { taker_acct_path: acctPath, taker_actv_path: actvPath, rest_path: restPath, cancel_lots: o.lots.toString(), cancel_expiry: o.expiry.toString(), cancel_display: !!o.display, cancel_reduce_only: !!o.reduceOnly };
  }

  private async execWithdraw(a: Pick<SignedAction, 'account' | 'p'>, rec: AccountRecord, act: M.Activity, daNonce: bigint) {
    const [amount, recipient] = a.p;
    if (amount <= 0n || amount >= X.MAX_COLLATERAL) throw new Error('withdrawal amount out of range');
    const old = M.copyPriv(rec.priv);
    if (old.collateral < amount) throw new Error('collateral below the amount');
    if (!X.exposureFresh(old, act, this.markets, this.params.maxAge, this.running.time)) throw new Error('index too old to move collateral');
    if (!X.covers(X.equity(old, this.markets) - amount, X.initialMargin(old, act, this.markets, this.params))) throw new Error('insufficient margin');
    const acctPath = hexPath(this.accounts.path(a.account));
    const leaf = await this.writeAccount(rec, { ...old, collateral: old.collateral - amount }, daNonce);
    await this.emitChange(rec, leaf, daNonce);
    const salt = await this.h([M.DS.WDSALT, rec.kEnc, this.running.batch, BigInt(this.running.withdrawalsCount)]);
    await this.appendWithdrawal(recipient, amount, salt);
    const nact: M.Activity = M.copyActivity(act);
    const actvPath = hexPath(this.activity.path(a.account));
    this.actv.set(a.account, nact);
    await this.writeActivity(a.account, nact);
    return { taker_acct_path: acctPath, taker_actv_path: actvPath };
  }

  /** The activity after CancelAll (SPEC.md §6.5): a new order epoch, no open orders or lots. */
  private voidOrders(act: M.Activity): M.Activity {
    return { ...M.copyActivity(act), epoch: act.epoch + 1n, openOrders: 0n, openBid: Array(M.MARKETS).fill(0n), openAsk: Array(M.MARKETS).fill(0n) };
  }

  /**
   * SetMasterAuth (seg_trade `set_key`, SPEC.md §7.3): master key only; the account's master
   * authorization becomes p[0] and the account is republished in full. Session keys and orders stay.
   */
  private async execSetMasterAuth(a: SignedAction, rec: AccountRecord, act: M.Activity, daNonce: bigint) {
    if (a.p[0] === 0n) throw new Error('empty master authorization');
    if (a.p.slice(1).some((x) => x !== 0n)) throw new Error('master authorization payload');
    const acctPath = hexPath(this.accounts.path(a.account));
    this.setRec(rec, { pub: { ...rec.pub, masterAuth: a.p[0] } });
    const leaf = await this.writeAccount(rec, rec.priv, daNonce);
    const actvPath = hexPath(this.activity.path(a.account));
    this.actv.set(a.account, act);
    await this.writeActivity(a.account, act);
    await this.emitFull(M.TAG.FULL, rec, leaf, daNonce);
    return { taker_acct_path: acctPath, taker_actv_path: actvPath };
  }

  /** CancelAll (seg_trade `cancel_all`): every order the account placed so far is void at once. */
  private async execCancelAll(a: SignedAction, act: M.Activity) {
    const acctPath = hexPath(this.accounts.path(a.account));
    const nact = this.voidOrders(act);
    const actvPath = hexPath(this.activity.path(a.account));
    this.actv.set(a.account, nact);
    await this.writeActivity(a.account, nact);
    return { taker_acct_path: acctPath, taker_actv_path: actvPath };
  }

  /** Transfer (seg_trade `transfer`): the withdrawal's debit rules, then a credit to another user account. */
  private async execTransfer(a: SignedAction, rec: AccountRecord, act: M.Activity, daNonce: bigint) {
    const [amount, to] = a.p;
    if (amount <= 0n || amount >= X.MAX_COLLATERAL) throw new Error('transfer amount out of range');
    const dest = to < this.numAccounts ? this.accts.get(to) : undefined;
    if (!dest) throw new Error('no such account');
    if (to === a.account) throw new Error('transfer to the same account');
    if (dest.pub.class !== M.CLASS.USER) throw new Error('transfers go to user accounts');
    const old = M.copyPriv(rec.priv);
    if (old.collateral < amount) throw new Error('collateral below the amount');
    if (!X.exposureFresh(old, act, this.markets, this.params.maxAge, this.running.time)) throw new Error('index too old to move collateral');
    if (!X.covers(X.equity(old, this.markets) - amount, X.initialMargin(old, act, this.markets, this.params))) throw new Error('insufficient margin');
    if (dest.priv.collateral + amount >= X.MAX_COLLATERAL) throw new Error('collateral out of range');
    const acctPath = hexPath(this.accounts.path(a.account));
    const leaf = await this.writeAccount(rec, { ...old, collateral: old.collateral - amount }, daNonce);
    await this.emitChange(rec, leaf, daNonce);
    const destPriv = M.privToNoir(dest.priv);
    const destPath = hexPath(this.accounts.path(to));
    const destLeaf = await this.writeAccount(dest, { ...dest.priv, collateral: dest.priv.collateral + amount }, daNonce);
    await this.emitChange(dest, destLeaf, daNonce);
    const nact: M.Activity = M.copyActivity(act);
    const actvPath = hexPath(this.activity.path(a.account));
    this.actv.set(a.account, nact);
    await this.writeActivity(a.account, nact);
    return {
      taker_acct_path: acctPath,
      taker_actv_path: actvPath,
      dest_pub: M.pubToNoir(dest.pub),
      dest_priv: destPriv,
      dest_k_enc: hex(dest.kEnc),
      dest_acct_path: destPath,
    };
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
    const live = (o: X.Order) => !X.expired(o, this.running.time) && o.epoch === this.actv.get(o.account)!.epoch;
    const total = opposite.reduce((t, [, o]) => t + (live(o) ? o.lots : 0n), 0n);
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
    return this.atomic(() => this.liquidateImpl(steps));
  }

  private async liquidateImpl(steps: LiqStep[]) {
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
      // Every order of the account goes at once: its order epoch advances.
      need(X.below(eq, mm), 'account is not liquidatable');
      if (act.openOrders === 0n) throw new Error('no orders to cancel');
      act = this.voidOrders(act);
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
      Object.assign(w, { ins_pub: M.pubToNoir(insRec.pub), ins_priv: M.privToNoir(insRec.priv), ins_path: hexPath(this.accounts.path(M.INSURANCE_INDEX)) });
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
    w.actv_path = hexPath(this.activity.path(idx));
    this.actv.set(idx, act);
    await this.writeActivity(idx, act);
    if (usesInsurance) Object.assign(w, { ins_actv: M.activityToNoir(insAct), ins_actv_path: hexPath(this.activity.path(M.INSURANCE_INDEX)) });
    // The liquidated account's leaf, then the other account's.
    w.acct_path = hexPath(this.accounts.path(idx));
    if (writeA) {
      const leaf = await this.writeAccount(rec, a, daNonce);
      await this.emitChange(rec, leaf, daNonce);
    }
    if (otherRec && other) {
      plan.other = otherRec.index;
      Object.assign(w, { other_index: otherRec.index.toString(), other_pub: M.pubToNoir(otherRec.pub), other_priv: M.privToNoir(otherRec.priv), other_k_enc: hex(otherRec.kEnc), other_path: hexPath(this.accounts.path(otherRec.index)) });
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
    return this.atomic(() => this.liquidateAccountImpl(index, counterparty));
  }

  private async liquidateAccountImpl(index: bigint, counterparty?: (market: number) => bigint | undefined): Promise<LiqStep[]> {
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
          await run({ kind: 'cancel', account: index });
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

/**
 * How a lane-P client authorizes: the secret behind its auth binding (client_auth), a P-256 key
 * and salt (client_p256), or a passkey registered with a relying party (client_webauthn).
 */
export type ClientAuth = bigint | { key: P256Key; salt: bigint } | { passkey: P256Key; salt: bigint; rpId: string; origin: string };

/**
 * A client's proof of a master action (SPEC.md §7.4): the client circuit authorizes the action's
 * message under the master key id. With a prover the client circuit is proved; without one the
 * action carries only the proof's public inputs, which is enough to execute (not prove) a batch.
 */
export async function proveAction(h: M.H, domain: bigint, auth: ClientAuth, kind: bigint, account: bigint, nonce: bigint, p: bigint[], prover?: Prover): Promise<ProvenAction> {
  const payload = [...p, ...Array<bigint>(X.ACTION_PAYLOAD - p.length).fill(0n)];
  const msg = await X.actionMsg(h, domain, kind, account, M.MASTER_KEY, nonce, payload);
  let proof: ClientProof;
  if (prover) {
    const made =
      typeof auth === 'bigint'
        ? await prover.clientProof(auth, msg, account)
        : 'passkey' in auth
          ? await prover.clientProofWebAuthn(auth.passkey, auth.salt, auth.rpId, auth.origin, msg, account)
          : await prover.clientProofP256(auth.key, auth.salt, msg, account);
    proof = { pkg: made.pkg, proof: made.proof, publicInputs: made.publicInputs };
  } else {
    const [pkg, binding] =
      typeof auth === 'bigint'
        ? ['client_auth', await M.authBinding(h, auth)]
        : 'passkey' in auth
          ? ['client_webauthn', await M.webauthnBinding(h, auth.passkey.pk, rpIdHash(auth.rpId), auth.salt)]
          : ['client_p256', await M.p256Binding(h, auth.key.pk, auth.salt)];
    proof = { pkg: pkg as string, proof: [], publicInputs: [msg, account, binding as bigint].map(hex) };
  }
  return { kind, account, nonce, p: payload, proof };
}

/** Oracle side: the publishers with the given indices sign an index update (SPEC.md §8.4). */
export async function signUpdate(h: M.H, domain: bigint, sks: bigint[], signers: number[], market: bigint, price: bigint, external: bigint, time: bigint): Promise<OracleUpdate> {
  const { sign } = await import('./grumpkin.ts');
  const msg = await M.oracleMessage(h, domain, market, price, external, time);
  const sigs: (Sig | undefined)[] = Array(M.N_ORACLES).fill(undefined);
  for (const j of signers) sigs[j] = await sign(h, sks[j], msg);
  return { market, price, external, time, sigs };
}
