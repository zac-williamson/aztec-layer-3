// State containers for the engine's sequencer mode (P2.24, SPEC.md §5, §11). The sequencer applies
// each signed action atomically: it is either applied in full or refused with nothing changed. The
// engine refuses an action by throwing part way through it, so its containers record how to undo
// every change while a transaction is open, and a refusal rolls them back. Copying the whole state
// for every action, as the witness builder's snapshots do, costs time in proportion to the state.
import type { Order } from './rules.ts';
import type { BookSibling } from './tree.ts';

/** An undo log with savepoints. Entries are recorded only while a transaction is open. */
export class Undo {
  private log: (() => void)[] = [];
  active = false;

  push(f: () => void) {
    this.log.push(f);
  }

  begin() {
    if (this.active) throw new Error('a transaction is already open');
    this.log.length = 0;
    this.active = true;
  }

  /** The log's position, to roll back to. */
  savepoint(): number {
    return this.log.length;
  }

  rollbackTo(mark: number) {
    const was = this.active;
    this.active = false;
    for (let i = this.log.length - 1; i >= mark; i--) this.log[i]();
    this.log.length = mark;
    this.active = was;
  }

  commit() {
    this.log.length = 0;
    this.active = false;
  }

  rollback() {
    this.rollbackTo(0);
    this.active = false;
  }
}

/**
 * A Map whose writes are undone by rollback. Values must be replaced, never changed in place (the
 * engine changes account records only through `setRec`, which journals them itself).
 */
export class JMap<K, V> extends Map<K, V> {
  undo?: Undo;

  constructor(undo?: Undo, entries?: Iterable<readonly [K, V]> | null) {
    super();
    this.undo = undo;
    if (entries) for (const [k, v] of entries) super.set(k, v);
  }

  override set(k: K, v: V): this {
    const u = this.undo;
    if (u?.active) {
      const had = super.has(k);
      const old = super.get(k);
      u.push(() => (had ? this.restoreEntry(k, old as V) : this.removeEntry(k)));
    }
    this.write(k, v);
    return this;
  }

  override delete(k: K): boolean {
    const u = this.undo;
    if (!super.has(k)) return false;
    if (u?.active) {
      const old = super.get(k) as V;
      u.push(() => this.restoreEntry(k, old));
    }
    this.remove(k);
    return true;
  }

  /** Subclasses keep their indexes in step here. */
  protected write(k: K, v: V) {
    super.set(k, v);
  }

  protected remove(k: K) {
    super.delete(k);
  }

  private restoreEntry(k: K, v: V) {
    this.write(k, v);
  }

  private removeEntry(k: K) {
    this.remove(k);
  }
}

/** Index of the position at which x belongs in the ascending array xs. */
function lowerBound(xs: bigint[], x: bigint): number {
  let [lo, hi] = [0, xs.length];
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (xs[mid] < x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** One side's book indices, grouped by price level (index >> 48), each level sorted. */
class Levels {
  /** Ascending prices that hold at least one order. */
  private prices: bigint[] = [];
  private byPrice = new Map<bigint, bigint[]>();

  insert(k: bigint) {
    const p = k >> 48n;
    let lvl = this.byPrice.get(p);
    if (!lvl) {
      this.byPrice.set(p, (lvl = []));
      this.prices.splice(lowerBound(this.prices, p), 0, p);
    }
    // New orders mostly land at an end of their level: asks at the back, bids at the front.
    if (!lvl.length || k > lvl[lvl.length - 1]) lvl.push(k);
    else if (k < lvl[0]) lvl.unshift(k);
    else lvl.splice(lowerBound(lvl, k), 0, k);
  }

  remove(k: bigint) {
    const p = k >> 48n;
    const lvl = this.byPrice.get(p);
    if (!lvl) return;
    const i = lowerBound(lvl, k);
    if (lvl[i] !== k) return;
    lvl.splice(i, 1);
    if (!lvl.length) {
      this.byPrice.delete(p);
      this.prices.splice(lowerBound(this.prices, p), 1);
    }
  }

  min(): bigint | undefined {
    return this.prices.length ? this.byPrice.get(this.prices[0])![0] : undefined;
  }

  max(): bigint | undefined {
    if (!this.prices.length) return undefined;
    const lvl = this.byPrice.get(this.prices[this.prices.length - 1])!;
    return lvl[lvl.length - 1];
  }

  ascending(): bigint[] {
    return this.prices.flatMap((p) => this.byPrice.get(p)!);
  }
}

/**
 * The resting orders of one market by book index, with both sides indexed by price level: the
 * best ask is the lowest index and the best bid the highest (book.nr's index order, SPEC.md §6.5).
 */
export class Orders<V extends Pick<Order, 'side'>> extends JMap<bigint, V> {
  private readonly asks = new Levels();
  private readonly bids = new Levels();

  constructor(undo?: Undo, entries?: Iterable<readonly [bigint, V]> | null) {
    super(undo);
    if (entries) for (const [k, v] of entries) this.write(k, v);
  }

  protected override write(k: bigint, v: V) {
    const had = Map.prototype.get.call(this, k) as V | undefined;
    if (had && had.side !== v.side) this.side(had.side).remove(k);
    if (!had || had.side !== v.side) this.side(v.side).insert(k);
    Map.prototype.set.call(this, k, v);
  }

  protected override remove(k: bigint) {
    const had = Map.prototype.get.call(this, k) as V | undefined;
    if (had) this.side(had.side).remove(k);
    Map.prototype.delete.call(this, k);
  }

  private side(s: bigint) {
    return s === 1n ? this.asks : this.bids;
  }

  /** The best order on `side` (0 bid, 1 ask), or undefined. */
  bestOn(side: bigint): V | undefined {
    const k = side === 1n ? this.asks.min() : this.bids.max();
    return k === undefined ? undefined : (Map.prototype.get.call(this, k) as V);
  }

  /** Book indices on `side`, best first. */
  ranked(side: bigint): bigint[] {
    return side === 1n ? this.asks.ascending() : this.bids.ascending().reverse();
  }

  clone(): Orders<V> {
    return new Orders(this.undo, [...Map.prototype.entries.call(this)].map(([k, v]) => [k, { ...v }] as const));
  }
}

// ---- Trees that hold nothing: the sequencer's engine keeps no Merkle state (lite mode) ----

/** The shared path every null tree returns, and its Noir encodings, computed once. */
const NULL_PATHS = new Map<number, bigint[]>();
const NULL_BOOK_PATHS = new Map<number, BookSibling[]>();
export const isNullPath = (p: unknown) => (Array.isArray(p) && NULL_PATHS.get(p.length) === p) || (Array.isArray(p) && NULL_BOOK_PATHS.get(p.length) === p);

export class NullTree {
  readonly height: number;
  readonly root = 0n;
  private readonly zero: bigint[];
  constructor(height: number) {
    this.height = height;
    if (!NULL_PATHS.has(height)) NULL_PATHS.set(height, Object.freeze(Array<bigint>(height).fill(0n)) as bigint[]);
    this.zero = NULL_PATHS.get(height)!;
  }
  async init() {
    return this;
  }
  get(_index: bigint) {
    return 0n;
  }
  path(_index: bigint): bigint[] {
    return this.zero;
  }
  snapshot() {
    return undefined as any;
  }
  restore(_s: unknown) {}
  async set(_index: bigint, _leaf: bigint) {}
}

export class NullBook {
  readonly height: number;
  readonly root = 0n;
  readonly totals = { ask: 0n, bid: 0n };
  private readonly zero: BookSibling[];
  constructor(height: number) {
    this.height = height;
    if (!NULL_BOOK_PATHS.has(height)) NULL_BOOK_PATHS.set(height, Object.freeze(Array.from({ length: height }, () => Object.freeze({ hash: 0n, ask: 0n, bid: 0n }))) as BookSibling[]);
    this.zero = NULL_BOOK_PATHS.get(height)!;
  }
  async init() {
    return this;
  }
  path(_index: bigint): BookSibling[] {
    return this.zero;
  }
  snapshot() {
    return undefined as any;
  }
  restore(_s: unknown) {}
  async set(_index: bigint, _leaf: bigint, _ask: bigint, _bid: bigint) {}
  leaves(): bigint[] {
    return [];
  }
}
