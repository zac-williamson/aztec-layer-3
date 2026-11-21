// Sparse Merkle trees mirroring circuits/l3x_exchange/src/{tree,book}.nr.
import type { Barretenberg } from '@aztec-foundation/bb.js';
import { type H, bookNode } from './model.ts';

/** Binary Merkle tree of fixed height with nodes hash([ds, left, right]) and empty leaves zero. */
export class MerkleTree {
  readonly height: number;
  readonly ds: bigint;
  private readonly h: H;
  private empty: bigint[] = [];
  private nodes = new Map<string, bigint>();

  constructor(h: H, height: number, ds: bigint) {
    this.h = h;
    this.height = height;
    this.ds = ds;
  }

  async init(): Promise<this> {
    let e = 0n;
    this.empty = [e];
    for (let i = 0; i < this.height; i++) {
      e = await this.h([this.ds, e, e]);
      this.empty.push(e);
    }
    return this;
  }

  private node(level: number, index: bigint): bigint {
    return this.nodes.get(`${level}:${index}`) ?? this.empty[level];
  }

  get root(): bigint {
    return this.node(this.height, 0n);
  }

  get(index: bigint): bigint {
    return this.node(0, index);
  }

  path(index: bigint): bigint[] {
    const out: bigint[] = [];
    let idx = index;
    for (let level = 0; level < this.height; level++) {
      out.push(this.node(level, idx ^ 1n));
      idx >>= 1n;
    }
    return out;
  }

  snapshot(): Map<string, bigint> {
    return new Map(this.nodes);
  }

  restore(nodes: Map<string, bigint>) {
    this.nodes = new Map(nodes);
  }

  async set(index: bigint, leaf: bigint): Promise<void> {
    this.nodes.set(`0:${index}`, leaf);
    let idx = index;
    let cur = leaf;
    for (let level = 0; level < this.height; level++) {
      const sib = this.node(level, idx ^ 1n);
      cur = idx & 1n ? await this.h([this.ds, sib, cur]) : await this.h([this.ds, cur, sib]);
      idx >>= 1n;
      this.nodes.set(`${level + 1}:${idx}`, cur);
    }
  }
}

export type BookSibling = { hash: bigint; ask: bigint; bid: bigint };
type BookNode = { hash: bigint; ask: bigint; bid: bigint };

/** The aggregate order-book tree (SPEC.md §6.5). */
export class BookTree {
  readonly height: number;
  private readonly api: Barretenberg;
  private empty: bigint[] = [];
  private nodes = new Map<string, BookNode>();

  constructor(api: Barretenberg, height = 80) {
    this.api = api;
    this.height = height;
  }

  async init(): Promise<this> {
    let e = 0n;
    this.empty = [e];
    for (let i = 0; i < this.height; i++) {
      e = await bookNode(this.api, e, e, 0n, 0n);
      this.empty.push(e);
    }
    return this;
  }

  private node(level: number, index: bigint): BookNode {
    return this.nodes.get(`${level}:${index}`) ?? { hash: this.empty[level], ask: 0n, bid: 0n };
  }

  get root(): bigint {
    return this.node(this.height, 0n).hash;
  }

  get totals(): { ask: bigint; bid: bigint } {
    const r = this.node(this.height, 0n);
    return { ask: r.ask, bid: r.bid };
  }

  path(index: bigint): BookSibling[] {
    const out: BookSibling[] = [];
    let idx = index;
    for (let level = 0; level < this.height; level++) {
      out.push(this.node(level, idx ^ 1n));
      idx >>= 1n;
    }
    return out;
  }

  snapshot(): Map<string, BookNode> {
    return new Map(this.nodes);
  }

  restore(nodes: Map<string, BookNode>) {
    this.nodes = new Map(nodes);
  }

  /** Writes a leaf with its ask and bid lots and updates the path. */
  async set(index: bigint, leaf: bigint, ask: bigint, bid: bigint): Promise<void> {
    let cur: BookNode = { hash: leaf, ask, bid };
    if (leaf === 0n) this.nodes.delete(`0:${index}`);
    else this.nodes.set(`0:${index}`, cur);
    let idx = index;
    for (let level = 0; level < this.height; level++) {
      const sib = this.node(level, idx ^ 1n);
      const [l, r] = idx & 1n ? [sib, cur] : [cur, sib];
      const a = l.ask + r.ask;
      const b = l.bid + r.bid;
      cur = { hash: await bookNode(this.api, l.hash, r.hash, a, b), ask: a, bid: b };
      idx >>= 1n;
      this.nodes.set(`${level + 1}:${idx}`, cur);
    }
  }

  /** Leaf indices of resting orders, in index order. */
  leaves(): bigint[] {
    return [...this.nodes.keys()]
      .filter((k) => k.startsWith('0:'))
      .map((k) => BigInt(k.slice(2)))
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  }
}
