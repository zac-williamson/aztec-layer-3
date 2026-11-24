// Sparse Merkle trees mirroring circuits/l3x_exchange/src/{tree,book}.nr, held and hashed in process
// by l3x-native (native/src/tree.rs). scripts/src/perf/native_check.ts checks them against the
// TypeScript trees they replaced (P2.23).
import type { Barretenberg } from '@aztec-foundation/bb.js';
import { type NativeBookTree, type NativeMerkleTree, native } from '../native.ts';
import { DS, type H } from './model.ts';

/** Binary Merkle tree of fixed height with nodes hash([ds, left, right]) and empty leaves zero. */
export class MerkleTree {
  readonly height: number;
  readonly ds: bigint;
  private readonly t: NativeMerkleTree;

  constructor(_h: H, height: number, ds: bigint) {
    this.height = height;
    this.ds = ds;
    this.t = new native.MerkleTree(height, ds);
  }

  async init(): Promise<this> {
    return this;
  }

  get root(): bigint {
    return this.t.root;
  }

  get(index: bigint): bigint {
    return this.t.get(index);
  }

  path(index: bigint): bigint[] {
    return this.t.path(index);
  }

  snapshot(): NativeMerkleTree {
    return this.t.copy();
  }

  restore(nodes: NativeMerkleTree) {
    this.t.restore(nodes);
  }

  async set(index: bigint, leaf: bigint): Promise<void> {
    this.t.set(index, leaf);
  }
}

export type BookSibling = { hash: bigint; ask: bigint; bid: bigint };

/** The aggregate order-book tree (SPEC.md §6.5). */
export class BookTree {
  readonly height: number;
  private readonly t: NativeBookTree;

  constructor(_api: Barretenberg, height = 80) {
    this.height = height;
    this.t = new native.BookTree(height, DS.BOOK);
  }

  async init(): Promise<this> {
    return this;
  }

  get root(): bigint {
    return this.t.root;
  }

  get totals(): { ask: bigint; bid: bigint } {
    const [ask, bid] = this.t.totals();
    return { ask, bid };
  }

  path(index: bigint): BookSibling[] {
    const f = this.t.path(index);
    const out: BookSibling[] = [];
    for (let i = 0; i < f.length; i += 3) out.push({ hash: f[i], ask: f[i + 1], bid: f[i + 2] });
    return out;
  }

  snapshot(): NativeBookTree {
    return this.t.copy();
  }

  restore(nodes: NativeBookTree) {
    this.t.restore(nodes);
  }

  /** Writes a leaf with its ask and bid lots and updates the path. */
  async set(index: bigint, leaf: bigint, ask: bigint, bid: bigint): Promise<void> {
    this.t.set(index, leaf, ask, bid);
  }

  /** Leaf indices of resting orders, in index order. */
  leaves(): bigint[] {
    return this.t.leaves();
  }
}
