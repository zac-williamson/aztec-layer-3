// The l3x-native addon (native/, SPEC.md §14): Poseidon2, the state trees, Grumpkin and Schnorr in
// process. bb.js computes the same values through a bb process, about 36–117 µs a permutation on
// mainframe; the addon takes a few. Build it with `npm run build:native`.
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface NativeMerkleTree {
  readonly height: number;
  readonly root: bigint;
  get(index: bigint): bigint;
  path(index: bigint): bigint[];
  set(index: bigint, leaf: bigint): void;
  copy(): NativeMerkleTree;
  restore(from: NativeMerkleTree): void;
}

export interface NativeBookTree {
  readonly height: number;
  readonly root: bigint;
  /** [ask lots, bid lots] in the whole book. */
  totals(): bigint[];
  /** Siblings from the leaf up, flattened as (hash, ask, bid) triples. */
  path(index: bigint): bigint[];
  set(index: bigint, leaf: bigint, ask: bigint, bid: bigint): void;
  leaves(): bigint[];
  copy(): NativeBookTree;
  restore(from: NativeBookTree): void;
}

export interface NativeApi {
  permute(state: bigint[]): bigint[];
  hash(inputs: bigint[]): bigint;
  MerkleTree: new (height: number, ds: bigint) => NativeMerkleTree;
  BookTree: new (height: number, ds: bigint) => NativeBookTree;
  /** k·P as [x, y], or [] for the point at infinity or a P off the curve. */
  grumpkinMul(x: bigint, y: bigint, k: bigint): bigint[];
  /** k·G from a fixed-base table. */
  grumpkinBaseMul(k: bigint): bigint[];
  schnorrVerify(pkX: bigint, pkY: bigint, s: bigint, e: bigint, msg: bigint): boolean;
  /** One signing attempt with the given randomness: [s, e], or [] to retry with fresh randomness. */
  schnorrSign(sk: bigint, msg: bigint, rand: bigint): bigint[];
  /** The crypto thread pool's size; the first call that passes `threads` (before any batch) sets it. */
  cryptoThreads(threads?: number): number;
  /**
   * The gateway's checks of signed actions on the crypto pool (P2.24): `flat` holds 16 fields an
   * action (kind, account, key id, nonce, payload ×8, pk_x, pk_y, s, e); the result holds
   * (msg, master_auth, ok) triples.
   */
  prepareActions(dsAction: bigint, dsMauth: bigint, domain: bigint, flat: bigint[]): Promise<bigint[]>;
  /** Receipt signatures (SPEC.md §11) for (msg, seq, issued_at) triples, as (s, e) pairs. */
  signReceipts(dsReceiptSig: bigint, domain: bigint, sk: bigint, seed: bigint, flat: bigint[]): Promise<bigint[]>;
}

export const NATIVE_PATH = join(resolve(dirname(fileURLToPath(import.meta.url)), '../..'), 'native', 'l3x_native.node');

function load(): NativeApi {
  if (!existsSync(NATIVE_PATH)) throw new Error(`l3x-native is not built (${NATIVE_PATH}): run \`npm run build:native\` in scripts/`);
  return createRequire(import.meta.url)(NATIVE_PATH);
}

export const native: NativeApi = load();
