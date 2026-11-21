// Grumpkin (y^2 = x^3 - 17 over the BN254 scalar field) and Schnorr signatures with a Poseidon2
// challenge, matching noir-lang/schnorr v0.4.0 (SPEC.md §7.1):
//   R = s·G + e·PK,  e = Poseidon2(DST, R.x, PK.x, PK.y, msg).
import { R as P, hex, randomField } from '../lib.ts';
import type { H } from './model.ts';

/** Grumpkin group order (the BN254 base field modulus). */
export const N = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export type Point = { x: bigint; y: bigint } | null;
export const G: Point = { x: 1n, y: 17631683881184975370165255887551781615748388533673675138860n };
export const SCHNORR_DST = 0x024c76938ed06b8ec1d9094b1013d190baa4011372f0604643bda812a63b832en;
const DS_NONCE = 0x6c33782e6e6f6e6365n; // "l3x.nonce"
const DS_SK = 0x6c33782e736bn; // "l3x.sk"
const DS_KENC = 0x6c33782e6b656e63n; // "l3x.kenc"

const mod = (a: bigint, m = P) => ((a % m) + m) % m;

function inv(a: bigint, m = P): bigint {
  let [r0, r1] = [mod(a, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error('not invertible');
  return mod(s0, m);
}

export function add(p: Point, q: Point): Point {
  if (!p) return q;
  if (!q) return p;
  if (p.x === q.x) {
    if (mod(p.y + q.y) === 0n) return null;
    return double(p);
  }
  const l = mod((q.y - p.y) * inv(q.x - p.x));
  const x = mod(l * l - p.x - q.x);
  return { x, y: mod(l * (p.x - x) - p.y) };
}

export function double(p: Point): Point {
  if (!p || p.y === 0n) return null;
  const l = mod(3n * p.x * p.x * inv(2n * p.y));
  const x = mod(l * l - 2n * p.x);
  return { x, y: mod(l * (p.x - x) - p.y) };
}

export function mul(p: Point, k: bigint): Point {
  let acc: Point = null;
  let base = p;
  let n = mod(k, N);
  while (n > 0n) {
    if (n & 1n) acc = add(acc, base);
    base = double(base);
    n >>= 1n;
  }
  return acc;
}

export type Sig = { s: bigint; e: bigint };

export async function sign(h: H, sk: bigint, msg: bigint): Promise<Sig> {
  const pk = mul(G, sk)!;
  for (;;) {
    // Hedged deterministic nonce: key, message and fresh randomness (SPEC.md §7.1).
    const k = mod(await h([DS_NONCE, sk, msg, randomField()]), N);
    const r = mul(G, k);
    if (!r || k === 0n) continue;
    const e = await h([SCHNORR_DST, r.x, pk.x, pk.y, msg]);
    const s = mod(k - e * sk, N);
    if (s !== 0n && e !== 0n) return { s, e };
  }
}

export async function verify(h: H, pk: Point, sig: Sig, msg: bigint): Promise<boolean> {
  const r = add(mul(G, sig.s), mul(pk, sig.e));
  if (!r || !pk) return false;
  return (await h([SCHNORR_DST, r.x, pk.x, pk.y, msg])) === sig.e;
}

const MASK_128 = (1n << 128n) - 1n;
export const scalarToNoir = (x: bigint) => ({ lo: hex(x & MASK_128), hi: hex(x >> 128n) });
export const sigToNoir = (s: Sig) => ({ s: scalarToNoir(s.s), e: scalarToNoir(s.e) });
export const zeroSig = () => ({ s: scalarToNoir(0n), e: scalarToNoir(0n) });

/** A user's keys, derived from one seed so a wallet can always recover them (SPEC.md §6.3). */
export async function keysFromSeed(h: H, seed: bigint) {
  let sk = mod(await h([DS_SK, seed]), N);
  if (sk === 0n) sk = 1n;
  const pk = mul(G, sk)!;
  const kEnc = await h([DS_KENC, seed]);
  return { sk, pk, kEnc };
}
