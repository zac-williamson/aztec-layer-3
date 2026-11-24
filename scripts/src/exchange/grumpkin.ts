// Grumpkin (y^2 = x^3 - 17 over the BN254 scalar field) and Schnorr signatures with a Poseidon2
// challenge, matching noir-lang/schnorr v0.4.0 (SPEC.md §7.1):
//   R = s·G + e·PK,  e = Poseidon2(DST, R.x, PK.x, PK.y, msg).
// The curve arithmetic runs in l3x-native (native/src/grumpkin.rs, P2.23); before it, affine
// bigint arithmetic here took about 26 ms a scalar multiplication.
import { R as P, hex, randomField } from '../lib.ts';
import { native } from '../native.ts';
import type { H } from './model.ts';

/** Grumpkin group order (the BN254 base field modulus). */
export const N = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export type Point = { x: bigint; y: bigint } | null;
export const G: Point = { x: 1n, y: 17631683881184975370165255887551781615748388533673675138860n };
export const SCHNORR_DST = 0x024c76938ed06b8ec1d9094b1013d190baa4011372f0604643bda812a63b832en;
const DS_SK = 0x6c33782e736bn; // "l3x.sk"
const DS_KENC = 0x6c33782e6b656e63n; // "l3x.kenc"
// The signing nonce's domain separator, "l3x.nonce", lives in native/src/grumpkin.rs.

const mod = (a: bigint, m = P) => ((a % m) + m) % m;
const point = (r: bigint[]): Point => (r.length ? { x: r[0], y: r[1] } : null);

/** k·p; null for the point at infinity (and for a p off the curve). */
export function mul(p: Point, k: bigint): Point {
  if (!p) return null;
  if (p.x === G!.x && p.y === G!.y) return point(native.grumpkinBaseMul(mod(k, N)));
  return point(native.grumpkinMul(p.x, p.y, mod(k, N)));
}

export type Sig = { s: bigint; e: bigint };

/** A hedged deterministic nonce from the key, the message and fresh randomness (SPEC.md §7.1). */
export async function sign(_h: H, sk: bigint, msg: bigint): Promise<Sig> {
  for (;;) {
    const r = native.schnorrSign(mod(sk, N), msg, randomField());
    if (r.length) return { s: r[0], e: r[1] };
  }
}

export async function verify(_h: H, pk: Point, sig: Sig, msg: bigint): Promise<boolean> {
  return !!pk && native.schnorrVerify(pk.x, pk.y, sig.s, sig.e, msg);
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
