// ECDSA over NIST P-256 for the P-256 client circuit (SPEC.md §7.4): the key signs a 32-byte digest
// directly, as hardware keys do through a digest-signing API (for example the Secure Enclave). The
// action message is already a domain-separated Poseidon2 hash, so the digest is its 32 bytes.
// Nonces follow RFC 6979 with HMAC-SHA256 (SPEC.md §7.1), and signatures are normalized to low s.
import { createHmac, randomBytes } from 'node:crypto';

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const A = P - 3n;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const G = {
  x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};

type Affine = { x: bigint; y: bigint } | null;
type Jacobian = { x: bigint; y: bigint; z: bigint };

const mod = (a: bigint, m: bigint) => ((a % m) + m) % m;
function inv(a: bigint, m: bigint): bigint {
  let [r0, r1, s0, s1] = [mod(a, m), m, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1, s0, s1] = [r1, r0 - q * r1, s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error('not invertible');
  return mod(s0, m);
}

const INF: Jacobian = { x: 0n, y: 1n, z: 0n };
const toJ = (p: Affine): Jacobian => (p ? { x: p.x, y: p.y, z: 1n } : INF);
function toAffine(p: Jacobian): Affine {
  if (p.z === 0n) return null;
  const zi = inv(p.z, P);
  const zi2 = mod(zi * zi, P);
  return { x: mod(p.x * zi2, P), y: mod(p.y * zi2 * zi, P) };
}

function double(p: Jacobian): Jacobian {
  if (p.z === 0n || p.y === 0n) return INF;
  const yy = mod(p.y * p.y, P);
  const s = mod(4n * p.x * yy, P);
  const zz = mod(p.z * p.z, P);
  const m = mod(3n * p.x * p.x + A * zz * zz, P);
  const x = mod(m * m - 2n * s, P);
  return { x, y: mod(m * (s - x) - 8n * yy * yy, P), z: mod(2n * p.y * p.z, P) };
}

function add(p: Jacobian, q: Jacobian): Jacobian {
  if (p.z === 0n) return q;
  if (q.z === 0n) return p;
  const pz2 = mod(p.z * p.z, P);
  const qz2 = mod(q.z * q.z, P);
  const u1 = mod(p.x * qz2, P);
  const u2 = mod(q.x * pz2, P);
  const s1 = mod(p.y * qz2 * q.z, P);
  const s2 = mod(q.y * pz2 * p.z, P);
  if (u1 === u2) return s1 === s2 ? double(p) : INF;
  const h = mod(u2 - u1, P);
  const r = mod(s2 - s1, P);
  const hh = mod(h * h, P);
  const hhh = mod(h * hh, P);
  const x = mod(r * r - hhh - 2n * u1 * hh, P);
  return { x, y: mod(r * (u1 * hh - x) - s1 * hhh, P), z: mod(h * p.z * q.z, P) };
}

function mul(k: bigint, p: Affine): Affine {
  let acc = INF;
  let base = toJ(p);
  for (let e = mod(k, N); e > 0n; e >>= 1n) {
    if (e & 1n) acc = add(acc, base);
    base = double(base);
  }
  return toAffine(acc);
}

const be32 = (x: bigint) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex');
const int = (b: Uint8Array) => BigInt(`0x${Buffer.from(b).toString('hex') || '0'}`);

export type P256Key = { sk: bigint; pk: { x: bigint; y: bigint } };

export function p256Key(sk: bigint = int(randomBytes(32))): P256Key {
  const d = mod(sk, N - 1n) + 1n;
  const pk = mul(d, G)!;
  return { sk: d, pk };
}

/** RFC 6979 §3.2 nonce for a 32-byte digest, with HMAC-SHA256. */
function rfc6979(sk: bigint, digest: Uint8Array): bigint {
  const hmac = (key: Buffer, ...parts: Buffer[]) => createHmac('sha256', key).update(Buffer.concat(parts)).digest();
  const x = be32(sk);
  const h = be32(mod(int(digest), N));
  let v = Buffer.alloc(32, 1);
  let k = Buffer.alloc(32, 0);
  k = hmac(k, v, Buffer.from([0]), x, h);
  v = hmac(k, v);
  k = hmac(k, v, Buffer.from([1]), x, h);
  v = hmac(k, v);
  for (;;) {
    v = hmac(k, v);
    const t = int(v);
    if (t >= 1n && t < N) return t;
    k = hmac(k, v, Buffer.from([0]));
    v = hmac(k, v);
  }
}

/** Signs a 32-byte digest: r ‖ s, 64 bytes, with s ≤ n/2. */
export function p256Sign(key: P256Key, digest: Uint8Array): Uint8Array {
  if (digest.length !== 32) throw new Error('P-256 digest must be 32 bytes');
  const z = int(digest);
  for (let k = rfc6979(key.sk, digest); ; k = mod(k + 1n, N)) {
    const r = mod(mul(k, G)!.x, N);
    if (r === 0n) continue;
    let s = mod(inv(k, N) * (z + r * key.sk), N);
    if (s === 0n) continue;
    if (s > N / 2n) s = N - s;
    return new Uint8Array(Buffer.concat([be32(r), be32(s)]));
  }
}

export function p256Verify(pk: { x: bigint; y: bigint }, digest: Uint8Array, sig: Uint8Array): boolean {
  const r = int(sig.slice(0, 32));
  const s = int(sig.slice(32));
  if (r <= 0n || r >= N || s <= 0n || s >= N) return false;
  if (mod(pk.y * pk.y - (pk.x * pk.x * pk.x + A * pk.x + B), P) !== 0n) return false;
  const w = inv(s, N);
  const u = add(toJ(mul(mod(int(digest) * w, N), G)), toJ(mul(mod(r * w, N), pk)));
  const q = toAffine(u);
  return !!q && mod(q.x, N) === r;
}

export const bytes32 = (x: bigint) => [...be32(x)];
/** The 16-byte halves of a 32-byte big-endian integer, as the circuit packs a key coordinate. */
export const halves = (x: bigint): [bigint, bigint] => [x >> 128n, x & ((1n << 128n) - 1n)];
