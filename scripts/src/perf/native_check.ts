// Checks l3x-native (native/) against bb.js and the TypeScript implementations it replaced, then
// times it. Usage: node src/perf/native_check.ts
import { Barretenberg } from '@aztec-foundation/bb.js';
import { R, fromBytes32, randomField, toBytes32 } from '../lib.ts';
import { native } from '../native.ts';
import { G, N, SCHNORR_DST, sign, verify } from '../exchange/grumpkin.ts';
import { BookTree, MerkleTree } from '../exchange/tree.ts';
import { DS } from '../exchange/model.ts';

const api = await Barretenberg.new({ threads: 1 });
let checks = 0;
function eq(a: unknown, b: unknown, what: string) {
  const sa = JSON.stringify(a, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
  const sb = JSON.stringify(b, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
  if (sa !== sb) throw new Error(`${what}: native ${sa} != reference ${sb}`);
  checks++;
}
const rand = (bits: number) => randomField() & ((1n << BigInt(bits)) - 1n);

// ---- References: bb.js and the TypeScript code the addon replaced ----
const refPermute = async (s: bigint[]) => (await api.poseidon2Permutation({ inputs: s.map(toBytes32) })).outputs.map(fromBytes32);
async function refHash(inputs: bigint[]) {
  let state = [0n, 0n, 0n, (BigInt(inputs.length) << 64n) % R];
  let pos = 0;
  for (const x of inputs) {
    state[pos] = (((state[pos] + x) % R) + R) % R;
    if (++pos === 3) [state, pos] = [await refPermute(state), 0];
  }
  if (pos !== 0) state = await refPermute(state);
  return state[0];
}

class RefTree {
  empty: bigint[] = [0n];
  nodes = new Map<string, bigint>();
  readonly height: number;
  readonly ds: bigint;
  constructor(height: number, ds: bigint) {
    this.height = height;
    this.ds = ds;
  }
  async init() {
    for (let i = 0; i < this.height; i++) this.empty.push(await refHash([this.ds, this.empty[i], this.empty[i]]));
    return this;
  }
  node = (l: number, i: bigint) => this.nodes.get(`${l}:${i}`) ?? this.empty[l];
  get root() {
    return this.node(this.height, 0n);
  }
  path(index: bigint) {
    return [...Array(this.height).keys()].map((l) => this.node(l, (index >> BigInt(l)) ^ 1n));
  }
  async set(index: bigint, leaf: bigint) {
    this.nodes.set(`0:${index}`, leaf);
    let [idx, cur] = [index, leaf];
    for (let l = 0; l < this.height; l++) {
      const sib = this.node(l, idx ^ 1n);
      cur = idx & 1n ? await refHash([this.ds, sib, cur]) : await refHash([this.ds, cur, sib]);
      idx >>= 1n;
      this.nodes.set(`${l + 1}:${idx}`, cur);
    }
  }
}

type BN = { hash: bigint; ask: bigint; bid: bigint };
class RefBook {
  empty: bigint[] = [0n];
  nodes = new Map<string, BN>();
  readonly height: number;
  constructor(height: number) {
    this.height = height;
  }
  nodeHash = async (l: bigint, r: bigint, a: bigint, b: bigint) => (await refPermute([l, r, (a + (b << 64n)) % R, DS.BOOK]))[0];
  async init() {
    for (let i = 0; i < this.height; i++) this.empty.push(await this.nodeHash(this.empty[i], this.empty[i], 0n, 0n));
    return this;
  }
  node = (l: number, i: bigint): BN => this.nodes.get(`${l}:${i}`) ?? { hash: this.empty[l], ask: 0n, bid: 0n };
  get root() {
    return this.node(this.height, 0n).hash;
  }
  path(index: bigint) {
    return [...Array(this.height).keys()].map((l) => this.node(l, (index >> BigInt(l)) ^ 1n));
  }
  async set(index: bigint, leaf: bigint, ask: bigint, bid: bigint) {
    let cur: BN = { hash: leaf, ask, bid };
    if (leaf === 0n) this.nodes.delete(`0:${index}`);
    else this.nodes.set(`0:${index}`, cur);
    let idx = index;
    for (let l = 0; l < this.height; l++) {
      const sib = this.node(l, idx ^ 1n);
      const [a, b] = idx & 1n ? [sib, cur] : [cur, sib];
      cur = { hash: await this.nodeHash(a.hash, b.hash, a.ask + b.ask, a.bid + b.bid), ask: a.ask + b.ask, bid: a.bid + b.bid };
      idx >>= 1n;
      this.nodes.set(`${l + 1}:${idx}`, cur);
    }
  }
  leaves() {
    return [...this.nodes.keys()].filter((k) => k.startsWith('0:')).map((k) => BigInt(k.slice(2))).sort((a, b) => (a < b ? -1 : 1));
  }
}

// Affine Grumpkin, as grumpkin.ts computed it.
type P = { x: bigint; y: bigint } | null;
const md = (a: bigint, m = R) => ((a % m) + m) % m;
function inv(a: bigint) {
  let [r0, r1, s0, s1] = [md(a), R, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1, s0, s1] = [r1, r0 - q * r1, s1, s0 - q * s1];
  }
  return md(s0);
}
function refAdd(p: P, q: P): P {
  if (!p) return q;
  if (!q) return p;
  if (p.x === q.x) return md(p.y + q.y) === 0n ? null : refDouble(p);
  const l = md((q.y - p.y) * inv(q.x - p.x));
  const x = md(l * l - p.x - q.x);
  return { x, y: md(l * (p.x - x) - p.y) };
}
function refDouble(p: P): P {
  if (!p || p.y === 0n) return null;
  const l = md(3n * p.x * p.x * inv(2n * p.y));
  const x = md(l * l - 2n * p.x);
  return { x, y: md(l * (p.x - x) - p.y) };
}
function refMul(p: P, k: bigint): P {
  let [acc, base, n] = [null as P, p, md(k, N)];
  for (; n > 0n; n >>= 1n, base = refDouble(base)) if (n & 1n) acc = refAdd(acc, base);
  return acc;
}
const pt = (r: bigint[]): P => (r.length ? { x: r[0], y: r[1] } : null);

// ---- Parity ----
const edge = [0n, 1n, R - 1n, R, R + 5n, -1n, -R - 3n, (1n << 256n) - 1n, 1n << 300n];
for (let i = 0; i < 1000; i++) {
  const s = [0, 1, 2, 3].map(() => (i < 36 ? edge[(i + 7 * Math.floor(i / 9)) % edge.length] : randomField()));
  eq(native.permute(s), await refPermute(s), `permute ${s}`);
}
for (let n = 0; n <= 12; n++) {
  for (let i = 0; i < 20; i++) {
    const xs = [...Array(n)].map(() => (i % 5 === 0 ? edge[(i + n) % edge.length] : randomField()));
    eq(native.hash(xs), await refHash(xs), `hash of ${n}`);
  }
}
console.log(`poseidon2 and the L3X hash agree with bb.js (${checks} checks)`);

for (const [height, ds, bits] of [
  [32, DS.ACCT_NODE, 32],
  [8, DS.KEY_NODE, 8],
] as const) {
  const t = await new MerkleTree(null as any, height, ds).init();
  const r = await new RefTree(height, ds).init();
  eq(t.root, r.root, `empty root ${height}`);
  const used: bigint[] = [];
  for (let i = 0; i < 120; i++) {
    const index = i % 4 === 3 && used.length ? used[i % used.length] : i % 17 === 0 ? (1n << BigInt(bits)) - 1n : rand(bits);
    used.push(index);
    const leaf = i % 9 === 0 ? 0n : randomField();
    await t.set(index, leaf);
    await r.set(index, leaf);
    eq(t.root, r.root, `root ${height}`);
    eq(t.path(index), r.path(index), `path ${height}`);
    eq(t.get(index), leaf, `get ${height}`);
  }
  const snap = t.snapshot();
  await t.set(5n, 99n);
  t.restore(snap);
  eq(t.root, r.root, 'restore');
}
console.log(`the Merkle trees agree with tree.ts's (${checks} checks)`);

const b = await new BookTree(null as any, 80).init();
const rb = await new RefBook(80).init();
eq(b.root, rb.root, 'empty book');
const live: bigint[] = [];
for (let i = 0; i < 150; i++) {
  const remove = i % 5 === 4 && live.length > 0;
  const index = remove ? live.splice(i % live.length, 1)[0] : (rand(24) << 48n) + rand(48);
  if (!remove) live.push(index);
  const leaf = remove ? 0n : randomField();
  const [ask, bid] = remove ? [0n, 0n] : i % 2 ? [rand(40), 0n] : [0n, rand(40)];
  await b.set(index, leaf, ask, bid);
  await rb.set(index, leaf, ask, bid);
  eq(b.root, rb.root, 'book root');
  eq(b.path(index), rb.path(index), 'book path');
  const r = rb.node(80, 0n);
  eq(b.totals, { ask: r.ask, bid: r.bid }, 'book totals');
}
eq(b.leaves(), rb.leaves(), 'book leaves');
console.log(`the order-book tree agrees with tree.ts's (${checks} checks)`);

for (let i = 0; i < 12; i++) {
  const k = i === 0 ? 0n : i === 1 ? N - 1n : i === 2 ? N + 7n : randomField();
  eq(pt(native.grumpkinBaseMul(k)), refMul(G, k), 'base mul');
  const p = refMul(G, randomField());
  eq(pt(native.grumpkinMul(p!.x, p!.y, k)), refMul(p, k), 'mul');
  if (md(k, N) === 0n) continue;
  const bb = await api.grumpkinMul({ point: { x: toBytes32(p!.x), y: toBytes32(p!.y) }, scalar: toBytes32(md(k, N) % R) });
  if (md(k, N) < R) eq(pt(native.grumpkinMul(p!.x, p!.y, k)) ?? { x: 0n, y: 0n }, { x: fromBytes32(bb.point.x), y: fromBytes32(bb.point.y) }, 'bb.js mul');
}
eq(native.grumpkinMul(1n, 2n, 5n), [], 'a point off the curve');
console.log(`Grumpkin agrees with the affine reference and bb.js (${checks} checks)`);

for (let i = 0; i < 12; i++) {
  const sk = md(randomField(), N);
  const pk = refMul(G, sk)!;
  const msg = randomField();
  const sig = await sign(null as any, sk, msg);
  // The reference check of a signature: R = s·G + e·PK and e = H(DST, R.x, PK.x, PK.y, msg).
  const r = refAdd(refMul(G, sig.s), refMul(pk, sig.e))!;
  eq(await refHash([SCHNORR_DST, r.x, pk.x, pk.y, msg]), sig.e, 'signature');
  eq(await verify(null as any, pk, sig, msg), true, 'verify');
  eq(await verify(null as any, pk, { s: sig.s, e: sig.e + 1n }, msg), false, 'verify a wrong e');
  eq(await verify(null as any, pk, sig, msg + 1n), false, 'verify a wrong message');
  eq(await verify(null as any, { x: pk.x, y: R - pk.y }, sig, msg), false, 'verify a wrong key');
}
console.log(`Schnorr agrees with the reference (${checks} checks)`);

// ---- Timing ----
function time(label: string, n: number, fn: (i: number) => unknown) {
  for (let i = 0; i < Math.min(n, 100); i++) fn(i);
  const t0 = performance.now();
  for (let i = 0; i < n; i++) fn(i);
  const us = ((performance.now() - t0) * 1000) / n;
  console.log(`${label.padEnd(44)} ${us.toFixed(2).padStart(9)} µs  (${Math.round(1e6 / us).toLocaleString()}/s)`);
}
const st = [randomField(), randomField(), randomField(), randomField()];
time('poseidon2 permutation', 100000, () => native.permute(st));
time('hash of 5 fields', 100000, () => native.hash([st[0], st[1], st[2], st[3], 7n]));
const bt = await new MerkleTree(null as any, 32, DS.ACCT_NODE).init();
time('accounts tree write (height 32)', 20000, (i) => bt.set(BigInt(i * 7919), st[i & 3]));
const bk = await new BookTree(null as any, 80).init();
time('order-book write (height 80)', 20000, (i) => bk.set((BigInt(1000 + (i % 97)) << 48n) + BigInt(i), st[i & 3], 5n, 0n));
const sk = md(randomField(), N);
time('Grumpkin k·G (fixed base)', 20000, () => native.grumpkinBaseMul(st[1]));
time('Grumpkin k·P', 5000, () => native.grumpkinMul(G!.x, G!.y, st[2]));
const sig = await sign(null as any, sk, st[0]);
const pk = refMul(G, sk)!;
time('Schnorr sign', 5000, (i) => native.schnorrSign(sk, st[0], BigInt(i + 1)));
time('Schnorr verify', 5000, () => native.schnorrVerify(pk.x, pk.y, sig.s, sig.e, st[0]));
console.log(`native check passed: ${checks} checks`);
await api.destroy();
process.exit(0);
