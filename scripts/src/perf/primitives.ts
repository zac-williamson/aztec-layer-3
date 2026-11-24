// Cost of the operator's cryptographic primitives through each bb.js backend (SPEC.md §14):
// Poseidon2 permutations and Grumpkin scalar multiplications, per call, single-threaded.
// Usage: node src/perf/primitives.ts
import { Barretenberg, BarretenbergSync, BackendType } from '@aztec-foundation/bb.js';
import { fromBytes32, randomField, toBytes32 } from '../lib.ts';
import { G } from '../exchange/grumpkin.ts';
import { native } from '../native.ts';

const fmt = (us: number) => (us < 1000 ? `${us.toFixed(2)} µs` : `${(us / 1000).toFixed(2)} ms`);

async function time(label: string, n: number, fn: (i: number) => unknown | Promise<unknown>) {
  for (let i = 0; i < Math.min(n, 50); i++) await fn(i); // warm up
  const t0 = performance.now();
  for (let i = 0; i < n; i++) await fn(i);
  const us = ((performance.now() - t0) * 1000) / n;
  console.log(`${label.padEnd(52)} ${fmt(us).padStart(10)}  (${Math.round(1e6 / us).toLocaleString()}/s)`);
  return us;
}

const state = [randomField(), randomField(), randomField(), randomField()].map(toBytes32);
const point = { x: toBytes32(G!.x), y: toBytes32(G!.y) };
const scalar = toBytes32(randomField() >> 8n);

const asyncApi = await Barretenberg.new({ threads: 1 });
await time('poseidon2 permutation, async (native socket)', 5000, () => asyncApi.poseidon2Permutation({ inputs: state }));
await time('grumpkin mul, async (native socket)', 500, () => asyncApi.grumpkinMul({ point, scalar }));
await asyncApi.destroy();

const shm = await BarretenbergSync.new();
await time('poseidon2 permutation, sync (native shared memory)', 20000, () => shm.poseidon2Permutation({ inputs: state }));
await time('grumpkin mul, sync (native shared memory)', 2000, () => shm.grumpkinMul({ point, scalar }));

const wasm = await BarretenbergSync.new({ backend: BackendType.Wasm } as any);
await time('poseidon2 permutation, sync (wasm)', 20000, () => wasm.poseidon2Permutation({ inputs: state }));
await time('grumpkin mul, sync (wasm)', 500, () => wasm.grumpkinMul({ point, scalar }));

await time('grumpkin mul, in process (l3x-native)', 5000, () => native.grumpkinMul(G!.x, G!.y, fromBytes32(scalar)));
const st = state.map(fromBytes32);
await time('poseidon2 permutation, in process (l3x-native)', 100000, () => native.permute(st));
const xs = state.map(fromBytes32);
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
await time('bigint 254-bit mulmod', 200000, (i) => (xs[i & 3] * xs[(i + 1) & 3]) % P);
process.exit(0);
