// Shared helpers for the P0 pipeline: paths, toolchain, field encoding, and the L3X hash.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Barretenberg } from '@aztec-foundation/bb.js';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export const CIRCUITS = join(ROOT, 'circuits');
export const TARGET = join(CIRCUITS, 'target');
export const VK_DIR = join(TARGET, 'vk');
export const OUT = join(ROOT, 'scripts', 'out');
export const AZTEC_VERSION = readFileSync(join(ROOT, '.aztecrc'), 'utf8').trim();
const BIN = join(homedir(), '.aztec', 'versions', AZTEC_VERSION, 'bin');
export const NARGO = join(BIN, 'aztec-nargo');
export const BB = join(BIN, 'aztec-bb');

/** BN254 scalar field modulus. */
export const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Domain separators; must match circuits/l3x_types/src/lib.nr. */
export const DS = {
  AUTH: 1n,
  AGG: 2n,
  PRIORITY: 3n,
  PRIORITY_ENTRY: 4n,
  ACCOUNTS: 5n,
  STATE: 6n,
  HEADER: 7n,
  DA: 8n,
  CONFIG: 9n,
} as const;

/** P0 shape parameters; must match circuits/l3x_types/src/lib.nr. */
export const SHAPE = {
  MAX_CLIENT_PROOFS: 10,
  MAX_PRIORITY: 8,
  DA_LEN: 64,
  CHONK_PROOF_LENGTH: 1221,
} as const;

export function run(cmd: string, args: string[], cwd = CIRCUITS): string {
  return execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 28 });
}

export function toBytes32(x: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = ((x % R) + R) % R;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function fromBytes32(b: Uint8Array): bigint {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  return v;
}

export function hex(x: bigint): string {
  return '0x' + x.toString(16).padStart(64, '0');
}

/** Split a byte string of concatenated 32-byte big-endian field elements. */
export function bytesToFields(bytes: Uint8Array): bigint[] {
  if (bytes.length % 32 !== 0) throw new Error(`byte length ${bytes.length} is not a multiple of 32`);
  const out: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 32) out.push(fromBytes32(bytes.subarray(i, i + 32)));
  return out;
}

export function randomField(): bigint {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return fromBytes32(b) % R;
}

async function permute(api: Barretenberg, state: bigint[]): Promise<bigint[]> {
  const { outputs } = await api.poseidon2Permutation({ inputs: state.map(toBytes32) });
  return outputs.map(fromBytes32);
}

/** Mirror of circuits/l3x_types/src/hash.nr: Poseidon2 sponge, rate 3, length in capacity. */
export async function l3xHash(api: Barretenberg, inputs: bigint[]): Promise<bigint> {
  let state = [0n, 0n, 0n, (BigInt(inputs.length) * (1n << 64n)) % R];
  let pos = 0;
  for (const x of inputs) {
    state[pos] = (state[pos] + x) % R;
    pos += 1;
    if (pos === 3) {
      state = await permute(api, state);
      pos = 0;
    }
  }
  if (pos !== 0) state = await permute(api, state);
  return state[0];
}

export type VkJson = { vk: string[]; hash: string; bb_version: string; scheme: string };

export function readVkJson(pkg: string): VkJson {
  return JSON.parse(readFileSync(join(VK_DIR, pkg, 'vk.json'), 'utf8'));
}

export function readVkBinary(pkg: string): Uint8Array {
  return new Uint8Array(readFileSync(join(VK_DIR, pkg, 'vk')));
}

export type CompiledCircuit = { bytecode: string; abi: any; noir_version?: string };

export function readCircuit(pkg: string): CompiledCircuit {
  return JSON.parse(readFileSync(join(TARGET, `${pkg}.json`), 'utf8'));
}

export function writeJson(path: string, value: unknown) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? hex(v) : v), 2) + '\n');
}

export function readJson<T = any>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8'));
}

export async function timed<T>(fn: () => Promise<T>): Promise<[T, number]> {
  const t0 = performance.now();
  const value = await fn();
  return [value, performance.now() - t0];
}
