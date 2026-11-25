// Shared helpers for the P0 pipeline: paths, toolchain, field encoding, and the L3X hash.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Barretenberg } from '@aztec-foundation/bb.js';
import { native } from './native.ts';

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
  TREES: 10n,
  ACTION_LOG: 11n,
  VK_NODE: 12n,
  DA_SPONGE: 13n,
  RECEIPT: 14n,
  RECEIPT_NODE: 15n,
  P256: 16n,
  WEBAUTHN: 17n,
} as const;

/** Shape parameters; must match circuits/l3x_types/src/{lib,merge}.nr. */
export const SHAPE = {
  MAX_CLIENT_PROOFS: 10,
  MAX_PRIORITY: 8,
  DA_MAX: 4080,
  X_DA_MAX: 4080,
  CHONK_PROOF_LENGTH: 1221,
  VK_TREE_HEIGHT: 6,
  VK_ROLE_SLOTS: 8,
} as const;

/** VK tree roles (SPEC.md §9.3); leaf index = role * VK_ROLE_SLOTS + slot. */
export const ROLE = { CLIENT: 0, CHONK: 1, TUBE: 2, SEGMENT: 3, MERGE: 4, SEGMENT2: 5 } as const;

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

/**
 * The Poseidon2 permutation, in process (l3x-native). The `api` parameter is unused: hashing went
 * through bb.js before the addon (SPEC.md §14, P2.23).
 */
export async function permute(_api: Barretenberg, state: bigint[]): Promise<bigint[]> {
  return native.permute(state);
}

/** Mirror of circuits/l3x_types/src/hash.nr: Poseidon2 sponge, rate 3, length in capacity. */
export async function l3xHash(_api: Barretenberg, inputs: bigint[]): Promise<bigint> {
  return native.hash(inputs);
}

// Mirrors of the l3x_types helpers.

export const trees = (api: Barretenberg, accountsRoot: bigint, otherRoot: bigint) =>
  l3xHash(api, [DS.TREES, accountsRoot, otherRoot]);

export const stateRoot = (api: Barretenberg, treesRoot: bigint, cursor: bigint, batch: bigint, time: bigint) =>
  l3xHash(api, [DS.STATE, treesRoot, cursor, batch, time]);

export const configHashOf = (api: Barretenberg, vkTreeRoot: bigint, paramsHash: bigint) =>
  l3xHash(api, [DS.CONFIG, vkTreeRoot, paramsHash]);

export const daIv = (): bigint[] => [0n, 0n, 0n, DS.DA_SPONGE];

export async function daAbsorb(api: Barretenberg, da: bigint[], len: number, x: bigint): Promise<[bigint[], number]> {
  const pos = len % 3;
  const s = [...da];
  s[pos] = (s[pos] + x) % R;
  return [pos === 2 ? await permute(api, s) : s, len + 1];
}

export async function daFinalize(api: Barretenberg, da: bigint[], len: number): Promise<bigint> {
  const s = len % 3 !== 0 ? await permute(api, da) : da;
  return l3xHash(api, [DS.DA, s[0], BigInt(len)]);
}

/** DA hash of a whole payload, as the Bridge computes it. */
export async function daHash(api: Barretenberg, payload: bigint[]): Promise<bigint> {
  let s = daIv();
  let n = 0;
  for (const x of payload) [s, n] = await daAbsorb(api, s, n, x);
  return daFinalize(api, s, n);
}

/** Layers of the VK tree: layers[0] are the leaves, the last layer is [root]. */
export async function vkTree(api: Barretenberg, leaves: bigint[]): Promise<bigint[][]> {
  if (leaves.length !== 1 << SHAPE.VK_TREE_HEIGHT) throw new Error(`VK tree needs ${1 << SHAPE.VK_TREE_HEIGHT} leaves`);
  const layers = [leaves];
  while (layers[layers.length - 1].length > 1) {
    const prev = layers[layers.length - 1];
    const next: bigint[] = [];
    for (let i = 0; i < prev.length; i += 2) next.push(await l3xHash(api, [DS.VK_NODE, prev[i], prev[i + 1]]));
    layers.push(next);
  }
  return layers;
}

export function vkPath(layers: bigint[][], index: number): bigint[] {
  const path: bigint[] = [];
  let idx = index;
  for (let level = 0; level < SHAPE.VK_TREE_HEIGHT; level++) {
    path.push(layers[level][idx ^ 1]);
    idx >>= 1;
  }
  return path;
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
