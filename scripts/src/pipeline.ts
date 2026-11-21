// The batch prover (SPEC.md §9.2). Segments become merge-tree leaves: a P-segment through client
// proofs, the Chonk IVC and the tube; an X-segment directly. Adjacent nodes are merged until two
// remain, and the root verifies those two and binds the batch header. Returns what Bridge.settle
// needs, plus timings.
import { cpus } from 'node:os';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { AztecClientBackend, type Barretenberg, UltraHonkBackend } from '@aztec-foundation/bb.js';
import { Noir } from '@aztec-foundation/noir-noir_js';
import {
  BB,
  DS,
  SHAPE,
  TARGET,
  bytesToFields,
  daAbsorb,
  daFinalize,
  daHash,
  daIv,
  fromBytes32,
  hex,
  l3xHash,
  randomField,
  readCircuit,
  readVkBinary,
  readVkJson,
  run,
  stateRoot,
  timed,
  trees,
  vkPath,
  vkTree,
} from './lib.ts';

const CircuitKind = { App: 0, Kernel: 1, HidingKernel: 2 } as const;
const IVC = ['agg_app', 'init_kernel', 'tail_kernel', 'hiding_kernel'] as const;
const ROLLUP = { verifierTarget: 'noir-rollup-no-zk' } as const;
const RECURSIVE = { verifierTarget: 'noir-recursive' } as const;

export function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(`check failed: ${msg}`);
}

/** Mirror of l3x_types::Running. */
export type Running = {
  state: bigint;
  actionLog: bigint;
  priorityHead: bigint;
  priorityCursor: bigint;
  da: bigint[];
  daLen: number;
  withdrawals: bigint;
  withdrawalsCount: number;
  time: bigint;
};

/** Mirror of l3x_types::NodeOutput, the public output of every merge-tree node. */
export type NodeOutput = { configHash: bigint; start: Running; end: Running };

export type ProvedNode = { pkg: string; proof: bigint[]; out: NodeOutput; ms: number };

export function runningFields(r: Running): bigint[] {
  return [
    r.state,
    r.actionLog,
    r.priorityHead,
    r.priorityCursor,
    ...r.da,
    BigInt(r.daLen),
    r.withdrawals,
    BigInt(r.withdrawalsCount),
    r.time,
  ];
}

export function nodeFields(n: NodeOutput): bigint[] {
  return [n.configHash, ...runningFields(n.start), ...runningFields(n.end)];
}

export const runningToNoir = (r: Running) => ({
  state: hex(r.state),
  action_log: hex(r.actionLog),
  priority_head: hex(r.priorityHead),
  priority_cursor: r.priorityCursor.toString(),
  da: r.da.map(hex),
  da_len: r.daLen,
  withdrawals: hex(r.withdrawals),
  withdrawals_count: r.withdrawalsCount,
  time: r.time.toString(),
});

export const nodeToNoir = (n: NodeOutput) => ({
  config_hash: hex(n.configHash),
  start: runningToNoir(n.start),
  end: runningToNoir(n.end),
});

const runningFromNoir = (o: any): Running => ({
  state: BigInt(o.state),
  actionLog: BigInt(o.action_log),
  priorityHead: BigInt(o.priority_head),
  priorityCursor: BigInt(o.priority_cursor),
  da: o.da.map((x: string) => BigInt(x)),
  daLen: Number(BigInt(o.da_len)),
  withdrawals: BigInt(o.withdrawals),
  withdrawalsCount: Number(BigInt(o.withdrawals_count)),
  time: BigInt(o.time),
});

const nodeFromNoir = (o: any): NodeOutput => ({
  configHash: BigInt(o.config_hash),
  start: runningFromNoir(o.start),
  end: runningFromNoir(o.end),
});

/** Running values at the start of a batch: the chain tip, with per-batch accumulators empty. */
export function batchStart(state: bigint, priorityHead: bigint, priorityCursor: bigint, time: bigint): Running {
  return { state, actionLog: 0n, priorityHead, priorityCursor, da: daIv(), daLen: 0, withdrawals: 0n, withdrawalsCount: 0, time };
}

const padTo = (xs: bigint[], n: number) => [...xs, ...Array<bigint>(n - xs.length).fill(0n)].map(hex);

export function ultraGates(pkg: string, target: string): number {
  const out = run(BB, ['gates', '-b', join(TARGET, `${pkg}.json`), '-t', target]);
  const m = out.match(/"circuit_size"\s*:\s*(\d+)/);
  return m ? Number(m[1]) : NaN;
}

export async function newApi(): Promise<Barretenberg> {
  const { Barretenberg } = await import('@aztec-foundation/bb.js');
  return Barretenberg.new({ threads: cpus().length });
}

export type ChonkSegment = {
  aggOut: { actions_hash: string; count: string };
  chonkVk: bigint[];
  chonkProof: bigint[];
  ms: Record<string, number>;
  sizes: Record<string, number>;
};

/** Override any field of a child's inputs (VK, proof, VK hash, membership, output): used by the negative tests. */
export type ChildOverrides = Partial<Record<'vk' | 'proof' | 'vk_hash' | 'membership' | 'out', unknown>>;

export class Prover {
  readonly api: Barretenberg;
  readonly manifest: any;
  private layers: bigint[][] = [];

  private constructor(api: Barretenberg, manifest: any) {
    this.api = api;
    this.manifest = manifest;
  }

  static async create(api: Barretenberg, manifest: any): Promise<Prover> {
    const p = new Prover(api, manifest);
    p.layers = await vkTree(api, manifest.vkTree.leaves.map((x: string) => BigInt(x)));
    assert(p.layers[p.layers.length - 1][0] === BigInt(manifest.vkTree.root), 'VK tree root != manifest');
    return p;
  }

  get vkTreeRoot(): bigint {
    return BigInt(this.manifest.vkTree.root);
  }
  get paramsHash(): bigint {
    return BigInt(this.manifest.paramsHash);
  }
  get configHash(): bigint {
    return BigInt(this.manifest.configHash);
  }

  membership(pkg: string) {
    const index = this.manifest.vkTree.slots[pkg];
    assert(index !== undefined, `${pkg} has no VK tree slot`);
    return { index, path: vkPath(this.layers, index).map(hex) };
  }

  child(node: ProvedNode, overrides: ChildOverrides = {}) {
    return {
      vk: readVkJson(node.pkg).vk,
      proof: node.proof.map(hex),
      vk_hash: this.manifest.vkHashByPkg[node.pkg],
      membership: overrides.membership ?? this.membership(node.pkg),
      out: nodeToNoir(node.out),
      ...overrides,
    };
  }

  /** Executes a rollup-target circuit, proves and verifies it, and checks its public inputs. */
  async proveNode(pkg: string, inputs: Record<string, unknown>): Promise<ProvedNode> {
    const c = readCircuit(pkg);
    const { witness, returnValue } = await new Noir(c as any).execute(inputs as any);
    const backend = new UltraHonkBackend(c.bytecode, this.api);
    const [pd, ms] = await timed(() => backend.generateProof(witness, ROLLUP));
    assert(await backend.verifyProof(pd, ROLLUP), `${pkg} proof does not verify`);
    // Padding and rogue_segment take their output as a public input instead of returning it.
    const out = nodeFromNoir(returnValue ?? inputs.out);
    const fields = nodeFields(out);
    assert(
      pd.publicInputs.length === fields.length && pd.publicInputs.every((x, i) => BigInt(x) === fields[i]),
      `${pkg} public inputs != its NodeOutput`,
    );
    return { pkg, proof: bytesToFields(pd.proof), out, ms };
  }

  /** MAX_CLIENT_PROOFS proofs of the P0 client circuit, each authorizing a random message. */
  async clientProofs() {
    const api = this.api;
    const client = readCircuit('client_auth');
    const clientNoir = new Noir(client as any);
    const clientBackend = new UltraHonkBackend(client.bytecode, api);
    const proofs: string[][] = [];
    const publicInputs: string[][] = [];
    const clientMs: number[] = [];
    for (let i = 0; i < SHAPE.MAX_CLIENT_PROOFS; i++) {
      const secret = randomField();
      // client_auth asserts hash(DS_AUTH, secret) == auth_binding, which cross-checks l3xHash.
      const { witness } = await clientNoir.execute({
        secret: hex(secret),
        msg: hex(randomField()),
        account_index: hex(BigInt(i + 1)),
        auth_binding: hex(await l3xHash(api, [DS.AUTH, secret])),
      });
      const [pd, t] = await timed(() => clientBackend.generateProof(witness, RECURSIVE));
      clientMs.push(t);
      proofs.push(bytesToFields(pd.proof).map(hex));
      publicInputs.push(pd.publicInputs);
    }
    assert(proofs[0].length === 458, `client proof has ${proofs[0].length} fields, expected 458`);
    return { proofs, publicInputs, meanMs: clientMs.reduce((a, b) => a + b, 0) / clientMs.length };
  }

  /** Client proofs and the Chonk IVC of a P-segment (agg_app and three kernels). */
  async chonkSegment(count: number, log = console.log): Promise<ChonkSegment> {
    const ms: Record<string, number> = {};
    const sizes: Record<string, number> = {};
    const api = this.api;
    const { proofs, publicInputs, meanMs } = await this.clientProofs();
    sizes.client_proof_fields = proofs[0].length;
    ms.client_proof_mean = meanMs;

    const circuits = Object.fromEntries(IVC.map((p) => [p, readCircuit(p)]));
    const agg = await new Noir(circuits.agg_app as any).execute({
      client_vk: readVkJson('client_auth').vk,
      proofs,
      public_inputs: publicInputs,
      count,
    });
    const aggOut = agg.returnValue as { actions_hash: string; count: string };
    const init = await new Noir(circuits.init_kernel as any).execute({ app_output: aggOut, app_vk: readVkJson('agg_app').vk });
    const tail = await new Noir(circuits.tail_kernel as any).execute({ prev: aggOut, prev_vk: readVkJson('init_kernel').vk });
    const hiding = await new Noir(circuits.hiding_kernel as any).execute({ prev: aggOut, prev_vk: readVkJson('tail_kernel').vk });

    const chonk = new AztecClientBackend(
      IVC.map((p) => new Uint8Array(gunzipSync(Buffer.from(circuits[p].bytecode, 'base64')))),
      api,
      [...IVC],
      [CircuitKind.App, CircuitKind.Kernel, CircuitKind.Kernel, CircuitKind.HidingKernel],
    );
    const ivcGates = await chonk.gates();
    IVC.forEach((p, i) => (sizes[`${p}_mega_gates`] = ivcGates[i]));
    const [res, chonkMs] = await timed(() =>
      chonk.prove(
        [agg.witness, init.witness, tail.witness, hiding.witness].map((w) => new Uint8Array(gunzipSync(w))),
        IVC.map(readVkBinary),
      ),
    );
    ms.chonk_prove = chonkMs;
    assert(await chonk.verify(res.proof, res.vk), 'Chonk proof does not verify natively');
    const fields = res.proofFields.map(fromBytes32);
    assert(fields.length === SHAPE.CHONK_PROOF_LENGTH + 2, `Chonk proof has ${fields.length} fields`);
    assert(
      fields[0] === BigInt(aggOut.actions_hash) && fields[1] === BigInt(aggOut.count),
      'Chonk public inputs are not the leading fields',
    );
    const chonkVk = bytesToFields(res.vk);
    const hidingVk = readVkJson('hiding_kernel').vk.map((x) => BigInt(x));
    assert(chonkVk.length === hidingVk.length && chonkVk.every((x, i) => x === hidingVk[i]), 'Chonk VK != hiding kernel VK');
    log(`  chonk: ${proofs.length} client proofs × ${ms.client_proof_mean.toFixed(0)} ms, IVC ${chonkMs.toFixed(0)} ms`);
    return { aggOut, chonkVk, chonkProof: fields.slice(2), ms, sizes };
  }

  /** P-segment leaf. P0 effect: the accounts root absorbs the actions hash. */
  async tube(start: Running, accountsRoot: bigint, otherRoot: bigint, count: number = SHAPE.MAX_CLIENT_PROOFS, log = console.log) {
    const seg = await this.chonkSegment(count, log);
    const node = await this.proveNode('tube', {
      chonk_vk: seg.chonkVk.map(hex),
      chonk_proof: seg.chonkProof.map(hex),
      agg: seg.aggOut,
      config_hash: hex(this.configHash),
      start: runningToNoir(start),
      accounts_root: hex(accountsRoot),
      other_root: hex(otherRoot),
    });
    const accountsOut = await l3xHash(this.api, [DS.ACCOUNTS, accountsRoot, BigInt(seg.aggOut.actions_hash)]);
    assert(node.out.end.state === (await trees(this.api, accountsOut, otherRoot)), 'tube end state mismatch');
    log(`  tube: ${node.ms.toFixed(0)} ms`);
    return { node, accountsRoot: accountsOut, chonk: seg };
  }

  /** X-segment leaf carrying one L3 block. P0 effect: each consumed entry is absorbed into the accounts root. */
  async xSegment(
    start: Running,
    accountsRoot: bigint,
    otherRoot: bigint,
    blockTime: bigint,
    entries: bigint[],
    daFields: bigint[],
    configHash = this.configHash,
  ) {
    assert(entries.length <= SHAPE.MAX_PRIORITY, 'too many priority entries for one X-segment');
    assert(daFields.length <= SHAPE.X_DA_MAX, 'too many DA fields for one X-segment');
    const node = await this.proveNode('x_segment', {
      config_hash: hex(configHash),
      start: runningToNoir(start),
      accounts_root: hex(accountsRoot),
      other_root: hex(otherRoot),
      block_time: blockTime.toString(),
      priority_n: entries.length,
      priority_entries: padTo(entries, SHAPE.MAX_PRIORITY),
      da_n: daFields.length,
      da_fields: padTo(daFields, SHAPE.X_DA_MAX),
    });
    let accounts = accountsRoot;
    for (const e of entries) accounts = await l3xHash(this.api, [DS.ACCOUNTS, accounts, e]);
    let [da, len] = [start.da, start.daLen];
    for (const x of daFields) [da, len] = await daAbsorb(this.api, da, len, x);
    assert(node.out.end.daLen === len && node.out.end.da.every((x, i) => x === da[i]), 'x_segment DA sponge mismatch');
    assert(node.out.end.state === (await trees(this.api, accounts, otherRoot)), 'x_segment end state mismatch');
    return { node, accountsRoot: accounts };
  }

  padding(at: Running, configHash = this.configHash): Promise<ProvedNode> {
    return this.proveNode('padding', { out: nodeToNoir({ configHash, start: at, end: at }) });
  }

  mergeInputs(left: ProvedNode, right: ProvedNode, lo: ChildOverrides = {}, ro: ChildOverrides = {}) {
    return {
      vk_tree_root: hex(this.vkTreeRoot),
      params_hash: hex(this.paramsHash),
      left: this.child(left, lo),
      right: this.child(right, ro),
    };
  }

  merge(left: ProvedNode, right: ProvedNode): Promise<ProvedNode> {
    return this.proveNode('merge', this.mergeInputs(left, right));
  }

  rootInputs(
    left: ProvedNode,
    right: ProvedNode,
    endAccounts: bigint,
    endOther: bigint,
    batchNumber: bigint,
    lo: ChildOverrides = {},
    ro: ChildOverrides = {},
  ) {
    return {
      ...this.mergeInputs(left, right, lo, ro),
      end_accounts_root: hex(endAccounts),
      end_other_root: hex(endOther),
      batch_number: batchNumber.toString(),
    };
  }

  /** Proves the root: an UltraHonk ZK proof whose only public input is H(header). */
  async proveRoot(inputs: Record<string, unknown>) {
    const c = readCircuit('root');
    const { witness, returnValue } = await new Noir(c as any).execute(inputs as any);
    const backend = new UltraHonkBackend(c.bytecode, this.api);
    const [pd, ms] = await timed(() => backend.generateProof(witness, RECURSIVE));
    const verified = await backend.verifyProof(pd, RECURSIVE);
    return { headerHash: BigInt(returnValue as string), proof: bytesToFields(pd.proof), publicInputs: pd.publicInputs.map((x) => BigInt(x)), ms, verified };
  }
}

export type SegmentSpec =
  | { kind: 'p'; count?: number }
  | { kind: 'x'; blockTime: bigint; entries?: bigint[]; daFields?: bigint[] };

export type BatchSpec = {
  batchNumber: bigint;
  /** Chain tip at the start of the batch (see batchStart). */
  start: Running;
  /** Opening of start.state. */
  accountsRoot: bigint;
  otherRoot: bigint;
  segments: SegmentSpec[];
};

export type ProvedBatch = {
  header: bigint[];
  headerHash: bigint;
  rootProof: bigint[];
  rootVk: bigint[];
  daPayload: bigint[];
  end: Running;
  accountsRoot: bigint;
  otherRoot: bigint;
  shape: string;
  ms: Record<string, number>;
  sizes: Record<string, number>;
};

/** Proves a batch: leaves in order, then merges of adjacent nodes until two remain, then the root. */
export async function proveBatch(prover: Prover, spec: BatchSpec, log = console.log): Promise<ProvedBatch> {
  const api = prover.api;
  const ms: Record<string, number> = {};
  const sizes: Record<string, number> = {};
  let running = spec.start;
  let accounts = spec.accountsRoot;
  const other = spec.otherRoot;
  const leaves: ProvedNode[] = [];
  const names: string[] = [];
  const daPayload: bigint[] = [];

  for (const [i, seg] of spec.segments.entries()) {
    if (seg.kind === 'p') {
      const r = await prover.tube(running, accounts, other, seg.count, log);
      accounts = r.accountsRoot;
      leaves.push(r.node);
      ms.chonk_prove = (ms.chonk_prove ?? 0) + r.chonk.ms.chonk_prove;
      ms.client_proof_mean = r.chonk.ms.client_proof_mean;
      Object.assign(sizes, r.chonk.sizes);
      names.push('tube');
    } else {
      const r = await prover.xSegment(running, accounts, other, seg.blockTime, seg.entries ?? [], seg.daFields ?? []);
      accounts = r.accountsRoot;
      leaves.push(r.node);
      daPayload.push(...(seg.daFields ?? []));
      names.push('x');
      log(`  x_segment ${i}: ${r.node.ms.toFixed(0)} ms (${seg.entries?.length ?? 0} priority entries, ${seg.daFields?.length ?? 0} DA fields)`);
    }
    const node = leaves[leaves.length - 1];
    ms[`${node.pkg}_${i}`] = node.ms;
    running = node.out.end;
  }

  let level = leaves;
  let shape = names;
  if (level.length === 1) {
    const pad = await prover.padding(level[0].out.end);
    ms.padding = pad.ms;
    level = [level[0], pad];
    shape = [shape[0], 'pad'];
  }
  let merges = 0;
  while (level.length > 2) {
    const next: ProvedNode[] = [];
    const nextShape: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        const m = await prover.merge(level[i], level[i + 1]);
        ms[`merge_${merges++}`] = m.ms;
        log(`  merge: ${m.ms.toFixed(0)} ms`);
        next.push(m);
        nextShape.push(`merge(${shape[i]}, ${shape[i + 1]})`);
      } else {
        next.push(level[i]);
        nextShape.push(shape[i]);
      }
    }
    level = next;
    shape = nextShape;
  }

  const root = await prover.proveRoot(prover.rootInputs(level[0], level[1], accounts, other, spec.batchNumber));
  assert(root.verified, 'root proof does not verify');
  ms.root_prove = root.ms;
  log(`  root: ${root.ms.toFixed(0)} ms`);

  // Rebuild the header in TS; it must hash to the root's public input.
  const s = spec.start;
  const e = level[1].out.end;
  const n = spec.batchNumber;
  const header = [
    await stateRoot(api, s.state, s.priorityCursor, n - 1n, s.time),
    await stateRoot(api, e.state, e.priorityCursor, n, e.time),
    accounts,
    n,
    s.time,
    e.time,
    s.priorityCursor,
    e.priorityCursor,
    s.priorityHead,
    e.priorityHead,
    e.withdrawals,
    BigInt(e.withdrawalsCount),
    e.actionLog,
    await daFinalize(api, e.da, e.daLen),
    0n,
    prover.configHash,
  ];
  const headerHash = await l3xHash(api, [DS.HEADER, ...header]);
  assert(headerHash === root.headerHash, 'TS header hash != root circuit output');
  assert(headerHash === root.publicInputs[0], 'TS header hash != root proof public input');
  assert((await daHash(api, daPayload)) === header[13], 'flat DA hash != segment sponge');

  return {
    header,
    headerHash,
    rootProof: root.proof,
    rootVk: readVkJson('root').vk.map((x) => BigInt(x)),
    daPayload,
    end: e,
    accountsRoot: accounts,
    otherRoot: other,
    shape: `root(${shape[0]}, ${shape[1]})`,
    ms,
    sizes,
  };
}
