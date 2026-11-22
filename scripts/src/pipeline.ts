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
  vkPath,
  vkTree,
} from './lib.ts';
import { type P256Key, bytes32, halves, p256Sign } from './exchange/p256.ts';

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
  withdrawalsAmount: bigint;
  batch: bigint;
  time: bigint;
};

/** Mirror of l3x_types::NodeOutput, the public output of every merge-tree node. */
export type NodeOutput = { configHash: bigint; start: Running; end: Running; receiptsRoot: bigint };

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
    r.withdrawalsAmount,
    r.batch,
    r.time,
  ];
}

export function nodeFields(n: NodeOutput): bigint[] {
  return [n.configHash, ...runningFields(n.start), ...runningFields(n.end), n.receiptsRoot];
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
  withdrawals_amount: r.withdrawalsAmount.toString(),
  batch: r.batch.toString(),
  time: r.time.toString(),
});

export const nodeToNoir = (n: NodeOutput) => ({
  config_hash: hex(n.configHash),
  start: runningToNoir(n.start),
  end: runningToNoir(n.end),
  receipts_root: hex(n.receiptsRoot),
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
  withdrawalsAmount: BigInt(o.withdrawals_amount),
  batch: BigInt(o.batch),
  time: BigInt(o.time),
});

const nodeFromNoir = (o: any): NodeOutput => ({
  configHash: BigInt(o.config_hash),
  start: runningFromNoir(o.start),
  end: runningFromNoir(o.end),
  receiptsRoot: BigInt(o.receipts_root),
});

/** Running values at the start of a batch: the chain tip, with per-batch accumulators empty. */
export function batchStart(state: bigint, priorityHead: bigint, priorityCursor: bigint, time: bigint, batch: bigint): Running {
  return {
    state,
    actionLog: 0n,
    priorityHead,
    priorityCursor,
    da: daIv(),
    daLen: 0,
    withdrawals: 0n,
    withdrawalsCount: 0,
    withdrawalsAmount: 0n,
    batch,
    time,
  };
}

export const copyRunning = (r: Running): Running => ({ ...r, da: [...r.da] });

export const padTo = (xs: bigint[], n: number) => [...xs, ...Array<bigint>(n - xs.length).fill(0n)].map(hex);
const MAX_WD_BATCH = 16;

export function ultraGates(pkg: string, target: string): number {
  const out = run(BB, ['gates', '-b', join(TARGET, `${pkg}.json`), '-t', target]);
  const m = out.match(/"circuit_size"\s*:\s*(\d+)/);
  return m ? Number(m[1]) : NaN;
}

export async function newApi(): Promise<Barretenberg> {
  const { Barretenberg } = await import('@aztec-foundation/bb.js');
  return Barretenberg.new({ threads: cpus().length });
}

/**
 * A client proof (SPEC.md §7.4): an UltraHonk ZK proof of one of the client circuits (`pkg`), as
 * fields, with its public inputs (msg, account_index, auth_binding).
 */
export type ClientProof = { pkg: string; proof: string[]; publicInputs: string[] };
const CLIENT_PROOF_FIELDS = 458;
/** The client circuits of the VK tree's client subtree. */
export const CLIENT_CIRCUITS = ['client_auth', 'client_p256'] as const;
/** Fields of AggOutput, the Chonk proof's public inputs: actions_hash, count, vk_tree_root. */
const AGG_OUTPUT_LEN = 3;

export type AggOut = { actions_hash: string; count: string; vk_tree_root: string };

export type ChonkSegment = {
  aggOut: AggOut;
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
  private params = 0n;

  private constructor(api: Barretenberg, manifest: any) {
    this.api = api;
    this.manifest = manifest;
  }

  /** `paramsHash` is the deployment's exchange parameters (default: the manifest's). */
  static async create(api: Barretenberg, manifest: any, paramsHash?: bigint): Promise<Prover> {
    const p = new Prover(api, manifest);
    p.params = paramsHash ?? BigInt(manifest.paramsHash);
    p.layers = await vkTree(api, manifest.vkTree.leaves.map((x: string) => BigInt(x)));
    assert(p.layers[p.layers.length - 1][0] === BigInt(manifest.vkTree.root), 'VK tree root != manifest');
    p.configHashValue = await l3xHash(api, [DS.CONFIG, p.vkTreeRoot, p.params]);
    return p;
  }

  get vkTreeRoot(): bigint {
    return BigInt(this.manifest.vkTree.root);
  }
  get paramsHash(): bigint {
    return this.params;
  }
  configHashValue = 0n;
  get configHash(): bigint {
    return this.configHashValue;
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

  private clientCircuits = new Map<string, { noir: Noir; backend: UltraHonkBackend }>();
  private dummy?: ClientProof;

  /** The client_auth VK hash: secret-knowledge lane-P master authorizations commit to it. */
  get clientVkHash(): bigint {
    return BigInt(this.manifest.vkHashByPkg.client_auth);
  }

  /** Every client circuit's VK hash, by package: what an engine needs to build P-segments. */
  get clientVks(): Record<string, bigint> {
    return Object.fromEntries(CLIENT_CIRCUITS.map((p) => [p, BigInt(this.manifest.vkHashByPkg[p])]));
  }

  /** Proves a client circuit (UltraHonk ZK, recursive target), as the client does. */
  async proveClient(pkg: string, inputs: Record<string, unknown>): Promise<ClientProof & { ms: number }> {
    let c = this.clientCircuits.get(pkg);
    if (!c) {
      const circuit = readCircuit(pkg);
      c = { noir: new Noir(circuit as any), backend: new UltraHonkBackend(circuit.bytecode, this.api) };
      this.clientCircuits.set(pkg, c);
    }
    const { witness } = await c.noir.execute(inputs as any);
    const [pd, ms] = await timed(() => c.backend.generateProof(witness, RECURSIVE));
    const proof = bytesToFields(pd.proof).map(hex);
    assert(proof.length === CLIENT_PROOF_FIELDS, `${pkg} proof has ${proof.length} fields, expected ${CLIENT_PROOF_FIELDS}`);
    return { pkg, proof, publicInputs: pd.publicInputs, ms };
  }

  /**
   * A client_auth proof: the client knows `secret` behind the account's auth binding
   * (hash(DS_AUTH, secret), which client_auth asserts) and authorizes `msg` for `account`.
   */
  async clientProof(secret: bigint, msg: bigint, account: bigint) {
    return this.proveClient('client_auth', {
      secret: hex(secret),
      msg: hex(msg),
      account_index: hex(account),
      auth_binding: hex(await l3xHash(this.api, [DS.AUTH, secret])),
    });
  }

  /**
   * A client_p256 proof: a P-256 key signs `msg`'s 32 bytes, and the auth binding commits to the
   * key and `salt` (hash(DS_P256, x_hi, x_lo, y_hi, y_lo, salt)).
   */
  async clientProofP256(key: P256Key, salt: bigint, msg: bigint, account: bigint) {
    const [xh, xl] = halves(key.pk.x);
    const [yh, yl] = halves(key.pk.y);
    return this.proveClient('client_p256', {
      pk_x: bytes32(key.pk.x),
      pk_y: bytes32(key.pk.y),
      salt: hex(salt),
      signature: [...p256Sign(key, new Uint8Array(bytes32(msg)))],
      msg: hex(msg),
      account_index: hex(account),
      auth_binding: hex(await l3xHash(this.api, [DS.P256, xh, xl, yh, yl, salt])),
    });
  }

  /** A valid proof of a random message, for the slots of a P-segment beyond its actions (agg_app verifies every slot). */
  async dummyClientProof(): Promise<ClientProof> {
    this.dummy ??= await this.clientProof(randomField(), randomField(), 0n);
    return this.dummy;
  }

  /** MAX_CLIENT_PROOFS client_auth proofs, each authorizing a random message (M1). */
  async randomClientProofs() {
    const proofs: ClientProof[] = [];
    const ms: number[] = [];
    for (let i = 0; i < SHAPE.MAX_CLIENT_PROOFS; i++) {
      const p = await this.clientProof(randomField(), randomField(), BigInt(i + 1));
      proofs.push(p);
      ms.push(p.ms);
    }
    return { proofs, meanMs: ms.reduce((a, b) => a + b, 0) / ms.length };
  }

  /**
   * The aggregation inputs over ten proof slots, as agg_app and agg_ultra take them: each slot's
   * VK, VK hash and place in the client subtree, under this deployment's VK tree.
   */
  aggInputs(slots: ClientProof[], count: number) {
    return {
      vk_tree_root: hex(this.vkTreeRoot),
      client_vks: slots.map((p) => readVkJson(p.pkg).vk),
      vk_hashes: slots.map((p) => this.manifest.vkHashByPkg[p.pkg]),
      memberships: slots.map((p) => this.membership(p.pkg)),
      proofs: slots.map((p) => p.proof),
      public_inputs: slots.map((p) => p.publicInputs),
      count,
    };
  }

  /**
   * The Chonk IVC of a P-segment (agg_app and three kernels) over its client proofs: agg_app
   * verifies them and folds their public inputs; the remaining slots carry a dummy proof.
   */
  async chonkSegment(clientProofs: ClientProof[], log = console.log): Promise<ChonkSegment> {
    const ms: Record<string, number> = {};
    const sizes: Record<string, number> = {};
    const api = this.api;
    const count = clientProofs.length;
    assert(count <= SHAPE.MAX_CLIENT_PROOFS, `${count} client proofs in one P-segment`);
    for (const p of clientProofs) assert(p.proof.length === CLIENT_PROOF_FIELDS, 'a client action carries no proof (it was built for execution only)');
    const dummy = await this.dummyClientProof();
    const slots = [...clientProofs, ...Array<ClientProof>(SHAPE.MAX_CLIENT_PROOFS - count).fill(dummy)];
    sizes.client_proof_fields = CLIENT_PROOF_FIELDS;

    const circuits = Object.fromEntries(IVC.map((p) => [p, readCircuit(p)]));
    const agg = await new Noir(circuits.agg_app as any).execute(this.aggInputs(slots, count));
    const aggOut = agg.returnValue as AggOut;
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
    assert(fields.length === SHAPE.CHONK_PROOF_LENGTH + AGG_OUTPUT_LEN, `Chonk proof has ${fields.length} fields`);
    assert(
      fields[0] === BigInt(aggOut.actions_hash) && fields[1] === BigInt(aggOut.count) && fields[2] === BigInt(aggOut.vk_tree_root),
      'Chonk public inputs are not the leading fields',
    );
    assert(fields[2] === this.vkTreeRoot, "the IVC's VK tree is not this deployment's");
    const chonkVk = bytesToFields(res.vk);
    const hidingVk = readVkJson('hiding_kernel').vk.map((x) => BigInt(x));
    assert(chonkVk.length === hidingVk.length && chonkVk.every((x, i) => x === hidingVk[i]), 'Chonk VK != hiding kernel VK');
    log(`  chonk: ${count} client proof(s) + ${SHAPE.MAX_CLIENT_PROOFS - count} dummies, IVC ${chonkMs.toFixed(0)} ms`);
    return { aggOut, chonkVk, chonkProof: fields.slice(AGG_OUTPUT_LEN), ms, sizes };
  }

  /**
   * P-segment leaf (SPEC.md §7.4, §9.2): the Chonk IVC over the segment's client proofs, then the
   * tube, which verifies the Chonk proof, recomputes the aggregation from the actions and applies
   * them. `inputs` is the engine's tube witness; its aggregation must be the IVC's.
   */
  async proveTube(inputs: Record<string, unknown>, clientProofs: ClientProof[], log = console.log) {
    const seg = await this.chonkSegment(clientProofs, log);
    const agg = inputs.agg as { actions_hash: string; count: string | number; vk_tree_root: string };
    assert(
      BigInt(agg.actions_hash) === BigInt(seg.aggOut.actions_hash) &&
        BigInt(agg.count) === BigInt(seg.aggOut.count) &&
        BigInt(agg.vk_tree_root) === BigInt(seg.aggOut.vk_tree_root),
      "the engine's aggregation != the IVC's",
    );
    const node = await this.proveNode('tube', { ...inputs, chonk_vk: seg.chonkVk.map(hex), chonk_proof: seg.chonkProof.map(hex) });
    return { node, chonk: seg };
  }

  padding(at: Running, configHash = this.configHash): Promise<ProvedNode> {
    return this.proveNode('padding', { out: nodeToNoir({ configHash, start: at, end: at, receiptsRoot: 0n }) });
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
    endState: unknown,
    withdrawalRecords: bigint[],
    batchNumber: bigint,
    lo: ChildOverrides = {},
    ro: ChildOverrides = {},
  ) {
    return {
      ...this.mergeInputs(left, right, lo, ro),
      end_state: endState,
      withdrawal_records: padTo(withdrawalRecords, MAX_WD_BATCH),
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

/**
 * A segment as the engine built it: the circuit, its inputs, the transition it must prove, and
 * for a trade segment its receipt leaves and receipts root (SPEC.md §11).
 */
export type SegmentWitness = {
  pkg: string;
  label: string;
  inputs: Record<string, unknown>;
  expectedEnd: Running;
  receiptsRoot?: bigint;
  receiptLeaves?: bigint[];
  /** A P-segment's client proofs, one per applied action, in order (SPEC.md §7.4). */
  clientProofs?: ClientProof[];
};

/**
 * Stand-ins for a tube's Chonk VK and proof when a batch is only executed: witness generation does
 * not check recursive proofs, so the tube's application of the actions runs without the IVC.
 */
export const chonkPlaceholder = () => ({
  chonk_vk: readVkJson('hiding_kernel').vk,
  chonk_proof: Array<string>(SHAPE.CHONK_PROOF_LENGTH).fill(hex(0n)),
});

export type BatchWitness = {
  batchNumber: bigint;
  start: Running;
  segments: SegmentWitness[];
  /** The state at the end of the batch, as Noir input, and the header values it determines. */
  endState: unknown;
  endAccountsRoot: bigint;
  /** L3 time at which the current refresh cycle began (SPEC.md §9.5). */
  cycleStart: bigint;
  /** Every market's public data (SPEC.md §8.4) and its hash, which the header carries. */
  marketData: bigint[];
  marketDataHash: bigint;
  withdrawalRecords: bigint[];
  withdrawalsRoot: bigint;
  daPayload: bigint[];
};

export type ProvedBatch = {
  header: bigint[];
  headerHash: bigint;
  rootProof: bigint[];
  rootVk: bigint[];
  daPayload: bigint[];
  marketData: bigint[];
  /** The batch's receipts tree: the header's root and, per segment, its root and leaves. */
  receiptsRoot: bigint;
  segmentRoots: bigint[];
  segmentLeaves: bigint[][];
  end: Running;
  shape: string;
  ms: Record<string, number>;
};

/**
 * Executes every segment of a batch without proving and checks each circuit's output against the
 * engine's expected transition: the differential check of proveBatch in seconds rather than minutes.
 * Returns the parts of a ProvedBatch the tests chain on (the header's state and accounts roots).
 */
export async function executeBatch(prover: Prover, w: BatchWitness, log = console.log): Promise<ProvedBatch> {
  let running = w.start;
  for (const seg of w.segments) {
    const t0 = performance.now();
    const inputs = seg.pkg === 'tube' ? { ...seg.inputs, ...chonkPlaceholder() } : seg.inputs;
    const { returnValue } = await new Noir(readCircuit(seg.pkg) as any).execute(inputs as any);
    const got = nodeFields(nodeFromNoir(returnValue));
    const want = nodeFields({ configHash: prover.configHash, start: running, end: seg.expectedEnd, receiptsRoot: seg.receiptsRoot ?? 0n });
    const bad = got.findIndex((x, j) => x !== want[j]);
    assert(bad < 0, `${seg.label}: circuit output differs from the engine at field ${bad} (${got[bad]} != ${want[bad]})`);
    log(`  ${seg.label}: executed in ${(performance.now() - t0).toFixed(0)} ms`);
    running = seg.expectedEnd;
  }
  const api = prover.api;
  const s = w.start;
  const e = running;
  return {
    header: [await stateRoot(api, s.state, s.priorityCursor, w.batchNumber - 1n, s.time), await stateRoot(api, e.state, e.priorityCursor, w.batchNumber, e.time), w.endAccountsRoot],
    headerHash: 0n,
    rootProof: [],
    rootVk: [],
    daPayload: w.daPayload,
    marketData: w.marketData,
    ...(await receiptsOf(api, w)),
    end: e,
    shape: `executed ${w.segments.length} segments`,
    ms: {},
  };
}

/** The receipts tree of a batch, built as proveBatch builds the merge tree (SPEC.md §11). */
async function receiptsOf(api: Barretenberg, w: BatchWitness) {
  const segmentRoots = w.segments.map((s) => s.receiptsRoot ?? 0n);
  const segmentLeaves = w.segments.map((s) => s.receiptLeaves ?? [0n, 0n]);
  const node = (l: bigint, r: bigint) => l3xHash(api, [DS.RECEIPT_NODE, l, r]);
  let level = segmentRoots.length === 1 ? [segmentRoots[0], 0n] : [...segmentRoots];
  while (level.length > 2) {
    const next: bigint[] = [];
    for (let k = 0; k < level.length; k += 2) next.push(k + 1 < level.length ? await node(level[k], level[k + 1]) : level[k]);
    level = next;
  }
  return { receiptsRoot: await node(level[0], level[1]), segmentRoots, segmentLeaves };
}

/**
 * The path of a receipted action's leaf (slot `slot` of segment `segment`) in a batch's receipts
 * tree, as Bridge.answer takes it: siblings from the leaf up, and for each level whether the node
 * is the right child. A node carried up unpaired adds no level.
 */
export async function receiptPath(api: Barretenberg, b: Pick<ProvedBatch, 'segmentRoots' | 'segmentLeaves'>, segment: number, slot: number) {
  const node = (l: bigint, r: bigint) => l3xHash(api, [DS.RECEIPT_NODE, l, r]);
  const path: bigint[] = [b.segmentLeaves[segment][slot ^ 1]];
  let bits = slot;
  let level = b.segmentRoots.length === 1 ? [b.segmentRoots[0], 0n] : [...b.segmentRoots];
  let i = segment;
  while (level.length > 2) {
    const next: bigint[] = [];
    for (let k = 0; k < level.length; k += 2) next.push(k + 1 < level.length ? await node(level[k], level[k + 1]) : level[k]);
    if (!(i === level.length - 1 && level.length % 2 === 1)) {
      if (i & 1) bits |= 1 << path.length;
      path.push(level[i ^ 1]);
    }
    i >>= 1;
    level = next;
  }
  if (i & 1) bits |= 1 << path.length;
  path.push(level[i ^ 1]);
  return { depth: path.length, bits, path };
}

/** Folds a receipt path from its leaf, as Bridge.answer does. */
export async function foldReceipt(api: Barretenberg, leaf: bigint, p: { depth: number; bits: number; path: bigint[] }) {
  let n = leaf;
  for (let i = 0; i < p.depth; i++) n = await l3xHash(api, [DS.RECEIPT_NODE, ...(((p.bits >> i) & 1) === 1 ? [p.path[i], n] : [n, p.path[i]])]);
  return n;
}

export const receiptLeaf = (api: Barretenberg, seq: bigint, msg: bigint) => l3xHash(api, [DS.RECEIPT, seq, msg]);

/**
 * Proves a batch: every segment (checking the circuit's output against the engine's expected
 * transition, the engine/circuit differential check), merges of adjacent nodes until two remain
 * (padding a single segment), then the root.
 */
export async function proveBatch(prover: Prover, w: BatchWitness, log = console.log): Promise<ProvedBatch> {
  const api = prover.api;
  const ms: Record<string, number> = {};
  const leaves: ProvedNode[] = [];
  const names: string[] = [];
  let running = w.start;
  for (const [i, seg] of w.segments.entries()) {
    let node: ProvedNode;
    if (seg.pkg === 'tube') {
      const t = await prover.proveTube(seg.inputs, seg.clientProofs ?? [], log);
      ms[`chonk_${i}`] = t.chonk.ms.chonk_prove;
      node = t.node;
    } else {
      node = await prover.proveNode(seg.pkg, seg.inputs);
    }
    const got = nodeFields(node.out);
    const want = nodeFields({ configHash: prover.configHash, start: running, end: seg.expectedEnd, receiptsRoot: seg.receiptsRoot ?? 0n });
    const bad = got.findIndex((x, j) => x !== want[j]);
    assert(bad < 0, `${seg.label}: circuit output differs from the engine at field ${bad} (${got[bad]} != ${want[bad]})`);
    ms[`${seg.pkg}_${i}`] = node.ms;
    log(`  ${seg.label}: ${node.ms.toFixed(0)} ms`);
    leaves.push(node);
    names.push(seg.pkg.replace('seg_', ''));
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
  if (merges) log(`  ${merges} merge(s): ${Object.entries(ms).filter(([k]) => k.startsWith('merge')).map(([, v]) => v.toFixed(0)).join(', ')} ms`);

  const root = await prover.proveRoot(prover.rootInputs(level[0], level[1], w.endState, w.withdrawalRecords, w.batchNumber));
  assert(root.verified, 'root proof does not verify');
  ms.root_prove = root.ms;
  log(`  root: ${root.ms.toFixed(0)} ms`);

  // Rebuild the header in TS; it must hash to the root's public input.
  const s = leaves[0].out.start;
  const e = level[1].out.end;
  const n = w.batchNumber;
  const header = [
    await stateRoot(api, s.state, s.priorityCursor, n - 1n, s.time),
    await stateRoot(api, e.state, e.priorityCursor, n, e.time),
    w.endAccountsRoot,
    n,
    s.time,
    e.time,
    s.priorityCursor,
    e.priorityCursor,
    s.priorityHead,
    e.priorityHead,
    w.withdrawalsRoot,
    BigInt(e.withdrawalsCount),
    e.withdrawalsAmount,
    e.actionLog,
    await daFinalize(api, e.da, e.daLen),
    w.marketDataHash,
    prover.configHash,
    w.cycleStart,
    await l3xHash(api, [DS.RECEIPT_NODE, level[0].out.receiptsRoot, level[1].out.receiptsRoot]),
  ];
  const headerHash = await l3xHash(api, [DS.HEADER, ...header]);
  assert(headerHash === root.headerHash, 'TS header hash != root circuit output');
  assert(headerHash === root.publicInputs[0], 'TS header hash != root proof public input');
  assert((await daHash(api, w.daPayload)) === header[14], 'flat DA hash != segment sponge');
  const receipts = await receiptsOf(api, w);
  assert(receipts.receiptsRoot === header[18], 'TS receipts tree != the root circuit\'s');

  return {
    header,
    headerHash,
    rootProof: root.proof,
    rootVk: readVkJson('root').vk.map((x) => BigInt(x)),
    daPayload: w.daPayload,
    marketData: w.marketData,
    ...receipts,
    end: e,
    shape: `root(${shape[0]}, ${shape[1]})`,
    ms,
  };
}
