// The batch prover (SPEC.md §9.2). Segments become merge-tree leaves: a P-segment through client
// proofs, the Chonk IVC and the tube; an X-segment directly. Adjacent nodes are merged until two
// remain, and the root verifies those two and binds the batch header. Returns what Bridge.settle
// needs, plus timings.
import { cpus } from 'node:os';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { AztecClientBackend, type Barretenberg, UltraHonkBackend, flattenChonkProofFields } from '@aztec-foundation/bb.js';
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
import { CLIENT_DATA_MAX, makeAssertion, rpHalves } from './exchange/webauthn.ts';
import { execPool } from './exec_pool.ts';

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
  batch: bigint;
  time: bigint;
};

/** Mirror of l3x_types::NodeOutput, the public output of every merge-tree node. */
export type NodeOutput = { configHash: bigint; start: Running; end: Running; receiptsRoot: bigint };

/** `ms` is the proof's time in bb; `execMs` the witness execution, `verifyMs` the native check. */
export type ProvedNode = { pkg: string; proof: bigint[]; out: NodeOutput; ms: number; execMs?: number; verifyMs?: number };

/** bb.js's proof settings for a verifier target (its own mapping is not exported). */
const SETTINGS = {
  'noir-recursive': { ipaAccumulation: false, oracleHashType: 'poseidon2', disableZk: false, optimizedSolidityVerifier: false },
  'noir-rollup-no-zk': { ipaAccumulation: true, oracleHashType: 'poseidon2', disableZk: true, optimizedSolidityVerifier: false },
} as const;

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
export const CLIENT_CIRCUITS = ['client_auth', 'client_p256', 'client_webauthn'] as const;
/** Segment apps a batch kernel folds (l3x_types::batch::APPS_PER_KERNEL). */
export const APPS_PER_KERNEL = 5;
/** bb's limit on apps in one Chonk run (CHONK_MAX_NUM_APPS). */
export const CHONK_MAX_APPS = 45;
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

  private bytecodes = new Map<string, Uint8Array>();
  private vks = new Map<string, Uint8Array>();

  /**
   * Proves `pkg` with UltraHonk, handing bb the build's VK (bb.js's backend passes an empty one,
   * so every proof would recompute it), then verifies natively against the same VK (bb.js's
   * verifyProof recomputes the VK first: about a minute for the root). P2.28.
   */
  async ultraProve(pkg: string, witness: Uint8Array, target: keyof typeof SETTINGS) {
    if (!this.bytecodes.has(pkg)) {
      this.bytecodes.set(pkg, new Uint8Array(gunzipSync(Buffer.from(readCircuit(pkg).bytecode, 'base64'))));
      this.vks.set(pkg, readVkBinary(pkg));
    }
    const settings = SETTINGS[target];
    const verificationKey = this.vks.get(pkg)!;
    const [r, ms] = await timed(() =>
      this.api.circuitProve({ witness: new Uint8Array(gunzipSync(witness)), circuit: { name: pkg, bytecode: this.bytecodes.get(pkg)!, verificationKey }, settings }),
    );
    const t0 = performance.now();
    const { verified } = await this.api.circuitVerify({ verificationKey, publicInputs: r.publicInputs, proof: r.proof, settings });
    const verifyMs = performance.now() - t0;
    return { proof: r.proof.map(fromBytes32), publicInputs: r.publicInputs.map(fromBytes32), ms, verified, verifyMs };
  }

  /** Executes a rollup-target circuit, proves and verifies it, and checks its public inputs. */
  async proveNode(pkg: string, inputs: Record<string, unknown>): Promise<ProvedNode> {
    const [{ witness, returnValue }, execMs] = await timed(() => execPool().execute(pkg, inputs));
    const pd = await this.ultraProve(pkg, witness, 'noir-rollup-no-zk');
    assert(pd.verified, `${pkg} proof does not verify`);
    // Padding and rogue_segment take their output as a public input instead of returning it.
    const out = nodeFromNoir(returnValue ?? inputs.out);
    const fields = nodeFields(out);
    assert(
      pd.publicInputs.length === fields.length && pd.publicInputs.every((x, i) => x === fields[i]),
      `${pkg} public inputs != its NodeOutput`,
    );
    return { pkg, proof: pd.proof, out, ms: pd.ms, execMs, verifyMs: pd.verifyMs };
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

  /**
   * The client_webauthn witness for an assertion of `msg` by passkey `key` registered with relying
   * party `rpId`: the auth binding commits to the key, the relying party and `salt`.
   */
  async webauthnWitness(key: P256Key, salt: bigint, rpId: string, origin: string, msg: bigint, account: bigint) {
    const a = makeAssertion(key, rpId, origin, msg);
    const [xh, xl] = halves(key.pk.x);
    const [yh, yl] = halves(key.pk.y);
    const [rh, rl] = rpHalves(rpId);
    return {
      pk_x: bytes32(key.pk.x),
      pk_y: bytes32(key.pk.y),
      salt: hex(salt),
      signature: [...a.signature],
      authenticator_data: [...a.authenticatorData],
      client_data: [...a.clientDataJSON, ...Array<number>(CLIENT_DATA_MAX - a.clientDataJSON.length).fill(0)],
      client_data_len: a.clientDataJSON.length,
      msg: hex(msg),
      account_index: hex(account),
      auth_binding: hex(await l3xHash(this.api, [DS.WEBAUTHN, xh, xl, yh, yl, rh, rl, salt])),
    };
  }

  /** A client_webauthn proof: a WebAuthn assertion of `msg`, as a browser's passkey makes it. */
  async clientProofWebAuthn(key: P256Key, salt: bigint, rpId: string, origin: string, msg: bigint, account: bigint) {
    return this.proveClient('client_webauthn', await this.webauthnWitness(key, salt, rpId, origin, msg, account));
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

  /**
   * A Chonk run over consecutive X-segments (SPEC.md §9.2, P2.28), all at once: a ChonkStream
   * sized to them (whole groups of five), fed every segment, then finished.
   */
  async chonkRun(segs: { pkg: string; inputs: Record<string, unknown> }[], log = console.log): Promise<ChonkRunResult> {
    assert(segs.length > 0 && segs.length <= CHONK_MAX_APPS, `${segs.length} segments in one Chonk run`);
    const s = ChonkStream.open(this, Math.ceil(segs.length / APPS_PER_KERNEL) * APPS_PER_KERNEL);
    for (const seg of segs) s.add(seg);
    return s.finish(log);
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
    const [{ witness, returnValue }, execMs] = await timed(() => execPool().execute('root', inputs));
    const pd = await this.ultraProve('root', witness, 'noir-recursive');
    return { headerHash: BigInt(returnValue as string), proof: pd.proof, publicInputs: pd.publicInputs, ms: pd.ms, verified: pd.verified, execMs, verifyMs: pd.verifyMs };
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
  receiptShape: ReceiptShape;
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
/**
 * The shape of a batch's receipts tree above its segments' own trees: a segment index, an empty
 * slot (null, a padding app's zero root), or a node over two subtrees. It follows the
 * aggregation: merges pair nodes level by level, and a Chonk run's kernels pair apps within a
 * group of five and chain the groups (P2.28).
 */
export type ReceiptShape = number | null | [ReceiptShape, ReceiptShape];

/** Merge-tree pairing, level by level with an odd node carried up, until the root's two children. */
export function mergeShape(leaves: ReceiptShape[]): ReceiptShape {
  let level = leaves.length === 1 ? [leaves[0], null] : [...leaves];
  while (level.length > 2) {
    const next: ReceiptShape[] = [];
    for (let k = 0; k < level.length; k += 2) next.push(k + 1 < level.length ? [level[k], level[k + 1]] : level[k]);
    level = next;
  }
  return [level[0], level[1]];
}

/**
 * A Chonk run over `segments` (l3x_types::batch): groups of five, chained left to right, padded
 * with empty slots up to the run's capacity (a streamed run's unused groups are all padding).
 */
export function chonkRunShape(segments: number[], capacity = Math.ceil(segments.length / APPS_PER_KERNEL) * APPS_PER_KERNEL): ReceiptShape {
  let acc: ReceiptShape | undefined;
  for (let i = 0; i < capacity; i += APPS_PER_KERNEL) {
    const g: ReceiptShape[] = segments.slice(i, i + APPS_PER_KERNEL);
    while (g.length < APPS_PER_KERNEL) g.push(null);
    const group: ReceiptShape = [[[g[0], g[1]], [g[2], g[3]]], g[4]];
    acc = acc === undefined ? group : [acc, group];
  }
  assert(acc !== undefined, 'empty Chonk run');
  return acc;
}

async function foldShape(api: Barretenberg, shape: ReceiptShape, roots: bigint[]): Promise<bigint> {
  if (shape === null) return 0n;
  if (typeof shape === 'number') return roots[shape];
  return l3xHash(api, [DS.RECEIPT_NODE, await foldShape(api, shape[0], roots), await foldShape(api, shape[1], roots)]);
}

const shapeHas = (shape: ReceiptShape, i: number): boolean =>
  shape === i || (Array.isArray(shape) && (shapeHas(shape[0], i) || shapeHas(shape[1], i)));

async function receiptsOf(api: Barretenberg, w: BatchWitness, shape = mergeShape(w.segments.map((_, i) => i))) {
  const segmentRoots = w.segments.map((s) => s.receiptsRoot ?? 0n);
  const segmentLeaves = w.segments.map((s) => s.receiptLeaves ?? [0n, 0n]);
  return { receiptsRoot: await foldShape(api, shape, segmentRoots), segmentRoots, segmentLeaves, receiptShape: shape };
}

/**
 * The path of a receipted action's leaf (slot `slot` of segment `segment`) in a batch's receipts
 * tree, as Bridge.answer takes it: siblings from the leaf up, and for each level whether the node
 * is the right child. A node carried up unpaired adds no level.
 */
export async function receiptPath(
  api: Barretenberg,
  b: Pick<ProvedBatch, 'segmentRoots' | 'segmentLeaves'> & { receiptShape?: ReceiptShape },
  segment: number,
  slot: number,
) {
  const node = (l: bigint, r: bigint) => l3xHash(api, [DS.RECEIPT_NODE, l, r]);
  // First up the segment's own receipts tree: two leaves for seg_trade, 32 for seg_quote.
  const path: bigint[] = [];
  let bits = 0;
  let leaves = b.segmentLeaves[segment];
  for (let j = slot; leaves.length > 1; j >>= 1) {
    if (j & 1) bits |= 1 << path.length;
    path.push(leaves[j ^ 1]);
    const up: bigint[] = [];
    for (let k = 0; k < leaves.length; k += 2) up.push(await node(leaves[k], leaves[k + 1]));
    leaves = up;
  }
  // Then up the aggregation's shape from the segment's root: collect siblings top-down, then reverse.
  const shape = b.receiptShape ?? mergeShape(b.segmentRoots.map((_, i) => i));
  const above: { sibling: bigint; right: boolean }[] = [];
  let at: ReceiptShape = shape;
  while (at !== segment) {
    assert(Array.isArray(at), `segment ${segment} is not in the receipts shape`);
    const right = shapeHas(at[1], segment);
    above.push({ sibling: await foldShape(api, right ? at[0] : at[1], b.segmentRoots), right });
    at = right ? at[1] : at[0];
  }
  for (const { sibling, right } of above.reverse()) {
    if (right) bits |= 1 << path.length;
    path.push(sibling);
  }
  return { depth: path.length, bits, path };
}

/** Folds a receipt path from its leaf, as Bridge.answer does. */
export async function foldReceipt(api: Barretenberg, leaf: bigint, p: { depth: number; bits: number; path: bigint[] }) {
  let n = leaf;
  for (let i = 0; i < p.depth; i++) n = await l3xHash(api, [DS.RECEIPT_NODE, ...(((p.bits >> i) & 1) === 1 ? [p.path[i], n] : [n, p.path[i]])]);
  return n;
}

export const receiptLeaf = (api: Barretenberg, seq: bigint, msg: bigint) => l3xHash(api, [DS.RECEIPT, seq, msg]);

export type ChonkRunResult = ProvedNode & {
  chonkMs: number;
  tubeMs: number;
  deciderMs: number;
  chonkExecMs: number;
  byPkg: Record<string, { n: number; ms: number }>;
  sizes: Record<string, number>;
};

/**
 * A Chonk run fed one segment at a time (SPEC.md §9.2, P2.28), so a proving service can fold a
 * batch's segments while the batch is still open. bb fixes a run's circuits when it starts
 * (chonkStart takes every circuit's kind), so a stream has a capacity in whole groups of five; at
 * `finish` the unused slots are filled with padding apps. Each segment is executed as its Mega
 * app on the witness workers as soon as it arrives and accumulated in order: app by app, and the
 * batch kernel after every fifth (bk_init, then bk_inner); `finish` adds bk_tail and bk_hiding,
 * proves the run (the HyperNova decider, ECCVM, translator) and the batch tube.
 *
 * The stream holds its prover's bb process from `open` to `finish`.
 */
/** Per-circuit accumulation totals and the decider of run `r`, under keys that do not sum into proving time. */
function recordRun(ms: Record<string, number>, r: number, res: ChonkRunResult) {
  for (const [pkg, b] of Object.entries(res.byPkg)) {
    ms[`acc.${pkg}.n`] = (ms[`acc.${pkg}.n`] ?? 0) + b.n;
    ms[`acc.${pkg}.ms`] = (ms[`acc.${pkg}.ms`] ?? 0) + b.ms;
  }
  ms[`decider.${r}`] = res.deciderMs;
}

export class ChonkStream {
  readonly capacity: number;
  readonly prover: Prover;
  private chain: Promise<void>;
  private group: { pkg: string; out: any }[] = [];
  private prev?: { pkg: string; out: any };
  private last?: any;
  private accumulated = 0;
  private added = 0;
  private bytecodes = new Map<string, Uint8Array>();
  execMs = 0;
  accumulateMs = 0;
  /** Accumulation time and count by circuit. */
  readonly byPkg: Record<string, { n: number; ms: number }> = {};
  readonly openedAt = performance.now();

  private constructor(prover: Prover, capacity: number) {
    assert(capacity > 0 && capacity % APPS_PER_KERNEL === 0 && capacity <= CHONK_MAX_APPS, `Chonk stream capacity ${capacity}`);
    this.prover = prover;
    this.capacity = capacity;
    const kinds: number[] = [];
    for (let g = 0; g < capacity / APPS_PER_KERNEL; g++) kinds.push(...Array<number>(APPS_PER_KERNEL).fill(CircuitKind.App), CircuitKind.Kernel);
    kinds.push(CircuitKind.Kernel, CircuitKind.HidingKernel);
    this.chain = prover.api.chonkStart({ kinds: kinds as any }).then(() => {});
    this.chain.catch(() => {});
  }

  /** Starts a run of `capacity` apps (a multiple of five, at most 45) on `prover`. */
  static open(prover: Prover, capacity: number) {
    return new ChonkStream(prover, capacity);
  }

  get size() {
    return this.added;
  }
  get full() {
    return this.added === this.capacity;
  }

  private step(f: () => Promise<void>) {
    this.chain = this.chain.then(f);
    this.chain.catch(() => {});
  }

  private bytecode(pkg: string) {
    if (!this.bytecodes.has(pkg)) this.bytecodes.set(pkg, new Uint8Array(gunzipSync(Buffer.from(readCircuit(pkg).bytecode, 'base64'))));
    return this.bytecodes.get(pkg)!;
  }

  private async exec(pkg: string, inputs: Record<string, unknown>) {
    const [r, ms] = await timed(() => execPool().execute(pkg, inputs));
    this.execMs += ms;
    return r;
  }

  private async accumulate(pkg: string, kind: number, witness: Uint8Array) {
    const api = this.prover.api;
    const t0 = performance.now();
    await api.chonkLoad({ circuit: { name: pkg, bytecode: this.bytecode(pkg), verificationKey: readVkBinary(pkg) }, kind: kind as any });
    await api.chonkAccumulate({ witness: new Uint8Array(gunzipSync(witness)) });
    const ms = performance.now() - t0;
    this.accumulateMs += ms;
    const b = (this.byPkg[pkg] ??= { n: 0, ms: 0 });
    b.n++;
    b.ms += ms;
    this.accumulated++;
  }

  private kernelRef(pkg: string) {
    const p = this.prover;
    return { prev_vk: readVkJson(pkg).vk, prev_vk_hash: p.manifest.vkHashByPkg[pkg], prev_membership: p.membership(pkg) };
  }

  private async app(pkg: string, r: { witness: Uint8Array; returnValue: any }) {
    await this.accumulate(pkg, CircuitKind.App, r.witness);
    this.group.push({ pkg, out: r.returnValue });
    this.last = r.returnValue;
    if (this.group.length < APPS_PER_KERNEL) return;
    const p = this.prover;
    const common = { vk_tree_root: hex(p.vkTreeRoot), params_hash: hex(p.paramsHash) };
    const appInputs = {
      ...Object.fromEntries(this.group.map((a, j) => [`a${j}`, a.out])),
      vks: this.group.map((a) => readVkJson(a.pkg).vk),
      vk_hashes: this.group.map((a) => p.manifest.vkHashByPkg[a.pkg]),
      memberships: this.group.map((a) => p.membership(a.pkg)),
    };
    const kpkg = this.prev ? 'bk_inner' : 'bk_init';
    const k = await this.exec(kpkg, this.prev ? { ...common, prev: this.prev.out, ...this.kernelRef(this.prev.pkg), ...appInputs } : { ...common, ...appInputs });
    await this.accumulate(kpkg, CircuitKind.Kernel, k.witness);
    this.prev = { pkg: kpkg, out: k.returnValue };
    this.group = [];
  }

  /** Adds the next segment of the run; its witness executes at once, its accumulation in turn. */
  add(seg: { pkg: string; inputs: Record<string, unknown> }) {
    assert(this.added < this.capacity, 'Chonk stream is full');
    assert(seg.pkg.startsWith('seg_'), `${seg.pkg} has no app build`);
    const pkg = `app_${seg.pkg.slice(4)}`;
    const r = this.exec(pkg, seg.inputs);
    r.catch(() => {});
    this.added++;
    this.step(async () => this.app(pkg, await r));
  }

  /** Pads the run, adds the tail and hiding kernels, proves it and its batch tube. */
  async finish(log = console.log): Promise<ChonkRunResult> {
    assert(this.added > 0, 'empty Chonk stream');
    const t0 = performance.now();
    await this.chain;
    const p = this.prover;
    const pads = this.capacity - this.added;
    const padOut = { config_hash: this.last.config_hash, start: this.last.end, end: this.last.end, receipts_root: hex(0n) };
    for (let i = 0; i < pads; i++) await this.app('app_pad', await this.exec('app_pad', { out: padOut }));
    const common = { vk_tree_root: hex(p.vkTreeRoot), params_hash: hex(p.paramsHash) };
    const tail = await this.exec('bk_tail', { ...common, prev: this.prev!.out, ...this.kernelRef(this.prev!.pkg) });
    await this.accumulate('bk_tail', CircuitKind.Kernel, tail.witness);
    const hiding = await this.exec('bk_hiding', { prev: tail.returnValue, prev_vk: readVkJson('bk_tail').vk });
    await this.accumulate('bk_hiding', CircuitKind.HidingKernel, hiding.witness);
    const out = nodeFromNoir(hiding.returnValue);
    const [res, proveMs] = await timed(() => p.api.chonkProve({}));
    const fields = flattenChonkProofFields(res.proof).map(fromBytes32);
    const outFields = nodeFields(out);
    assert(fields.length === SHAPE.CHONK_PROOF_LENGTH + outFields.length, `batch Chonk proof has ${fields.length} fields`);
    assert(outFields.every((x, i) => fields[i] === x), "batch Chonk public inputs != the run's NodeOutput");
    const finishMs = performance.now() - t0;
    const node = await p.proveNode('btube', { chonk_vk: readVkJson('bk_hiding').vk, chonk_proof: fields.slice(outFields.length).map(hex), out: nodeToNoir(out) });
    const chonkMs = this.accumulateMs + proveMs;
    const sizes = { apps: this.added, pads, kernels: this.capacity / APPS_PER_KERNEL + 2 };
    log(
      `  chonk run: ${this.added} apps (+${pads} pads), ${sizes.kernels} kernels: accumulation ${(this.accumulateMs / 1000).toFixed(1)} s, decider ${(proveMs / 1000).toFixed(1)} s, ` +
        `finish ${(finishMs / 1000).toFixed(1)} s from the last segment, batch tube ${(node.ms / 1000).toFixed(1)} s`,
    );
    return { ...node, chonkMs, tubeMs: node.ms, deciderMs: proveMs, chonkExecMs: this.execMs, byPkg: this.byPkg, sizes };
  }
}

/**
 * Provers that work at once, each with its own bb process (P2.26, SPEC.md §9.2): `run` lends one
 * out, or waits for one to come back.
 */
export class ProverPool {
  readonly provers: Prover[];
  /**
   * A prover kept for roots (P2.28), usually with more threads: the root is a fixed 2^23 proof on
   * every batch's critical path. Without one, roots take a pool prover.
   */
  readonly rootProver?: Prover;
  private free: Prover[];
  private waiting: ((p: Prover) => void)[] = [];
  private rootBusy = false;

  constructor(provers: Prover[], rootProver?: Prover) {
    this.provers = provers;
    this.rootProver = rootProver;
    this.free = [...provers];
  }

  /** `n` provers whose bb processes use `threads` threads each, and a root prover of `rootThreads` if not 0. */
  static async create(n: number, threads: number, manifest: any, paramsHash?: bigint, rootThreads = 0): Promise<ProverPool> {
    const { Barretenberg } = await import('@aztec-foundation/bb.js');
    const provers: Prover[] = [];
    for (let i = 0; i < n; i++) provers.push(await Prover.create(await Barretenberg.new({ threads }), manifest, paramsHash));
    const root = rootThreads ? await Prover.create(await Barretenberg.new({ threads: rootThreads }), manifest, paramsHash) : undefined;
    return new ProverPool(provers, root);
  }

  /**
   * Runs `f` on the root prover when it is idle, else on a pool prover: one root prover cannot keep
   * up when roots take longer than the batch interval.
   */
  async runRoot<T>(f: (p: Prover) => Promise<T>): Promise<T> {
    const rp = this.rootProver;
    if (!rp || this.rootBusy) return this.run(f);
    this.rootBusy = true;
    try {
      return await f(rp);
    } finally {
      this.rootBusy = false;
    }
  }

  /** Lends a prover until `release`, waiting for one if all are lent. */
  async acquire(): Promise<Prover> {
    return this.free.pop() ?? (await new Promise<Prover>((ok) => this.waiting.push(ok)));
  }

  release(p: Prover) {
    const next = this.waiting.shift();
    if (next) next(p);
    else this.free.push(p);
  }

  async run<T>(f: (p: Prover) => Promise<T>): Promise<T> {
    const p = await this.acquire();
    try {
      return await f(p);
    } finally {
      this.release(p);
    }
  }

  async destroy() {
    for (const p of this.provers) await p.api.destroy();
    if (this.rootProver) await this.rootProver.api.destroy();
  }
}

/**
 * Proves a batch on a pool (P2.26): every segment at once, since each one's start is the engine's
 * end of the one before; each merge as soon as both its children are proved, in `proveBatch`'s
 * pairing; then the root. The checks are `proveBatch`'s.
 */
export async function proveBatchParallel(pool: ProverPool, w: BatchWitness, log = console.log): Promise<ProvedBatch & { wallMs: number }> {
  const t0 = performance.now();
  const ms: Record<string, number> = {};
  const configHash = pool.provers[0].configHash;
  const leafPs = w.segments.map((seg, i) =>
    pool.run(async (prover) => {
      const node = seg.pkg === 'tube' ? (await prover.proveTube(seg.inputs, seg.clientProofs ?? [], log)).node : await prover.proveNode(seg.pkg, seg.inputs);
      const start = i === 0 ? w.start : w.segments[i - 1].expectedEnd;
      const got = nodeFields(node.out);
      const want = nodeFields({ configHash, start, end: seg.expectedEnd, receiptsRoot: seg.receiptsRoot ?? 0n });
      const bad = got.findIndex((x, j) => x !== want[j]);
      assert(bad < 0, `${seg.label}: circuit output differs from the engine at field ${bad} (${got[bad]} != ${want[bad]})`);
      ms[`${seg.pkg}_${i}`] = node.ms;
      return node;
    }),
  );
  const { top, shape, root } = await mergeAndRoot(pool, w, leafPs, w.segments.map((s) => s.pkg.replace('seg_', '')), ms);
  const leaves = await Promise.all(leafPs);
  const wallMs = performance.now() - t0;
  log(`  ${leaves.length} segments, ${Object.keys(ms).filter((k) => k.startsWith('merge')).length} merges and the root on ${pool.provers.length} provers in ${(wallMs / 1000).toFixed(1)} s (root ${(root.ms / 1000).toFixed(1)} s)`);
  return { ...(await finishBatch(pool.provers[0], w, leaves, top, shape, root, ms)), wallMs };
}

/**
 * The merge tree over a batch's leaf nodes, each merge as soon as both its children are proved,
 * then the root (P2.26). `names` label the leaves in the batch's shape string.
 */
async function mergeAndRoot(pool: ProverPool, w: BatchWitness, leafPs: Promise<ProvedNode>[], names: string[], ms: Record<string, number>) {
  let level: Promise<ProvedNode>[] = leafPs;
  let shape = names;
  if (level.length === 1) {
    level = [level[0], level[0].then((n) => pool.run((p) => p.padding(n.out.end)))];
    shape = [shape[0], 'pad'];
  }
  let merges = 0;
  while (level.length > 2) {
    const next: Promise<ProvedNode>[] = [];
    const nextShape: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        const k = merges++;
        next.push(
          Promise.all([level[i], level[i + 1]]).then(([a, b]) =>
            pool.run(async (p) => {
              const m = await p.merge(a, b);
              ms[`merge_${k}`] = m.ms;
              return m;
            }),
          ),
        );
        nextShape.push(`merge(${shape[i]}, ${shape[i + 1]})`);
      } else {
        next.push(level[i]);
        nextShape.push(shape[i]);
      }
    }
    level = next;
    shape = nextShape;
  }
  const top = await Promise.all(level);
  const root = await pool.runRoot((p) => p.proveRoot(p.rootInputs(top[0], top[1], w.endState, w.withdrawalRecords, w.batchNumber)));
  assert(root.verified, 'root proof does not verify');
  ms.root_prove = root.ms;
  console.log(`  root: witness ${(root.execMs / 1000).toFixed(1)} s, proof ${(root.ms / 1000).toFixed(1)} s, check ${(root.verifyMs / 1000).toFixed(1)} s`);
  return { top, shape, root };
}

/**
 * Proves a batch with Chonk aggregation (SPEC.md §9.2, P2.28): each run of up to `runApps`
 * consecutive X-segments (split evenly) is one Chonk run (segment apps folded by batch kernels) and one batch
 * tube; a P-segment stays a tube of its own. The runs prove at once on the pool, then the merge
 * tree over the runs and the root. Each run's output is checked against the engine's transition.
 */
export async function proveBatchChonk(pool: ProverPool, w: BatchWitness, runApps = CHONK_MAX_APPS, log = console.log): Promise<ProvedBatch & { wallMs: number }> {
  const t0 = performance.now();
  const ms: Record<string, number> = {};
  const configHash = pool.provers[0].configHash;
  assert(runApps >= 1 && runApps <= CHONK_MAX_APPS, `runs of ${runApps} apps`);
  // Each maximal block of consecutive X-segments splits into the fewest runs of at most
  // `runApps`, of near-equal size; a P-segment is a run of its own.
  const runs: number[][] = [];
  const blocks: number[][] = [];
  for (const [i, seg] of w.segments.entries()) {
    const cur = blocks[blocks.length - 1];
    if (seg.pkg !== 'tube' && cur && w.segments[cur[0]].pkg !== 'tube') cur.push(i);
    else blocks.push([i]);
  }
  for (const b of blocks) {
    const k = Math.ceil(b.length / runApps);
    for (let j = 0, at = 0; j < k; j++) {
      const size = Math.floor(b.length / k) + (j < b.length % k ? 1 : 0);
      runs.push(b.slice(at, at + size));
      at += size;
    }
  }
  const roots = w.segments.map((s) => s.receiptsRoot ?? 0n);
  const leafPs = runs.map((run, r) =>
    pool.run(async (prover) => {
      const first = run[0];
      const lastSeg = run[run.length - 1];
      const start = first === 0 ? w.start : w.segments[first - 1].expectedEnd;
      let node: ProvedNode;
      let receiptsRoot: bigint;
      if (w.segments[first].pkg === 'tube') {
        const seg = w.segments[first];
        node = (await prover.proveTube(seg.inputs, seg.clientProofs ?? [], log)).node;
        receiptsRoot = roots[first];
        ms[`tube_${first}`] = node.ms;
      } else {
        const res = await prover.chonkRun(run.map((i) => w.segments[i]), log);
        node = res;
        receiptsRoot = await foldShape(prover.api, chonkRunShape(run), roots);
        ms[`chonk_${r}`] = res.chonkMs;
        ms[`btube_${r}`] = res.tubeMs;
        recordRun(ms, r, res);
      }
      const got = nodeFields(node.out);
      const want = nodeFields({ configHash, start, end: w.segments[lastSeg].expectedEnd, receiptsRoot });
      const bad = got.findIndex((x, j) => x !== want[j]);
      assert(bad < 0, `run ${r} (segments ${first}..${lastSeg}): output differs from the engine at field ${bad} (${got[bad]} != ${want[bad]})`);
      return node;
    }),
  );
  const names = runs.map((run) => (w.segments[run[0]].pkg === 'tube' ? 'tube' : `chonk(${run.length})`));
  const { top, shape, root } = await mergeAndRoot(pool, w, leafPs, names, ms);
  const leaves = await Promise.all(leafPs);
  const wallMs = performance.now() - t0;
  log(`  ${w.segments.length} segments in ${runs.length} runs, ${Object.keys(ms).filter((k) => k.startsWith('merge')).length} merges and the root on ${pool.provers.length} provers in ${(wallMs / 1000).toFixed(1)} s (root ${(root.ms / 1000).toFixed(1)} s)`);
  const receiptShape = mergeShape(runs.map((run) => (w.segments[run[0]].pkg === 'tube' ? run[0] : chonkRunShape(run))));
  return { ...(await finishBatch(pool.provers[0], w, leaves, top, shape, root, ms, receiptShape)), wallMs };
}

/**
 * Proves a batch while it is still open (SPEC.md §9.2, P2.28): the proving service pushes each
 * segment as the engine closes it. Consecutive X-segments go to a ChonkStream of `capacity` apps,
 * which takes a prover from the pool when it opens and accumulates them as they arrive; a full
 * stream is finished and the next one opened, and a P-segment ends the stream and proves as its
 * own tube. When the batch closes, `finish` finishes the last stream (padding it), then the merge
 * tree over the runs and the root: what is left after the close is the last stream's remaining
 * accumulation, its decider and batch tube, any merges, and the root.
 */
export class BatchStream {
  private runs: { segs: number[]; leaf?: Promise<ProvedNode>; stream?: Promise<ChonkStream> }[] = [];
  private segments: SegmentWitness[] = [];
  readonly ms: Record<string, number> = {};
  readonly t0 = performance.now();

  readonly pool: ProverPool;
  readonly capacity: number;
  readonly log: (m: string) => void;

  constructor(pool: ProverPool, capacity = 20, log: (m: string) => void = console.log) {
    this.pool = pool;
    this.capacity = capacity;
    this.log = log;
    assert(capacity % APPS_PER_KERNEL === 0 && capacity > 0 && capacity <= CHONK_MAX_APPS, `stream capacity ${capacity}`);
  }

  private finishRun(r: (typeof this.runs)[number]) {
    if (!r.stream || r.leaf) return;
    const k = this.runs.indexOf(r);
    r.leaf = r.stream.then(async (s) => {
      try {
        const res = await s.finish(this.log);
        this.ms[`chonk_${k}`] = res.chonkMs;
        this.ms[`btube_${k}`] = res.tubeMs;
        recordRun(this.ms, k, res);
        return res;
      } finally {
        this.pool.release(s.prover);
      }
    });
    r.leaf.catch(() => {});
  }

  /** The batch's next segment, in order. */
  push(seg: SegmentWitness) {
    const i = this.segments.length;
    this.segments.push(seg);
    const cur = this.runs[this.runs.length - 1];
    if (seg.pkg === 'tube') {
      if (cur) this.finishRun(cur);
      const leaf = this.pool.run(async (p) => (await p.proveTube(seg.inputs, seg.clientProofs ?? [], this.log)).node);
      leaf.catch(() => {});
      this.runs.push({ segs: [i], leaf });
      return;
    }
    let run = cur;
    if (!run || run.leaf || run.segs.length === this.capacity) {
      if (run) this.finishRun(run);
      const stream = this.pool.acquire().then((p) => ChonkStream.open(p, this.capacity));
      stream.catch(() => {});
      run = { segs: [], stream };
      this.runs.push(run);
    }
    run.segs.push(i);
    run.stream!.then((s) => s.add(seg));
  }

  /** The closed batch (its segments must be the ones pushed, and more may follow here): proves the rest. */
  async finish(w: BatchWitness): Promise<ProvedBatch & { wallMs: number; closeToRootMs: number }> {
    const tClose = performance.now();
    for (const seg of w.segments.slice(this.segments.length)) this.push(seg);
    assert(w.segments.length === this.segments.length && w.segments.every((s, i) => s === this.segments[i]), 'stream segments != the batch');
    assert(this.runs.length > 0, 'empty batch');
    this.finishRun(this.runs[this.runs.length - 1]);
    const configHash = this.pool.provers[0].configHash;
    const roots = w.segments.map((s) => s.receiptsRoot ?? 0n);
    const leafPs = this.runs.map(async (run, r) => {
      const node = await run.leaf!;
      const first = run.segs[0];
      const last = run.segs[run.segs.length - 1];
      const tube = w.segments[first].pkg === 'tube';
      const receiptsRoot = tube ? roots[first] : await foldShape(this.pool.provers[0].api, chonkRunShape(run.segs, this.capacity), roots);
      const start = first === 0 ? w.start : w.segments[first - 1].expectedEnd;
      const got = nodeFields(node.out);
      const want = nodeFields({ configHash, start, end: w.segments[last].expectedEnd, receiptsRoot });
      const bad = got.findIndex((x, j) => x !== want[j]);
      assert(bad < 0, `run ${r} (segments ${first}..${last}): output differs from the engine at field ${bad} (${got[bad]} != ${want[bad]})`);
      return node;
    });
    const names = this.runs.map((run) => (w.segments[run.segs[0]].pkg === 'tube' ? 'tube' : `chonk(${run.segs.length})`));
    const { top, shape, root } = await mergeAndRoot(this.pool, w, leafPs, names, this.ms);
    const leaves = await Promise.all(leafPs);
    const end = performance.now();
    const receiptShape = mergeShape(this.runs.map((run) => (w.segments[run.segs[0]].pkg === 'tube' ? run.segs[0] : chonkRunShape(run.segs, this.capacity))));
    return { ...(await finishBatch(this.pool.provers[0], w, leaves, top, shape, root, this.ms, receiptShape)), wallMs: end - this.t0, closeToRootMs: end - tClose };
  }
}

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
  return finishBatch(prover, w, leaves, level, shape, root, ms);
}

/** Rebuilds a proved batch's header in TS, which must hash to the root's public input. */
async function finishBatch(
  prover: Prover,
  w: BatchWitness,
  leaves: ProvedNode[],
  level: ProvedNode[],
  shape: string[],
  root: Awaited<ReturnType<Prover['proveRoot']>>,
  ms: Record<string, number>,
  receiptShape?: ReceiptShape,
): Promise<ProvedBatch> {
  const api = prover.api;
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
  assert((await daHash(api, w.daPayload)) === header[13], 'flat DA hash != segment sponge');
  const receipts = await receiptsOf(api, w, receiptShape);
  assert(receipts.receiptsRoot === header[17], 'TS receipts tree != the root circuit\'s');

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
