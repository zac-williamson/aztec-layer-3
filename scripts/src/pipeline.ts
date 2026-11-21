// The P0 batch prover (SPEC.md §9.2): client proofs → Chonk IVC → tube → root (with padding).
// Returns the batch header, the root proof and VK for Bridge.settle, and timings and sizes.
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
  fromBytes32,
  hex,
  l3xHash,
  randomField,
  readCircuit,
  readVkBinary,
  readVkJson,
  run,
  timed,
} from './lib.ts';

const CircuitKind = { App: 0, Kernel: 1, HidingKernel: 2 } as const;
const IVC = ['agg_app', 'init_kernel', 'tail_kernel', 'hiding_kernel'] as const;

export type BatchInput = {
  prevAccountsRoot: bigint;
  prevLastTime: bigint;
  batchNumber: bigint;
  minTime: bigint;
  maxTime: bigint;
  priorityStart: bigint;
  priorityHeadStart: bigint;
  priorityEntries: bigint[];
  daPayload: bigint[];
  configHash: bigint;
  /** Number of client proofs folded into the actions hash (all slots carry real proofs). */
  count?: number;
};

export type ProvedBatch = {
  header: bigint[];
  headerHash: bigint;
  rootProof: bigint[];
  rootVk: bigint[];
  daPayload: bigint[];
  ms: Record<string, number>;
  sizes: Record<string, number>;
};

export function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(`check failed: ${msg}`);
}

function ultraGates(pkg: string, target: string): number {
  const out = run(BB, ['gates', '-b', join(TARGET, `${pkg}.json`), '-t', target]);
  const m = out.match(/"circuit_size"\s*:\s*(\d+)/);
  return m ? Number(m[1]) : NaN;
}

export async function newApi(): Promise<Barretenberg> {
  const { Barretenberg } = await import('@aztec-foundation/bb.js');
  return Barretenberg.new({ threads: cpus().length });
}

export async function proveBatch(api: Barretenberg, input: BatchInput, log = console.log): Promise<ProvedBatch> {
  assert(input.priorityEntries.length <= SHAPE.MAX_PRIORITY, 'too many priority entries for P0 shape');
  assert(input.daPayload.length === SHAPE.DA_LEN, 'DA payload has wrong length');
  const ms: Record<string, number> = {};
  const sizes: Record<string, number> = {};

  // 1. Client proofs.
  const count = input.count ?? SHAPE.MAX_CLIENT_PROOFS;
  const client = readCircuit('client_auth');
  const clientNoir = new Noir(client as any);
  const clientBackend = new UltraHonkBackend(client.bytecode, api);
  const proofs: string[][] = [];
  const publicInputs: string[][] = [];
  const clientMs: number[] = [];
  for (let i = 0; i < SHAPE.MAX_CLIENT_PROOFS; i++) {
    const secret = randomField();
    // client_auth asserts hash(DS_AUTH, secret) == auth_binding: this cross-checks l3xHash.
    const { witness } = await clientNoir.execute({
      secret: hex(secret),
      msg: hex(randomField()),
      account_index: hex(BigInt(i + 1)),
      auth_binding: hex(await l3xHash(api, [DS.AUTH, secret])),
    });
    const [pd, t] = await timed(() => clientBackend.generateProof(witness, { verifierTarget: 'noir-recursive' }));
    clientMs.push(t);
    proofs.push(bytesToFields(pd.proof).map(hex));
    publicInputs.push(pd.publicInputs);
  }
  sizes.client_proof_fields = proofs[0].length;
  assert(sizes.client_proof_fields === 458, `client proof has ${sizes.client_proof_fields} fields, expected 458`);
  ms.client_proof_mean = clientMs.reduce((a, b) => a + b, 0) / clientMs.length;
  log(`client proofs: ${clientMs.length} × ${ms.client_proof_mean.toFixed(0)} ms`);

  // 2. IVC witnesses.
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

  // 3. Chonk.
  const chonk = new AztecClientBackend(
    IVC.map((p) => new Uint8Array(gunzipSync(Buffer.from(circuits[p].bytecode, 'base64')))),
    api,
    [...IVC],
    [CircuitKind.App, CircuitKind.Kernel, CircuitKind.Kernel, CircuitKind.HidingKernel],
  );
  const ivcGates = await chonk.gates();
  IVC.forEach((p, i) => (sizes[`${p}_mega_gates`] = ivcGates[i]));
  const [chonkRes, chonkMs] = await timed(() =>
    chonk.prove(
      [agg.witness, init.witness, tail.witness, hiding.witness].map((w) => new Uint8Array(gunzipSync(w))),
      IVC.map(readVkBinary),
    ),
  );
  ms.chonk_prove = chonkMs;
  assert(await chonk.verify(chonkRes.proof, chonkRes.vk), 'Chonk proof does not verify natively');
  const chonkFields = chonkRes.proofFields.map(fromBytes32);
  sizes.chonk_proof_fields_total = chonkFields.length;
  assert(chonkFields.length === SHAPE.CHONK_PROOF_LENGTH + 2, `Chonk proof has ${chonkFields.length} fields`);
  assert(
    chonkFields[0] === BigInt(aggOut.actions_hash) && chonkFields[1] === BigInt(aggOut.count),
    'Chonk public inputs are not the leading fields',
  );
  const chonkVk = bytesToFields(chonkRes.vk);
  const hidingVk = readVkJson('hiding_kernel').vk.map((x) => BigInt(x));
  assert(chonkVk.length === hidingVk.length && chonkVk.every((x, i) => x === hidingVk[i]), 'Chonk VK != hiding kernel VK');
  log(`chonk: ${chonkMs.toFixed(0)} ms (${IVC.map((p, i) => `${p}=${ivcGates[i]}`).join(' ')})`);

  // 4. Tube.
  const tubeC = readCircuit('tube');
  const tubeW = await new Noir(tubeC as any).execute({
    chonk_vk: chonkVk.map(hex),
    chonk_proof: chonkFields.slice(2).map(hex),
    output: aggOut,
  });
  const tubeBackend = new UltraHonkBackend(tubeC.bytecode, api);
  const [tubeProof, tubeMs] = await timed(() => tubeBackend.generateProof(tubeW.witness, { verifierTarget: 'noir-rollup-no-zk' }));
  ms.tube_prove = tubeMs;
  assert(await tubeBackend.verifyProof(tubeProof, { verifierTarget: 'noir-rollup-no-zk' }), 'tube proof does not verify');
  const tubeFields = bytesToFields(tubeProof.proof);
  sizes.tube_proof_fields = tubeFields.length;
  sizes.tube_gates = ultraGates('tube', 'noir-rollup-no-zk');
  log(`tube: ${tubeMs.toFixed(0)} ms (${sizes.tube_gates} gates)`);

  // 5. Padding segment.
  const padC = readCircuit('padding');
  const padW = await new Noir(padC as any).execute({ output: { actions_hash: hex(0n), count: 0 } });
  const [padProof, padMs] = await timed(() =>
    new UltraHonkBackend(padC.bytecode, api).generateProof(padW.witness, { verifierTarget: 'noir-rollup-no-zk' }),
  );
  ms.padding_prove = padMs;

  // 6. Root.
  const n = input.priorityEntries.length;
  const rootC = readCircuit('root');
  const rootW = await new Noir(rootC as any).execute({
    tube_vk: readVkJson('tube').vk,
    tube_proof: tubeFields.map(hex),
    agg: aggOut,
    padding_vk: readVkJson('padding').vk,
    padding_proof: bytesToFields(padProof.proof).map(hex),
    prev_accounts_root: hex(input.prevAccountsRoot),
    prev_last_time: input.prevLastTime.toString(),
    batch_number: input.batchNumber.toString(),
    min_time: input.minTime.toString(),
    max_time: input.maxTime.toString(),
    priority_start: input.priorityStart.toString(),
    priority_n: n,
    priority_head_start: hex(input.priorityHeadStart),
    priority_entries: [...input.priorityEntries, ...Array<bigint>(SHAPE.MAX_PRIORITY - n).fill(0n)].map(hex),
    da_payload: input.daPayload.map(hex),
    config_hash: hex(input.configHash),
  });
  const rootBackend = new UltraHonkBackend(rootC.bytecode, api);
  const [rootProof, rootMs] = await timed(() => rootBackend.generateProof(rootW.witness, { verifierTarget: 'noir-recursive' }));
  ms.root_prove = rootMs;
  assert(await rootBackend.verifyProof(rootProof, { verifierTarget: 'noir-recursive' }), 'root proof does not verify');
  const rootFields = bytesToFields(rootProof.proof);
  sizes.root_proof_fields = rootFields.length;
  sizes.root_gates = ultraGates('root', 'noir-recursive');
  log(`root: ${rootMs.toFixed(0)} ms (${sizes.root_gates} gates)`);

  // 7. Rebuild the header in TS; it must hash to the root's public input.
  const actions = BigInt(aggOut.actions_hash);
  const prevState = await l3xHash(api, [DS.STATE, input.prevAccountsRoot, input.priorityStart, input.batchNumber - 1n, input.prevLastTime]);
  let head = input.priorityHeadStart;
  for (const e of input.priorityEntries) head = await l3xHash(api, [DS.PRIORITY, head, e]);
  const newAccounts = await l3xHash(api, [DS.ACCOUNTS, input.prevAccountsRoot, actions]);
  const priorityEnd = input.priorityStart + BigInt(n);
  const newState = await l3xHash(api, [DS.STATE, newAccounts, priorityEnd, input.batchNumber, input.maxTime]);
  const daHash = await l3xHash(api, [DS.DA, ...input.daPayload]);
  const header = [
    prevState, newState, newAccounts, input.batchNumber, input.minTime, input.maxTime, input.priorityStart, priorityEnd,
    input.priorityHeadStart, head, 0n, 0n, actions, daHash, 0n, input.configHash,
  ];
  const headerHash = await l3xHash(api, [DS.HEADER, ...header]);
  assert(headerHash === BigInt(rootW.returnValue as string), 'TS header hash != root circuit output');
  assert(headerHash === BigInt(rootProof.publicInputs[0]), 'TS header hash != root proof public input');

  return {
    header,
    headerHash,
    rootProof: rootFields,
    rootVk: readVkJson('root').vk.map((x) => BigInt(x)),
    daPayload: input.daPayload,
    ms,
    sizes,
  };
}
