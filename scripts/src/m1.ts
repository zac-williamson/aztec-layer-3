// M1 (SPEC.md §14): the cost of verifying MAX_CLIENT_PROOFS UltraHonk ZK client proofs and ending
// with a RollupHonk proof that can enter the merge tree, two ways, on the same proofs:
//   chonk: agg_app inside the Chonk IVC (OINK/HN folding in Mega), then the tube;
//   ultra: agg_ultra, the same checks in one UltraHonk circuit proved with the rollup target.
// Writes scripts/out/m1.json.
import { cpus } from 'node:os';
import { join } from 'node:path';
import { UltraHonkBackend } from '@aztec-foundation/bb.js';
import { Noir } from '@aztec-foundation/noir-noir_js';
import { Engine } from './exchange/engine.ts';
import * as M from './exchange/model.ts';
import { protocolAccounts, testParams } from './exchange/params.ts';
import { OUT, SHAPE, readCircuit, readJson, readVkJson, timed, writeJson } from './lib.ts';
import { Prover, assert, newApi, ultraGates } from './pipeline.ts';

async function main() {
  const manifest = readJson(join(OUT, 'manifest.json'));
  const api = await newApi();
  const h = M.hasher(api);
  const { params } = await testParams(h);
  const prover = await Prover.create(api, manifest, await M.paramsHash(h, params));
  const n = SHAPE.MAX_CLIENT_PROOFS;

  // Chonk path: IVC over n client proofs, then the tube, for a P-segment at genesis. agg_app
  // verifies all n proof slots and the tube's circuit is fixed, so the cost does not depend on how
  // many of the proofs carry actions; this segment applies none.
  const engine = await Engine.create(api, params, prover.vkTreeRoot, await protocolAccounts(h), prover.clientVkHash);
  await engine.beginBatch(1n, 0n, 0n, 0n);
  await engine.provenSegment([], true);
  const tube = await prover.proveTube(engine.segments[0].inputs, []);
  const chonk = {
    agg_app_mega_gates: tube.chonk.sizes.agg_app_mega_gates,
    kernel_mega_gates: ['init_kernel', 'tail_kernel', 'hiding_kernel'].map((k) => tube.chonk.sizes[`${k}_mega_gates`]),
    ivc_ms: Math.round(tube.chonk.ms.chonk_prove),
    tube_gates: ultraGates('tube', 'noir-rollup-no-zk'),
    tube_ms: Math.round(tube.node.ms),
    total_ms: Math.round(tube.chonk.ms.chonk_prove + tube.node.ms),
  };
  console.log(`chonk path: IVC ${chonk.ivc_ms} ms + tube ${chonk.tube_ms} ms = ${chonk.total_ms} ms`);

  // UltraHonk path: the same verification in one circuit.
  const { proofs, publicInputs } = await prover.randomClientProofs();
  const c = readCircuit('agg_ultra');
  const { witness } = await new Noir(c as any).execute({
    client_vk: readVkJson('client_auth').vk,
    proofs,
    public_inputs: publicInputs,
    count: n,
  });
  const backend = new UltraHonkBackend(c.bytecode, api);
  const [pd, ms] = await timed(() => backend.generateProof(witness, { verifierTarget: 'noir-rollup-no-zk' }));
  assert(await backend.verifyProof(pd, { verifierTarget: 'noir-rollup-no-zk' }), 'agg_ultra proof does not verify');
  const gates = ultraGates('agg_ultra', 'noir-rollup-no-zk');
  const ultra = { gates, gates_per_client_proof: Math.round(gates / n), ms: Math.round(ms) };
  console.log(`ultra path: ${gates} gates, ${ultra.ms} ms`);

  const result = {
    threads: cpus().length,
    machine: `${process.platform}-${process.arch}`,
    client_proofs: n,
    chonk,
    ultra,
    ratio_ultra_over_chonk_ms: Number((ultra.ms / chonk.total_ms).toFixed(2)),
  };
  writeJson(join(OUT, 'm1.json'), result);
  console.log(JSON.stringify(result, null, 2));
  await api.destroy();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
