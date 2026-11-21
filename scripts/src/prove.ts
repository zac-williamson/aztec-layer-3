// Proves one synthetic P1 batch natively (no network) and records gate counts and timings
// (SPEC.md §14). Two accounts register and deposit through the priority queue and a block carries
// a signed index update: three segments, so the merge tree is root(merge(block, priority),
// priority). Writes scripts/out/batch-1.json and scripts/out/measurements.json.
import { cpus } from 'node:os';
import { join } from 'node:path';
import { OUT, hex, randomField, readJson, writeJson } from './lib.ts';
import { Engine } from './p1/engine.ts';
import { keysFromSeed, sign } from './p1/grumpkin.ts';
import * as M from './p1/model.ts';
import { testParams } from './p1/params.ts';
import { Prover, assert, newApi, proveBatch, ultraGates } from './pipeline.ts';

async function main() {
  const manifest = readJson(join(OUT, 'manifest.json'));
  const api = await newApi();
  const h = M.hasher(api);
  const { params, oracleSk } = await testParams(h);
  const prover = await Prover.create(api, manifest, await M.paramsHash(h, params));
  const engine = await Engine.create(api, params, BigInt(manifest.vkTree.root));
  const now = BigInt(Math.floor(Date.now() / 1000));

  const reqs: M.Request[] = [];
  for (const [i, seed] of [11n, 22n, 33n].entries()) {
    const k = await keysFromSeed(h, seed);
    const encC = await M.encCommitment(h, k.kEnc);
    engine.keyring.set(encC, k.kEnc);
    const sender = randomField();
    reqs.push({ kind: M.KIND.REGISTER, a: await M.masterAuthOf(h, k.pk!.x, k.pk!.y), b: encC, sender, time: now - 60n });
    reqs.push({ kind: M.KIND.DEPOSIT, a: BigInt(i), b: 1000n * BigInt(i + 1), sender, time: now - 50n });
  }
  await engine.beginBatch(1n, 0n, 0n, 0n);
  await engine.block(now, { price: 2000n, time: now, sig: await sign(h, oracleSk, await M.oracleMessage(h, engine.domain, 2000n, now)) });
  await engine.priority(reqs);
  const w = await engine.endBatch();
  const batch = await proveBatch(prover, w);
  assert(batch.header[0] === BigInt(manifest.genesisStateRoot), 'genesis state root mismatch');
  console.log(`${batch.shape}: header hash ${hex(batch.headerHash)} matches the root proof's public input`);

  writeJson(join(OUT, 'batch-1.json'), { shape: batch.shape, header: batch.header, headerHash: batch.headerHash, daPayload: batch.daPayload });
  const R = 'noir-rollup-no-zk';
  const gates = Object.fromEntries(
    ['seg_block', 'seg_priority', 'padding', 'merge', 'tube'].map((p) => [p, ultraGates(p, R)]).concat([['root', ultraGates('root', 'noir-recursive')]]),
  );
  const measurements = {
    threads: cpus().length,
    machine: `${process.platform}-${process.arch}`,
    shape: batch.shape,
    ms: Object.fromEntries(Object.entries(batch.ms).map(([k, v]) => [k, Math.round(v)])),
    gates,
    daFields: batch.daPayload.length,
  };
  writeJson(join(OUT, 'measurements.json'), measurements);
  console.log(JSON.stringify(measurements, null, 2));
  await api.destroy();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
