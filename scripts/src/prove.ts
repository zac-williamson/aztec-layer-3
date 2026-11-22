// Proves one synthetic batch natively (no network) and records gate counts and timings
// (SPEC.md §14). Three accounts register and deposit through the priority queue and a block carries
// signed index updates for three markets: three segments, so the merge tree is
// root(merge(block, priority), priority). Writes scripts/out/batch-1.json and
// scripts/out/measurements.json.
import { cpus } from 'node:os';
import { join } from 'node:path';
import { OUT, hex, randomField, readJson, writeJson } from './lib.ts';
import { Engine, signUpdate } from './exchange/engine.ts';
import { keysFromSeed } from './exchange/grumpkin.ts';
import * as M from './exchange/model.ts';
import { protocolAccounts, testParams } from './exchange/params.ts';
import { Prover, assert, newApi, proveBatch, ultraGates } from './pipeline.ts';

async function main() {
  const manifest = readJson(join(OUT, 'manifest.json'));
  const api = await newApi();
  const h = M.hasher(api);
  const { params, oracleSks } = await testParams(h);
  const prover = await Prover.create(api, manifest, await M.paramsHash(h, params));
  const engine = await Engine.create(api, params, BigInt(manifest.vkTree.root), await protocolAccounts(h));
  const now = BigInt(Math.floor(Date.now() / 1000));

  const reqs: M.Request[] = [];
  for (const [i, seed] of [11n, 22n, 33n].entries()) {
    const k = await keysFromSeed(h, seed);
    const encC = await M.encCommitment(h, k.kEnc);
    engine.keyring.set(encC, k.kEnc);
    const sender = randomField();
    reqs.push({ kind: M.KIND.REGISTER, a: await M.masterAuthOf(h, k.pk!.x, k.pk!.y), b: encC, sender, time: now - 60n });
    reqs.push(await M.depositRequest(h, BigInt(M.PROTOCOL_ACCOUNTS + i), 1000n * BigInt(i + 1), sender, now - 50n));
  }
  await engine.beginBatch(1n, 0n, 0n, 0n);
  const update = (m: bigint, price: bigint) => signUpdate(h, engine.domain, oracleSks, [0, 1], m, price, price, now);
  await engine.block(now, [await update(0n, 2000n), await update(1n, 30_000n), await update(2n, 100n)]);
  await engine.priority(reqs);
  const w = await engine.endBatch();
  const batch = await proveBatch(prover, w);
  assert(batch.header[0] === BigInt(manifest.genesisStateRoot), 'genesis state root mismatch');
  console.log(`${batch.shape}: header hash ${hex(batch.headerHash)} matches the root proof's public input`);

  writeJson(join(OUT, 'batch-1.json'), { shape: batch.shape, header: batch.header, headerHash: batch.headerHash, daPayload: batch.daPayload });
  const R = 'noir-rollup-no-zk';
  const gates = Object.fromEntries(
    ['seg_block', 'seg_priority', 'seg_trade', 'seg_refresh', 'seg_liquidate', 'seg_forced', 'seg_trigger', 'padding', 'merge', 'tube'].map((p) => [p, ultraGates(p, R)]).concat([['root', ultraGates('root', 'noir-recursive')]]),
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
