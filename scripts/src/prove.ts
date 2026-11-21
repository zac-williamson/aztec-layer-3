// Proves one synthetic P0 batch natively (no network) and records measurements M1–M4
// (SPEC.md §14). Writes scripts/out/batch-1.json and scripts/out/measurements.json.
import { cpus } from 'node:os';
import { join } from 'node:path';
import { DS, OUT, SHAPE, hex, l3xHash, randomField, readJson, writeJson } from './lib.ts';
import { assert, newApi, proveBatch } from './pipeline.ts';

async function main() {
  const manifest = readJson(join(OUT, 'manifest.json'));
  const api = await newApi();
  const now = BigInt(Math.floor(Date.now() / 1000));
  const sender = randomField();
  const entries: bigint[] = [];
  for (let i = 0; i < 2; i++) entries.push(await l3xHash(api, [DS.PRIORITY_ENTRY, randomField(), sender, now - 30n]));

  const batch = await proveBatch(api, {
    prevAccountsRoot: 0n,
    prevLastTime: 0n,
    batchNumber: 1n,
    minTime: now - 60n,
    maxTime: now,
    priorityStart: 0n,
    priorityHeadStart: 0n,
    priorityEntries: entries,
    daPayload: Array.from({ length: SHAPE.DA_LEN }, () => randomField()),
    configHash: BigInt(manifest.configHash),
    count: Number(process.env.COUNT ?? SHAPE.MAX_CLIENT_PROOFS),
  });
  assert(batch.header[0] === BigInt(manifest.genesisStateRoot), 'genesis state root mismatch');
  console.log(`header hash ${hex(batch.headerHash)} matches the root proof's public input`);

  writeJson(join(OUT, 'batch-1.json'), {
    header: batch.header,
    headerHash: batch.headerHash,
    rootProof: batch.rootProof,
    rootVk: batch.rootVk,
    daPayload: batch.daPayload,
    priorityEntries: entries,
  });
  const measurements = {
    threads: cpus().length,
    machine: `${process.platform}-${process.arch}`,
    ms: Object.fromEntries(Object.entries(batch.ms).map(([k, v]) => [k, Math.round(v)])),
    sizes: batch.sizes,
    derived: {
      agg_app_mega_gates_per_client_proof: Math.round(batch.sizes.agg_app_mega_gates / SHAPE.MAX_CLIENT_PROOFS),
      pipeline_ms_excluding_client_proofs: Math.round(
        batch.ms.chonk_prove + batch.ms.tube_prove + batch.ms.padding_prove + batch.ms.root_prove,
      ),
    },
  };
  writeJson(join(OUT, 'measurements.json'), measurements);
  console.log(JSON.stringify(measurements, null, 2));
  await api.destroy();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
