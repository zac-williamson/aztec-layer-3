// Proves one synthetic batch natively (no network) and records measurements M1–M4 and M7
// (SPEC.md §14). The batch has a P-segment (10 client proofs → Chonk → tube) and two X-segments,
// so the merge tree is root(merge(tube, x), x). Writes scripts/out/batch-1.json and
// scripts/out/measurements.json.
import { cpus } from 'node:os';
import { join } from 'node:path';
import { DS, OUT, SHAPE, hex, l3xHash, randomField, readJson, writeJson } from './lib.ts';
import { Prover, assert, batchStart, newApi, proveBatch, ultraGates } from './pipeline.ts';

const rand = (n: number) => Array.from({ length: n }, () => randomField());

async function main() {
  const manifest = readJson(join(OUT, 'manifest.json'));
  const api = await newApi();
  const prover = await Prover.create(api, manifest);
  const now = BigInt(Math.floor(Date.now() / 1000));
  const sender = randomField();
  const entries: bigint[] = [];
  for (let i = 0; i < 2; i++) entries.push(await l3xHash(api, [DS.PRIORITY_ENTRY, randomField(), sender, now - 30n]));

  const batch = await proveBatch(prover, {
    batchNumber: 1n,
    start: batchStart(BigInt(manifest.genesisTrees), 0n, 0n, 0n),
    accountsRoot: 0n,
    otherRoot: 0n,
    segments: [
      { kind: 'p', count: Number(process.env.COUNT ?? SHAPE.MAX_CLIENT_PROOFS) },
      { kind: 'x', blockTime: now - 30n, entries, daFields: rand(40) },
      { kind: 'x', blockTime: now, daFields: rand(20) },
    ],
  });
  assert(batch.header[0] === BigInt(manifest.genesisStateRoot), 'genesis state root mismatch');
  console.log(`${batch.shape}: header hash ${hex(batch.headerHash)} matches the root proof's public input`);

  writeJson(join(OUT, 'batch-1.json'), {
    shape: batch.shape,
    header: batch.header,
    headerHash: batch.headerHash,
    rootProof: batch.rootProof,
    rootVk: batch.rootVk,
    daPayload: batch.daPayload,
    priorityEntries: entries,
  });
  const R = 'noir-rollup-no-zk';
  const gates = {
    tube: ultraGates('tube', R),
    x_segment: ultraGates('x_segment', R),
    padding: ultraGates('padding', R),
    merge: ultraGates('merge', R),
    root: ultraGates('root', 'noir-recursive'),
  };
  const measurements = {
    threads: cpus().length,
    machine: `${process.platform}-${process.arch}`,
    shape: batch.shape,
    ms: Object.fromEntries(Object.entries(batch.ms).map(([k, v]) => [k, Math.round(v)])),
    sizes: { ...batch.sizes, gates },
    derived: {
      agg_app_mega_gates_per_client_proof: Math.round(batch.sizes.agg_app_mega_gates / SHAPE.MAX_CLIENT_PROOFS),
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
