// The proving service (P2.27, SPEC.md §5): it follows the sequencer's journal as the operator writes
// it, replays it into the witness builder, and proves each batch the journal closes on a pool of
// provers, several batches at once. For each batch it reports the segments, the proving time and the
// F0→F1 lag: from the batch's opening (its oldest receipt is no older) and from its closing to its
// root proof.
//
// Usage: node src/operator/prover.ts --journal path [--provers 6] [--threads 16] [--from 2]
//                                     [--batches N] [--idle-exit 60] [--agg stream|chonk|merge]
//                                     [--run-apps 20] [--root-threads 0]
//   --root-threads: a separate prover of that many threads for roots (0: roots use the pool).
//   --agg: stream (default, P2.28) folds each batch's segments into Chonk runs of --run-apps
//   apps as the engine closes them, while the batch is open; chonk does the same once the batch
//   has closed; merge is P2.27's RollupHonk merge tree over every segment.
//   --from: the first batch number to prove (earlier batches are replayed, not proved: the demo
//   genesis batch holds every demo account's registration and deposit).
import { closeSync, existsSync, openSync, readSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { OUT, readJson, writeJson } from '../lib.ts';
import { BatchStream, ProverPool, newApi, proveBatchChonk, proveBatchParallel } from '../pipeline.ts';
import * as M from '../exchange/model.ts';
import { testParams } from '../exchange/params.ts';
import { type ClosedBatch, Replayer } from './replay.ts';

const { values: a } = parseArgs({
  options: {
    journal: { type: 'string' },
    provers: { type: 'string', default: '6' },
    threads: { type: 'string', default: '16' },
    from: { type: 'string', default: '2' },
    batches: { type: 'string', default: '0' },
    'idle-exit': { type: 'string', default: '60' },
    agg: { type: 'string', default: 'stream' },
    'run-apps': { type: 'string', default: '20' },
    'root-threads': { type: 'string', default: '0' },
  },
});
const log = (m: string) => console.log(`[prover] ${m}`);
if (!a.journal) throw new Error('--journal is required');
const journal = a.journal;
const manifest = readJson(join(OUT, 'manifest.json'));
const api = await newApi();
const h = M.hasher(api);
const { params } = await testParams(h);
const pool = await ProverPool.create(Number(a.provers), Number(a.threads), manifest, await M.paramsHash(h, params), Number(a['root-threads']));
const rep = await Replayer.create(api, pool.provers[0]);
log(`${a.provers} provers × ${a.threads} threads${a['root-threads'] !== '0' ? `, a root prover of ${a['root-threads']}` : ''}, ${a.agg} aggregation; following ${journal}`);

type Done = { batch: string; actions: number; segments: number; provingMs: number; lagFromOpenMs: number; lagFromCloseMs: number };
const done: Done[] = [];
const inFlight = new Set<Promise<void>>();
const want = Number(a.batches);
let started = 0;

// Streaming: the open batch's stream and how many of its segments it has been given.
let stream: { batch: bigint; s: BatchStream; pushed: number } | undefined;
const streaming = a.agg === 'stream';
const wanted = (n: bigint) => n >= BigInt(a.from!) && !(want && started >= want);

/** Pushes the open batch's new segments to its stream (opening one for a batch to be proved). */
function follow() {
  const e = rep.engine;
  if (!streaming || !e.segments.length) return;
  const n = e.running.batch;
  if (!stream || stream.batch !== n) {
    if (!wanted(n)) return;
    stream = { batch: n, s: new BatchStream(pool, Number(a['run-apps']), () => {}), pushed: 0 };
  }
  for (const seg of e.segments.slice(stream.pushed)) stream.s.push(seg);
  stream.pushed = e.segments.length;
}

function prove(b: ClosedBatch) {
  const n = b.witness.batchNumber;
  const s = stream?.batch === n ? stream.s : undefined;
  if (stream?.batch === n) stream = undefined;
  if (!s && !wanted(n)) return;
  started++;
  const t0 = Date.now();
  const kinds = new Map<string, number>();
  for (const s of b.witness.segments) kinds.set(s.pkg.replace('seg_', ''), (kinds.get(s.pkg.replace('seg_', '')) ?? 0) + 1);
  log(`batch ${n} closed: ${b.actions} actions, ${b.witness.segments.length} segments (${[...kinds].map(([k, v]) => `${v} ${k}`).join(', ')}); proving`);
  const p = (
    s ? s.finish(b.witness)
    : streaming ? new BatchStream(pool, Number(a['run-apps']), () => {}).finish(b.witness)
    : a.agg === 'merge' ? proveBatchParallel(pool, b.witness, () => {})
    : proveBatchChonk(pool, b.witness, Number(a['run-apps']), () => {})
  ).then(
    (r) => {
      const end = Date.now();
      const d: Done = { batch: n.toString(), actions: b.actions, segments: b.witness.segments.length, provingMs: end - t0, lagFromOpenMs: end - b.openedMs, lagFromCloseMs: end - b.closedMs };
      done.push(d);
      log(`batch ${n} proved in ${(d.provingMs / 1000).toFixed(0)} s: lag ${(d.lagFromCloseMs / 1000).toFixed(0)} s from its close, ${(d.lagFromOpenMs / 1000).toFixed(0)} s from its opening; header ${r.headerHash.toString(16).slice(0, 12)}…`);
    },
    (e) => log(`batch ${n} failed: ${e.stack ?? e}`),
  );
  const tracked = p.finally(() => inFlight.delete(tracked));
  inFlight.add(tracked);
}

// Follow the journal: read whatever the operator appended, line by line.
while (!existsSync(journal)) await new Promise((ok) => setTimeout(ok, 200));
const fd = openSync(journal, 'r');
let pos = 0;
let rest = '';
let idleSince = Date.now();
const buf = Buffer.alloc(1 << 22);
for (;;) {
  const size = statSync(journal).size;
  if (size > pos) {
    const n = readSync(fd, buf, 0, Math.min(buf.length, size - pos), pos);
    pos += n;
    const lines = (rest + buf.subarray(0, n).toString()).split('\n');
    rest = lines.pop()!;
    for (const line of lines) if (line) {
      const b = await rep.feed(line);
      if (b) prove(b);
      follow();
    }
    idleSince = Date.now();
  } else if (Date.now() - idleSince > Number(a['idle-exit']) * 1000) break;
  if (want && started >= want && inFlight.size === 0) break;
  await new Promise((ok) => setTimeout(ok, 100));
}
closeSync(fd);
await Promise.all(inFlight);
const sum = (k: keyof Done) => done.map((d) => Number(d[k]));
const avg = (xs: number[]) => (xs.length ? xs.reduce((x, y) => x + y, 0) / xs.length : 0);
log(`${done.length} batches proved, ${sum('actions').reduce((x, y) => x + y, 0)} actions; lag from close mean ${(avg(sum('lagFromCloseMs')) / 1000).toFixed(0)} s, max ${(Math.max(0, ...sum('lagFromCloseMs')) / 1000).toFixed(0)} s; from opening max ${(Math.max(0, ...sum('lagFromOpenMs')) / 1000).toFixed(0)} s`);
writeJson(join(OUT, 'prover.json'), { provers: Number(a.provers), threads: Number(a.threads), agg: a.agg, runApps: Number(a['run-apps']), batches: done });
await pool.destroy();
await api.destroy();
process.exit(0);
