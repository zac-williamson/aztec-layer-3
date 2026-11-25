// Journal replay (P2.24, SPEC.md §5: "Its journal is the witness source"). The sequencer's journal,
// replayed into an engine that builds witnesses, yields the batches to prove. Every journaled
// action must apply again, under its journaled sequence number, and every journaled step must
// succeed: anything else means the sequencer and the witness builder disagree.
//
// With --execute, every segment of the listed batches (0-based) is executed in its circuit and its
// output compared with the engine's (pipeline.ts executeBatch).
//
// Usage: node src/operator/replay.ts <journal> [--execute 0,1]
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { OUT, readJson } from '../lib.ts';
import { type BatchWitness, Prover, assert, executeBatch, newApi } from '../pipeline.ts';
import { Engine, type OracleUpdate, type SignedAction } from '../exchange/engine.ts';
import * as M from '../exchange/model.ts';
import { protocolAccounts, testParams } from '../exchange/params.ts';
import { fromWire } from './wire.ts';

type Entry =
  | { t: 'batch'; n: string }
  | { t: 'key'; c: string; k: string }
  | { t: 'block'; time: string; updates: any[]; fired: number[]; liquidated: string[] }
  | { t: 'priority'; reqs: any[] }
  | { t: 'act'; seq: string; at: string; a: any };

const big = (x: string | number | bigint) => BigInt(x);
const update = (u: any): OracleUpdate => ({ market: big(u.market), price: big(u.price), external: big(u.external), time: big(u.time), sigs: u.sigs.map((s: any) => (s ? { s: big(s.s), e: big(s.e) } : undefined)) });
const request = (q: any): M.Request => ({
  kind: big(q.kind),
  a: big(q.a),
  b: big(q.b),
  ...(q.c !== undefined ? { c: big(q.c) } : {}),
  sender: big(q.sender),
  time: big(q.time),
  ...(q.deposit ? { deposit: { amount: big(q.deposit.amount), salt: big(q.deposit.salt) } } : {}),
});

export type ReplayReport = { entries: number; actions: number; batches: number; segments: number; daFields: number[]; ms: number; executed: number };

/** Replays a journal into a witness-building engine; returns the batches' witnesses and a report. */
export async function replay(path: string, opts: { execute?: number[]; log?: (m: string) => void } = {}): Promise<{ witnesses: BatchWitness[]; report: ReplayReport; engine: Engine }> {
  const log = opts.log ?? ((m: string) => console.log(`[replay] ${m}`));
  const api = await newApi();
  const h = M.hasher(api);
  const { params } = await testParams(h);
  const manifest = opts.execute?.length ? readJson(join(OUT, 'manifest.json')) : undefined;
  const prover = manifest ? await Prover.create(api, manifest, await M.paramsHash(h, params)) : undefined;
  const engine = await Engine.create(api, params, manifest ? BigInt(manifest.vkTree.root) : 0n, await protocolAccounts(h), prover?.clientVks ?? {});
  const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
  const witnesses: BatchWitness[] = [];
  const t0 = performance.now();
  let open = false;
  let actions = 0;
  let queued: { a: SignedAction; seq: bigint }[] = [];

  const flush = async () => {
    if (!queued.length) return;
    const before = engine.rejected.length;
    await engine.trade(queued.map((q) => q.a));
    if (engine.rejected.length !== before) {
      const r = engine.rejected[before];
      throw new Error(`journaled action ${r.action.account}/${r.action.nonce} was refused on replay: ${r.reason}`);
    }
    for (const q of queued) assert(q.a.seq === q.seq, `action journaled as ${q.seq} replayed as ${q.a.seq}`);
    actions += queued.length;
    queued = [];
  };
  const closeBatch = async () => {
    if (!open) return;
    witnesses.push(await engine.endBatch());
    open = false;
  };

  for (const line of lines) {
    const e: Entry = JSON.parse(line);
    if (e.t === 'act') {
      queued.push({ a: fromWire(e.a), seq: big(e.seq) });
      continue;
    }
    await flush();
    if (e.t === 'batch') {
      await closeBatch();
      const r = engine.running;
      await engine.beginBatch(big(e.n), r?.priorityHead ?? 0n, r?.priorityCursor ?? 0n, r?.time ?? 0n);
      open = true;
    } else if (e.t === 'key') {
      engine.keyring.set(big(e.c), big(e.k));
    } else if (e.t === 'block') {
      await engine.block(big(e.time), e.updates.map(update));
      for (const m of e.fired) await engine.fireTriggers([m]);
      for (const i of e.liquidated) await engine.liquidateAccount(big(i));
    } else if (e.t === 'priority') {
      await engine.priority(e.reqs.map(request));
    } else {
      throw new Error(`unknown journal entry ${(e as any).t}`);
    }
  }
  await flush();
  await closeBatch();
  const ms = performance.now() - t0;
  const report: ReplayReport = {
    entries: lines.length,
    actions,
    batches: witnesses.length,
    segments: witnesses.reduce((n, w) => n + w.segments.length, 0),
    daFields: witnesses.map((w) => w.daPayload.length),
    ms: Math.round(ms),
    executed: 0,
  };
  log(`${report.entries} entries: ${actions} signed actions in ${report.batches} batches, ${report.segments} segments, replayed in ${(ms / 1000).toFixed(1)} s (${Math.round((actions * 1000) / ms)} actions/s)`);
  if (opts.execute?.length && prover) {
    for (const i of opts.execute) {
      const w = witnesses[i];
      assert(!!w, `no batch ${i} to execute`);
      await executeBatch(prover, w, (m) => log(`  ${m}`));
      report.executed += w.segments.length;
    }
    log(`executed ${report.executed} segments in their circuits; each output matched the engine`);
  }
  await api.destroy();
  return { witnesses, report, engine };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { values: a, positionals } = parseArgs({ allowPositionals: true, options: { execute: { type: 'string', default: '' } } });
  assert(positionals.length === 1, 'usage: replay.ts <journal> [--execute 0,1]');
  await replay(positionals[0], { execute: a.execute ? a.execute.split(',').map(Number) : [] });
  process.exit(0);
}
