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
import type { Barretenberg } from '@aztec-foundation/bb.js';
import { type BatchWitness, Prover, assert, executeBatch, newApi } from '../pipeline.ts';
import { Engine, type OracleUpdate, type SignedAction } from '../exchange/engine.ts';
import * as M from '../exchange/model.ts';
import { protocolAccounts, testParams } from '../exchange/params.ts';
import { fromWire } from './wire.ts';

type Entry =
  | { t: 'batch'; n: string; ms?: number }
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

/** A batch the journal closed: its witness, its applied actions, and when the sequencer opened and closed it. */
export type ClosedBatch = { witness: BatchWitness; actions: number; openedMs: number; closedMs: number };

/**
 * Feeds journal lines, one at a time, into an engine that builds witnesses; a `batch` line closes
 * the open batch and returns it. Every journaled action must apply under its journaled number.
 */
export class Replayer {
  readonly engine: Engine;
  actions = 0;
  entries = 0;
  private open?: { actions: number; openedMs: number };
  private queued: { a: SignedAction; seq: bigint }[] = [];

  constructor(engine: Engine) {
    this.engine = engine;
  }

  /** An engine for `params`; with a prover, one that can also execute and prove (its VK tree and client circuits). */
  static async create(api: Barretenberg, prover?: Prover): Promise<Replayer> {
    const h = M.hasher(api);
    const { params } = await testParams(h);
    return new Replayer(await Engine.create(api, params, prover?.vkTreeRoot ?? 0n, await protocolAccounts(h), prover?.clientVks ?? {}));
  }

  private async flush() {
    if (!this.queued.length) return;
    const e = this.engine;
    const before = e.rejected.length;
    await e.trade(this.queued.map((q) => q.a));
    if (e.rejected.length !== before) {
      const r = e.rejected[before];
      throw new Error(`journaled action ${r.action.account}/${r.action.nonce} was refused on replay: ${r.reason}`);
    }
    for (const q of this.queued) assert(q.a.seq === q.seq, `action journaled as ${q.seq} replayed as ${q.a.seq}`);
    this.actions += this.queued.length;
    if (this.open) this.open.actions += this.queued.length;
    this.queued = [];
  }

  private async close(atMs: number): Promise<ClosedBatch | undefined> {
    if (!this.open) return undefined;
    const b: ClosedBatch = { witness: await this.engine.endBatch(), actions: this.open.actions, openedMs: this.open.openedMs, closedMs: atMs };
    this.open = undefined;
    return b;
  }

  /** One journal line; resolves with the batch it closed, if it closed one. */
  async feed(line: string): Promise<ClosedBatch | undefined> {
    const e: Entry = JSON.parse(line);
    this.entries++;
    if (e.t === 'act') {
      this.queued.push({ a: fromWire(e.a), seq: big(e.seq) });
      return undefined;
    }
    await this.flush();
    const engine = this.engine;
    if (e.t === 'batch') {
      const now = e.ms ?? Date.now();
      const closed = await this.close(now);
      const r = engine.running;
      await engine.beginBatch(big(e.n), r?.priorityHead ?? 0n, r?.priorityCursor ?? 0n, r?.time ?? 0n);
      this.open = { actions: 0, openedMs: now };
      return closed;
    }
    if (e.t === 'key') engine.keyring.set(big(e.c), big(e.k));
    else if (e.t === 'block') {
      await engine.block(big(e.time), e.updates.map(update));
      for (const m of e.fired) await engine.fireTriggers([m]);
      for (const i of e.liquidated) await engine.liquidateAccount(big(i));
    } else if (e.t === 'priority') await engine.priority(e.reqs.map(request));
    else throw new Error(`unknown journal entry ${(e as any).t}`);
    return undefined;
  }

  /** The end of the journal: applies what is queued and closes the open batch. */
  async finish(): Promise<ClosedBatch | undefined> {
    await this.flush();
    return this.close(Date.now());
  }
}

/** Replays a journal into a witness-building engine; returns the batches' witnesses and a report. */
export async function replay(path: string, opts: { execute?: number[]; log?: (m: string) => void } = {}): Promise<{ witnesses: BatchWitness[]; report: ReplayReport; engine: Engine }> {
  const log = opts.log ?? ((m: string) => console.log(`[replay] ${m}`));
  const api = await newApi();
  const h = M.hasher(api);
  const { params } = await testParams(h);
  const manifest = opts.execute?.length ? readJson(join(OUT, 'manifest.json')) : undefined;
  const prover = manifest ? await Prover.create(api, manifest, await M.paramsHash(h, params)) : undefined;
  const rep = await Replayer.create(api, prover);
  const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
  const witnesses: BatchWitness[] = [];
  const t0 = performance.now();
  for (const line of lines) {
    const b = await rep.feed(line);
    if (b) witnesses.push(b.witness);
  }
  const last = await rep.finish();
  if (last) witnesses.push(last.witness);
  const ms = performance.now() - t0;
  const report: ReplayReport = {
    entries: lines.length,
    actions: rep.actions,
    batches: witnesses.length,
    segments: witnesses.reduce((n, w) => n + w.segments.length, 0),
    daFields: witnesses.map((w) => w.daPayload.length),
    ms: Math.round(ms),
    executed: 0,
  };
  log(`${report.entries} entries: ${rep.actions} signed actions in ${report.batches} batches, ${report.segments} segments, replayed in ${(ms / 1000).toFixed(1)} s (${Math.round((rep.actions * 1000) / ms)} actions/s)`);
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
  return { witnesses, report, engine: rep.engine };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { values: a, positionals } = parseArgs({ allowPositionals: true, options: { execute: { type: 'string', default: '' } } });
  assert(positionals.length === 1, 'usage: replay.ts <journal> [--execute 0,1]');
  await replay(positionals[0], { execute: a.execute ? a.execute.split(',').map(Number) : [] });
  process.exit(0);
}
