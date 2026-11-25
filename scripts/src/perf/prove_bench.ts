// Proving throughput (P2.26, SPEC.md §14): one batch of a synthetic market, proved on a pool of
// provers. Makers rest a bid and an ask each round and cancel the round before's (seg_quote), and
// takers cross with IOC orders (seg_trade). It reports the batch's segments, the wall time on the
// pool, the sum of every proof's time (what one prover would take), and signed actions proved per
// second of wall time.
// Usage: node src/perf/prove_bench.ts [rounds] [makers] [takers] [provers] [threads]
// AGG=chonk proves with Chonk aggregation (P2.28; RUN_APPS segments a run, default 45) instead of
// the RollupHonk merge tree.
import { join } from 'node:path';
import { OUT, randomField, readJson, writeJson } from '../lib.ts';
import { CHONK_MAX_APPS, ProverPool, newApi, proveBatchChonk, proveBatchParallel } from '../pipeline.ts';
import { Engine, type SignedAction, signAction, signUpdate } from '../exchange/engine.ts';
import { keysFromSeed } from '../exchange/grumpkin.ts';
import * as M from '../exchange/model.ts';
import { protocolAccounts, testParams } from '../exchange/params.ts';
import * as X from '../exchange/rules.ts';

const [ROUNDS, MAKERS, TAKERS, PROVERS, THREADS] = [4, 16, 4, 8, 16].map((d, i) => Number(process.argv[2 + i] ?? d));
const log = (m: string) => console.log(`[prove-bench] ${m}`);
const manifest = readJson(join(OUT, 'manifest.json'));
const api = await newApi();
const h = M.hasher(api);
const { params, oracleSks } = await testParams(h);
const pool = await ProverPool.create(PROVERS, THREADS, manifest, await M.paramsHash(h, params));
const engine = await Engine.create(api, params, BigInt(manifest.vkTree.root), await protocolAccounts(h), pool.provers[0].clientVks);
const users = await Promise.all([...Array(MAKERS + TAKERS).keys()].map(async (i) => ({ index: BigInt(2 + i), addr: randomField(), keys: await keysFromSeed(h, 3000n + BigInt(i)) })));

// Genesis batch (not timed): registrations and deposits.
let now = BigInt(Math.floor(Date.now() / 1000)) - 50_000n;
const update = (time: bigint) => signUpdate(h, engine.domain, oracleSks, [0, 2], 0n, 2000n, 2000n, time);
const reqs: M.Request[] = [];
for (const [i, u] of users.entries()) {
  const encC = await M.encCommitment(h, u.keys.kEnc);
  engine.keyring.set(encC, u.keys.kEnc);
  reqs.push({ kind: M.KIND.REGISTER, a: await M.masterAuthOf(h, u.keys.pk!.x, u.keys.pk!.y), b: encC, sender: u.addr, time: now + BigInt(i) });
  reqs.push(await M.depositRequest(h, u.index, 1n << 40n, u.addr, now + BigInt(i)));
}
await engine.beginBatch(1n, 0n, 0n, 0n);
await engine.block(now, [await update(now - 1n)]);
await engine.priority(reqs);
await engine.endBatch();

// The measured batch.
const end = engine.running;
await engine.beginBatch(2n, end.priorityHead, end.priorityCursor, end.time);
const { BID, ASK } = M.SIDE;
const nonce = new Map(users.map((u) => [u.index, 0n]));
const sign = (u: (typeof users)[number], kind: bigint, p: bigint[]) => {
  const n = nonce.get(u.index)! + 1n;
  nonce.set(u.index, n);
  return signAction(h, engine.domain, u.keys, kind, u.index, n, p);
};
let actions = 0;
const t0 = performance.now();
for (let round = 0; round < ROUNDS; round++) {
  now += 1n;
  await engine.block(now, [await update(now)]);
  const acts: SignedAction[] = [];
  for (const o of engine.orders[0].values()) {
    const m = users.slice(0, MAKERS).find((u) => u.index === o.account);
    if (m) acts.push(await sign(m, X.KIND_ACT.CANCEL, [0n, o.side, o.price, o.seq]));
  }
  for (const [i, m] of users.slice(0, MAKERS).entries()) {
    const spread = 1n + BigInt((round + i) % 5);
    acts.push(await sign(m, X.KIND_ACT.PLACE, [0n, BID, 2000n - spread, 3n, X.TIF.GTC, 0n]));
    acts.push(await sign(m, X.KIND_ACT.PLACE, [0n, ASK, 2000n + spread, 3n, X.TIF.GTC, 0n]));
  }
  for (const [i, t] of users.slice(MAKERS).entries()) {
    const side = (round + i) % 2 ? BID : ASK;
    acts.push(await sign(t, X.KIND_ACT.PLACE, [0n, side, side === BID ? 2010n : 1990n, 2n, X.TIF.IOC, 0n]));
  }
  const before = engine.rejected.length;
  await engine.trade(acts);
  if (engine.rejected.length !== before) throw new Error(`refused: ${engine.rejected.slice(before).map((r) => r.reason).join('; ')}`);
  actions += acts.length;
}
const w = await engine.endBatch();
const witnessMs = performance.now() - t0;
const kinds = new Map<string, number>();
for (const s of w.segments) kinds.set(s.pkg, (kinds.get(s.pkg) ?? 0) + 1);
log(`${actions} signed actions in ${w.segments.length} segments (${[...kinds].map(([k, v]) => `${v} ${k}`).join(', ')}), witnesses in ${(witnessMs / 1000).toFixed(1)} s; ${w.daPayload.length} DA fields`);

const AGG = process.env.AGG ?? 'merge';
const RUN_APPS = Number(process.env.RUN_APPS ?? CHONK_MAX_APPS);
const loadBefore = (await import('node:os')).loadavg()[0];
const b = AGG === 'chonk' ? await proveBatchChonk(pool, w, RUN_APPS, log) : await proveBatchParallel(pool, w, log);
const loadAfter = (await import('node:os')).loadavg()[0];
const sum = Object.entries(b.ms).filter(([k]) => !k.startsWith('acc.') && !k.startsWith('decider.')).reduce((x, [, y]) => x + y, 0);
const acc = Object.keys(b.ms).filter((k) => k.startsWith('acc.') && k.endsWith('.n')).map((k) => k.slice(4, -2));
if (acc.length) log(`accumulation per circuit: ${acc.map((p) => `${p} ${b.ms[`acc.${p}.n`]} × ${(b.ms[`acc.${p}.ms`] / b.ms[`acc.${p}.n`] / 1000).toFixed(2)} s`).join(', ')}`);
const byKind = (prefix: string) => {
  const xs = Object.entries(b.ms).filter(([k]) => k.startsWith(prefix)).map(([, v]) => v);
  return xs.length ? `${xs.length} × ${(xs.reduce((x, y) => x + y, 0) / xs.length / 1000).toFixed(1)} s` : 'none';
};
log(`proofs: seg_quote ${byKind('seg_quote')}, seg_trade ${byKind('seg_trade')}, seg_block ${byKind('seg_block')}, chonk runs ${byKind('chonk')}, batch tubes ${byKind('btube')}, merges ${byKind('merge')}, root ${(b.ms.root_prove / 1000).toFixed(1)} s`);
log(`aggregation ${AGG}${AGG === 'chonk' ? ` (runs of ≤ ${RUN_APPS})` : ''}, shape ${b.shape}; host load ${loadBefore.toFixed(0)} → ${loadAfter.toFixed(0)}`);
log(`wall ${(b.wallMs / 1000).toFixed(1)} s on ${PROVERS} provers × ${THREADS} threads; one prover would take ${(sum / 1000).toFixed(0)} s (${(sum / b.wallMs).toFixed(1)}× faster)`);
log(`${(actions / (b.wallMs / 1000)).toFixed(1)} signed actions proved a second of wall time; ${(actions / (sum / 1000)).toFixed(2)} a second of one prover's time`);
writeJson(join(OUT, `prove-bench-${AGG}.json`), { agg: AGG, runApps: RUN_APPS, shape: b.shape, load: [loadBefore, loadAfter], actions, segments: Object.fromEntries(kinds), wallMs: Math.round(b.wallMs), sumMs: Math.round(sum), provers: PROVERS, threads: THREADS, ms: b.ms });
await pool.destroy();
await api.destroy();
process.exit(0);
