// Engine throughput (SPEC.md §14): signed actions a second through the engine, which builds every
// segment's witness, without executing or proving circuits. A synthetic market 0: makers requote a
// bid and an ask around the mark every block and cancel the previous pair, takers send crossing IOC
// orders, and a ladder of resting orders sets the book's depth.
// Usage: node src/perf/engine_bench.ts [rounds] [makers] [takers] [depth]
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { OUT, randomField, readJson } from '../lib.ts';
import { newApi } from '../pipeline.ts';
import { Engine, type SignedAction, signAction, signUpdate } from '../exchange/engine.ts';
import { keysFromSeed } from '../exchange/grumpkin.ts';
import * as M from '../exchange/model.ts';
import { protocolAccounts, testParams } from '../exchange/params.ts';
import { native } from '../native.ts';
import * as X from '../exchange/rules.ts';

const [ROUNDS, MAKERS, TAKERS, DEPTH] = [30, 16, 8, 0].map((d, i) => Number(process.argv[2 + i] ?? d));
const api = await newApi();
const h = M.hasher(api);
// The VK tree root only enters witnesses, which this benchmark never executes.
const vkTreeRoot = existsSync(join(OUT, 'manifest.json')) ? BigInt(readJson(join(OUT, 'manifest.json')).vkTree.root) : 0n;
const { params, oracleSks } = await testParams(h);
// LITE=1: the sequencer's engine (P2.24), with the gateway's checks made first, in parallel.
const LITE = !!process.env.LITE;
const engine = await Engine.create(api, params, vkTreeRoot, await protocolAccounts(h), {}, { lite: LITE });
const users = await Promise.all([...Array(MAKERS + TAKERS + 1).keys()].map(async (i) => ({ index: BigInt(2 + i), addr: randomField(), keys: await keysFromSeed(h, 1000n + BigInt(i)) })));
const makers = users.slice(0, MAKERS);
const takers = users.slice(MAKERS, MAKERS + TAKERS);
const ladder = users[MAKERS + TAKERS];

let now = BigInt(Math.floor(Date.now() / 1000)) - 100_000n;
const reqs: M.Request[] = [];
for (const [i, u] of users.entries()) {
  const encC = await M.encCommitment(h, u.keys.kEnc);
  engine.keyring.set(encC, u.keys.kEnc);
  reqs.push({ kind: M.KIND.REGISTER, a: await M.masterAuthOf(h, u.keys.pk!.x, u.keys.pk!.y), b: encC, sender: u.addr, time: now + BigInt(i) });
}
for (const [i, u] of users.entries()) reqs.push(await M.depositRequest(h, u.index, 1n << 40n, u.addr, now + 500n + BigInt(i)));
now += 1000n;
await engine.beginBatch(1n, 0n, 0n, 0n);
const update = (price: bigint) => signUpdate(h, engine.domain, oracleSks, [0, 2], 0n, price, price, now - 1n);
await engine.block(now, [await update(2000n)]);
await engine.priority(reqs);

const { BID, ASK } = M.SIDE;
const { PLACE, CANCEL } = X.KIND_ACT;
const nonce = (u: (typeof users)[number]) => engine.actv.get(u.index)!.nonce;
const stats = { actions: 0, rejected: 0, tradeMs: 0, blockMs: 0, segments: 0, signMs: 0, gatewayMs: 0 };
const timed = async <T>(key: 'tradeMs' | 'blockMs' | 'signMs' | 'gatewayMs', fn: () => Promise<T>) => {
  const t0 = performance.now();
  const v = await fn();
  stats[key] += performance.now() - t0;
  return v;
};

// The ladder: DEPTH bids and DEPTH asks between 1% and 4% from the mark, which never trade.
if (DEPTH > 0) {
  let n = nonce(ladder);
  const acts: SignedAction[] = [];
  for (let i = 0; i < DEPTH; i++) {
    const off = 20n + BigInt(i % 60);
    acts.push(await signAction(h, engine.domain, ladder.keys, PLACE, ladder.index, ++n, [0n, BID, 2000n - off, 1n, X.TIF.GTC, 0n]));
    acts.push(await signAction(h, engine.domain, ladder.keys, PLACE, ladder.index, ++n, [0n, ASK, 2000n + off, 1n, X.TIF.GTC, 0n]));
  }
  await engine.trade(acts);
}

let batch = 1n;
const rejectedBefore = engine.rejected.length;
for (let round = 0; round < ROUNDS; round++) {
  now += 1n;
  await timed('blockMs', async () => engine.block(now, [await update(2000n)]));
  // Cancels of each maker's resting quotes, new quotes, then takers crossing them.
  const acts: SignedAction[] = [];
  await timed('signMs', async () => {
    const next = new Map(users.map((u) => [u.index, nonce(u)]));
    const sign = (u: (typeof users)[number], kind: bigint, p: bigint[]) => {
      const n = next.get(u.index)! + 1n;
      next.set(u.index, n);
      return signAction(h, engine.domain, u.keys, kind, u.index, n, p);
    };
    for (const o of engine.orders[0].values()) {
      const m = makers.find((u) => u.index === o.account);
      if (m) acts.push(await sign(m, CANCEL, [0n, o.side, o.price, o.seq]));
    }
    for (const [i, m] of makers.entries()) {
      const spread = 1n + BigInt((round + i) % 5);
      acts.push(await sign(m, PLACE, [0n, BID, 2000n - spread, 3n, X.TIF.GTC, 0n]));
      acts.push(await sign(m, PLACE, [0n, ASK, 2000n + spread, 3n, X.TIF.GTC, 0n]));
    }
    for (const [i, t] of takers.entries()) {
      const side = (round + i) % 2 ? BID : ASK;
      acts.push(await sign(t, PLACE, [0n, side, side === BID ? 2010n : 1990n, 2n, X.TIF.IOC, 0n]));
    }
  });
  if (LITE) {
    await timed('gatewayMs', async () => {
      const flat = acts.flatMap((a) => [a.kind, a.account, a.keyId, a.nonce, ...a.p, a.pk.x, a.pk.y, a.sig.s, a.sig.e]);
      const out = await native.prepareActions(M.DS.ACTION, M.DS.MAUTH, engine.domain, flat);
      acts.forEach((a, i) => (a.prepared = { msg: out[3 * i], masterAuth: out[3 * i + 1], ok: out[3 * i + 2] === 1n }));
    });
  }
  const segs = engine.segments.length;
  await timed('tradeMs', () => engine.trade(acts));
  stats.segments += engine.segments.length - segs;
  stats.actions += acts.length;
  if ((round + 1) % 10 === 0) {
    // Close the batch so its witnesses do not accumulate; the next starts where it ended.
    if (!LITE) await engine.endBatch();
    const end = engine.running;
    await engine.beginBatch(++batch, end.priorityHead, end.priorityCursor, end.time);
  }
}
stats.rejected = engine.rejected.length - rejectedBefore;
const per = (ms: number) => ((ms * 1000) / stats.actions).toFixed(0);
console.log(
  `[engine-bench] ${LITE ? 'sequencer mode: ' : ''}${stats.actions} actions in ${ROUNDS} blocks (${MAKERS} makers, ${TAKERS} takers, ${engine.orders[0].size} resting orders at the end), ${stats.rejected} refused, ${stats.segments} trade segments`,
);
console.log(`[engine-bench] trade: ${stats.tradeMs.toFixed(0)} ms, ${per(stats.tradeMs)} µs an action, ${Math.round((stats.actions * 1000) / stats.tradeMs)} actions/s`);
console.log(`[engine-bench] blocks: ${(stats.blockMs / ROUNDS).toFixed(1)} ms each; signing (client side): ${per(stats.signMs)} µs an action`);
if (LITE) console.log(`[engine-bench] gateway checks: ${per(stats.gatewayMs)} µs an action of wall time on ${native.cryptoThreads()} crypto threads`);
if (stats.rejected) console.log(`[engine-bench] refusals: ${[...new Set(engine.rejected.slice(rejectedBefore).map((r) => r.reason))].join('; ')}`);
process.exit(0);
