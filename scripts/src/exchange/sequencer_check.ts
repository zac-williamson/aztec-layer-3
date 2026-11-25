// Sequencer mode against the witness builder (P2.24, SPEC.md §5): one seeded random workload, with
// valid and refused actions mixed, through an engine in sequencer mode (no trees, DA or witnesses;
// atomic actions undone through its journal) and through one that builds every witness. After
// every step, both must have refused the same actions for the same reasons and hold the same state
// in everything that decides outcomes. Usage: node src/exchange/sequencer_check.ts [rounds] [seed]
import { randomField } from '../lib.ts';
import { assert, newApi } from '../pipeline.ts';
import { Engine, type SignedAction, signAction, signUpdate } from './engine.ts';
import { keysFromSeed } from './grumpkin.ts';
import * as M from './model.ts';
import { protocolAccounts, testParams } from './params.ts';
import * as X from './rules.ts';

const ROUNDS = Number(process.argv[2] ?? 60);
let seed = Number(process.argv[3] ?? 0x13579b);
/** mulberry32: a seeded generator, so a failure reproduces. */
const rnd = () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = <T>(xs: T[]) => xs[Math.floor(rnd() * xs.length)];
const int = (lo: number, hi: number) => BigInt(lo + Math.floor(rnd() * (hi - lo + 1)));
const log = (m: string) => console.log(`[sequencer-check] ${m}`);

const api = await newApi();
const h = M.hasher(api);
const { params, oracleSks } = await testParams(h);
const protocol = await protocolAccounts(h);
const full = await Engine.create(api, params, 0n, protocol);
const lite = await Engine.create(api, params, 0n, protocol, {}, { lite: true });
const engines = [full, lite];

const N_USERS = 10;
const users = await Promise.all([...Array(N_USERS).keys()].map(async (i) => ({ index: BigInt(2 + i), addr: randomField(), keys: await keysFromSeed(h, 7000n + BigInt(i)), session: await keysFromSeed(h, 8000n + BigInt(i)) })));
let now = BigInt(Math.floor(Date.now() / 1000)) - 200_000n;

/** Everything in an engine's state that decides outcomes: not leaves, roots, blinds or DA. */
function semantic(e: Engine) {
  const entries = <V>(m: Map<bigint, V>) => [...m].sort(([a], [b]) => (a < b ? -1 : 1));
  return JSON.stringify(
    {
      accts: entries(e.accts).map(([k, r]) => [k, r.pub, { ...r.priv, blind: 0n }, r.kEnc]),
      actv: entries(e.actv).map(([k, a]) => [k, { ...a, keysRoot: 0n }]),
      orders: e.orders.map(entries),
      triggers: e.triggers.map(entries),
      keys: entries(e.keys).map(([k, v]) => [k, [...v].sort(([a], [b]) => a - b)]),
      markets: e.markets.map((m) => ({ ...m, bookRoot: 0n, triggerRoot: 0n })),
      scalars: [e.feesPending, e.insurancePending, e.insuranceMicro, e.lastSeq, e.numAccounts, e.refreshCursor, e.cycleStart, e.running.time, e.running.priorityCursor],
      rejected: e.rejected.map((r) => r.reason),
    },
    (_k, v) => (typeof v === 'bigint' ? v.toString() : v),
  );
}
let steps = 0;
async function both(label: string, f: (e: Engine) => Promise<unknown>) {
  for (const e of engines) await f(e);
  const [a, b] = engines.map(semantic);
  if (a !== b) {
    const [x, y] = [JSON.parse(a), JSON.parse(b)];
    for (const k of Object.keys(x)) if (JSON.stringify(x[k]) !== JSON.stringify(y[k])) log(`differs in ${k}:\n  witness builder ${JSON.stringify(x[k]).slice(0, 1500)}\n  sequencer       ${JSON.stringify(y[k]).slice(0, 1500)}`);
    throw new Error(`sequencer mode diverged at ${label}`);
  }
  steps++;
}

// Registrations, deposits (one to a missing account, refunded), indices for markets 0 and 1.
const update = (market: bigint, price: bigint) => signUpdate(h, full.domain, oracleSks, [0, 2], market, price, price, now - 1n);
const reqs: M.Request[] = [];
for (const [i, u] of users.entries()) {
  const encC = await M.encCommitment(h, u.keys.kEnc);
  for (const e of engines) e.keyring.set(encC, u.keys.kEnc);
  reqs.push({ kind: M.KIND.REGISTER, a: await M.masterAuthOf(h, u.keys.pk!.x, u.keys.pk!.y), b: encC, sender: u.addr, time: now + BigInt(i) });
}
for (const [i, u] of users.entries()) reqs.push(await M.depositRequest(h, u.index, i % 3 === 2 ? 40_000n : 4_000_000n, u.addr, now + 100n + BigInt(i)));
reqs.push(await M.depositRequest(h, 999n, 500n, users[0].addr, now + 200n));
now += 300n;
const marks = [2000n, 30_000n];
await both('genesis batch', async (e) => {
  await e.beginBatch(1n, 0n, 0n, 0n);
  await e.block(now, [await update(0n, marks[0]), await update(1n, marks[1])]);
  await e.priority(reqs);
});

const { BID, ASK } = M.SIDE;
const K = X.KIND_ACT;
// Every user's session key in slot 1, for markets 0 and 1.
const keyActs: SignedAction[] = [];
for (const u of users) keyActs.push(await signAction(h, full.domain, u.keys, K.ADD_KEY, u.index, 1n, [1n, u.session.pk!.x, u.session.pk!.y, 3n, 100_000_000n, now + 100_000n]));
await both('session keys', (e) => e.trade(keyActs.map((a) => ({ ...a, p: [...a.p] }))));
const TIFS = [X.TIF.GTC, X.TIF.GTC, X.TIF.IOC, X.TIF.FOK, X.TIF.POST_ONLY, X.TIF.GTT];
const nonceOf = (u: (typeof users)[number]) => full.actv.get(u.index)!.nonce;
let batch = 1n;
const kinds: Record<string, number> = {};

for (let round = 0; round < ROUNDS; round++) {
  now += int(1, 30);
  // The index walks; now and then it jumps, which may flag triggers and leave accounts liquidatable.
  for (let m = 0; m < 2; m++) marks[m] = (marks[m] * (1000n + int(-4, 4) + (rnd() < 0.05 ? int(-60, 60) : 0n))) / 1000n;
  const ups = [await update(0n, marks[0]), await update(1n, marks[1])];
  await both(`block ${round}`, (e) => e.block(now, ups));
  for (let m = 0; m < 2; m++) if (full.markets[m].triggerPending) await both(`fire ${m}`, (e) => e.fireTriggers([m]));
  for (const u of users) if (full.dueForLiquidation(u.index)) await both(`liquidate ${u.index}`, (e) => e.liquidateAccount(u.index));

  const acts: SignedAction[] = [];
  const next = new Map(users.map((u) => [u.index, nonceOf(u)]));
  const keyNonce = new Map(users.map((u) => [u.index, full.keyOf(u.index, 1).nonce]));
  // Each user acts at most twice a round, so one refusal rarely cascades into nonce refusals.
  const turns = [...users, ...users].sort(() => rnd() - 0.5).slice(0, 12);
  for (let i = 0; i < 12; i++) {
    const u = turns[i];
    const n = () => {
      const v = next.get(u.index)! + 1n;
      next.set(u.index, v);
      return v;
    };
    const m = rnd() < 0.7 ? 0 : 1;
    const mark = full.markets[m].markPrice;
    const mine = [...full.orders[m].values()].filter((o) => o.account === u.index);
    const r = rnd();
    let kind = 'place';
    let a: SignedAction;
    if (r < 0.5) {
      const side = rnd() < 0.5 ? BID : ASK;
      const off = (mark * int(-30, 30)) / 1000n + (rnd() < 0.05 ? (mark * 8n) / 100n : 0n);
      const tif = pick(TIFS);
      const lots = rnd() < 0.05 ? 1_000_000n : int(1, 12);
      const expiry = tif === X.TIF.GTT ? now + int(-5, 60) : 0n;
      a = await signAction(h, full.domain, u.keys, K.PLACE, u.index, n(), [BigInt(m), side, mark + off, lots, tif, rnd() < 0.1 ? 1n : 0n, expiry, rnd() < 0.2 ? 1n : 0n]);
    } else if (r < 0.65 && mine.length) {
      const o = pick(mine);
      const modify = rnd() < 0.3;
      kind = modify ? 'modify' : 'cancel';
      a = await signAction(h, full.domain, u.keys, modify ? K.MODIFY : K.CANCEL, u.index, n(), [BigInt(m), o.side, o.price, o.seq, ...(modify ? [o.lots - 1n] : [])]);
    } else if (r < 0.68) {
      kind = 'cancel missing';
      a = await signAction(h, full.domain, u.keys, K.CANCEL, u.index, n(), [BigInt(m), BID, mark, 99_999n]);
    } else if (r < 0.71) {
      kind = 'cancel all';
      a = await signAction(h, full.domain, u.keys, K.CANCEL_ALL, u.index, n(), []);
    } else if (r < 0.75) {
      kind = 'withdraw';
      a = await signAction(h, full.domain, u.keys, K.WITHDRAW, u.index, n(), [rnd() < 0.2 ? 50_000_000n : int(1, 20_000), u.addr]);
    } else if (r < 0.79) {
      kind = 'transfer';
      const to = rnd() < 0.1 ? 4242n : pick(users).index;
      a = await signAction(h, full.domain, u.keys, K.TRANSFER, u.index, n(), [int(1, 30_000), to]);
    } else if (r < 0.82) {
      const add = rnd() < 0.7;
      kind = add ? 'add key' : 'revoke key';
      const s = u.session;
      a = await signAction(h, full.domain, u.keys, add ? K.ADD_KEY : K.REVOKE_KEY, u.index, n(), add ? [1n, s.pk!.x, s.pk!.y, 3n, 100_000_000n, now + 3600n] : [1n]);
    } else if (r < 0.89) {
      kind = 'session place';
      const kn = keyNonce.get(u.index)! + 1n;
      keyNonce.set(u.index, kn);
      const side = rnd() < 0.5 ? BID : ASK;
      a = await signAction(h, full.domain, u.session, K.PLACE, u.index, kn, [BigInt(m), side, mark + (mark * int(-20, 20)) / 1000n, int(1, 5), X.TIF.GTC, 0n, 0n, 0n], 1n);
    } else if (r < 0.95) {
      const trig = [...full.triggers[m].entries()].filter(([, t]) => t.account === u.index);
      if (trig.length && rnd() < 0.4) {
        kind = 'cancel trigger';
        const [, t] = pick(trig);
        a = await signAction(h, full.domain, u.keys, K.CANCEL_TRIGGER, u.index, n(), [BigInt(m), t.dir, t.price, t.seq]);
      } else {
        kind = 'trigger';
        const dir = rnd() < 0.5 ? X.DIR.UP : X.DIR.DOWN;
        const at = dir === X.DIR.UP ? mark + (mark * int(1, 40)) / 1000n : mark - (mark * int(1, 40)) / 1000n;
        const side = rnd() < 0.5 ? BID : ASK;
        a = await signAction(h, full.domain, u.keys, K.PLACE_TRIGGER, u.index, n(), [BigInt(m), side, side === BID ? at + at / 50n : at - at / 50n, int(1, 6), dir, at, rnd() < 0.3 ? 1n : 0n, 0n]);
      }
    } else if (r < 0.97) {
      kind = 'stale nonce';
      a = await signAction(h, full.domain, u.keys, K.PLACE, u.index, nonceOf(u), [BigInt(m), BID, mark, 1n, X.TIF.GTC, 0n, 0n, 0n]);
    } else {
      kind = 'bad signature';
      a = await signAction(h, full.domain, users[0].keys, K.PLACE, u.index, n(), [BigInt(m), BID, mark, 1n, X.TIF.GTC, 0n, 0n, 0n]);
      if (u === users[0]) a.sig = { s: a.sig.s, e: a.sig.e ^ 1n };
    }
    kinds[kind] = (kinds[kind] ?? 0) + 1;
    acts.push(a);
  }
  await both(`trade ${round}`, (e) => e.trade(acts.map((a) => ({ ...a, p: [...a.p] }))));
  if (round % 7 === 6) await both(`sweep ${round}`, (e) => e.maintenance({ sweep: true, refresh: 2 }));
  if (round % 10 === 9) {
    // A new batch; each engine starts it where its last one ended.
    batch++;
    await both(`batch ${batch}`, async (e) => {
      if (!e.lite) await e.endBatch();
      await e.beginBatch(batch, e.running.priorityHead, e.running.priorityCursor, e.running.time);
    });
  }
}

const reasons = new Map<string, number>();
for (const r of full.rejected) reasons.set(r.reason, (reasons.get(r.reason) ?? 0) + 1);
log(`${ROUNDS} rounds, ${steps} steps compared; actions sent: ${Object.entries(kinds).map(([k, v]) => `${k} ${v}`).join(', ')}`);
log(`both engines applied ${full.lastSeq} signed actions and refused ${full.rejected.length}: ${[...reasons].map(([k, v]) => `${k} ×${v}`).join('; ')}`);
log(`resting: ${full.orders.map((o) => o.size).join('/')} orders, ${full.triggers.map((t) => t.size).join('/')} triggers; fees pending ${full.feesPending}`);
assert(full.lastSeq > 0n && full.rejected.length > 0, 'the workload must both apply and refuse actions');
log('sequencer mode agrees with the witness builder');
process.exit(0);
