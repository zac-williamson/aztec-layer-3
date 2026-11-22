// Adversarial witnesses for the segment circuits (SPEC.md §17). Each case builds an honest witness
// with the engine, tampers with it the way a malicious operator could, and checks that the circuit
// refuses it, with the expected assertion. Execution only, no proving: a witness that cannot be
// generated cannot be proved.
import { join } from 'node:path';
import { Noir } from '@aztec-foundation/noir-noir_js';
import { OUT, hex, randomField, readCircuit, readJson } from '../lib.ts';
import { Prover, assert, batchStart, chonkPlaceholder, newApi, nodeToNoir } from '../pipeline.ts';
import { Engine, type SignedAction, proveAction, signAction, signUpdate } from './engine.ts';
import { keysFromSeed, scalarToNoir, sign, sigToNoir } from './grumpkin.ts';
import * as M from './model.ts';
import { protocolAccounts, testParams } from './params.ts';
import * as X from './rules.ts';

type Case = { name: string; pass: boolean; how: string };
const results: Case[] = [];
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

async function execute(pkg: string, inputs: unknown) {
  return new Noir(readCircuit(pkg) as any).execute(inputs as any);
}

async function expectFail(name: string, pkg: string, inputs: unknown, message?: string) {
  try {
    await execute(pkg, inputs);
    results.push({ name, pass: false, how: 'ACCEPTED' });
  } catch (e: any) {
    const msg = String(e?.message ?? e).split('\n')[0];
    // Unlabelled assertions (inside the schnorr library) fail as "Cannot satisfy constraint".
    const ok = message ? msg.includes(message) : /Circuit execution failed|Cannot satisfy constraint/.test(msg);
    results.push({ name, pass: ok, how: msg.slice(0, 140) });
  }
}

async function main() {
  const manifest = readJson(join(OUT, 'manifest.json'));
  const api = await newApi();
  const h = M.hasher(api);
  const { params, oracleSks } = await testParams(h);
  const prover = await Prover.create(api, manifest, await M.paramsHash(h, params));
  const protocol = await protocolAccounts(h);
  const engine = await Engine.create(api, params, prover.vkTreeRoot, protocol);
  const now = BigInt(Math.floor(Date.now() / 1000));
  const update = (e: Engine, market: bigint, price: bigint, time: bigint, signers = [0, 1]) =>
    signUpdate(h, e.domain, oracleSks, signers, market, price, price, time);

  // Three accounts (indices 2, 3, 4) with collateral, indices for markets 0 and 1, and five resting
  // asks from account 2 in market 0.
  const users = await Promise.all([1n, 2n, 3n].map((s) => keysFromSeed(h, s)));
  const idx = (u: number) => BigInt(M.PROTOCOL_ACCOUNTS + u);
  const reqs: M.Request[] = [];
  for (const [i, k] of users.entries()) {
    const encC = await M.encCommitment(h, k.kEnc);
    engine.keyring.set(encC, k.kEnc);
    const sender = randomField();
    reqs.push({ kind: M.KIND.REGISTER, a: await M.masterAuthOf(h, k.pk!.x, k.pk!.y), b: encC, sender, time: now });
    reqs.push({ kind: M.KIND.DEPOSIT, a: idx(i), b: 1_000_000n, sender, time: now });
  }
  await engine.beginBatch(1n, 0n, 0n, 0n);
  await engine.block(now, [await update(engine, 0n, 2000n, now), await update(engine, 1n, 30_000n, now)]);
  await engine.priority(reqs);
  const act = (u: number, nonce: bigint, kind: bigint, p: bigint[]) => signAction(h, engine.domain, users[u], kind, idx(u), nonce, p);
  const { BID, ASK } = M.SIDE;
  const { PLACE, WITHDRAW } = X.KIND_ACT;
  const { GTC, IOC, FOK, POST_ONLY } = X.TIF;
  await engine.trade([
    await act(0, 1n, PLACE, [0n, ASK, 2000n, 10n, GTC, 0n]),
    await act(0, 2n, PLACE, [0n, ASK, 2001n, 10n, GTC, 0n]),
    await act(0, 3n, PLACE, [0n, ASK, 2002n, 10n, GTC, 0n]),
    await act(0, 4n, PLACE, [0n, ASK, 2002n, 10n, GTC, 0n]),
    await act(0, 5n, PLACE, [0n, ASK, 2002n, 10n, GTC, 0n]),
  ]);
  assert(engine.rejected.length === 0, `setup rejected: ${engine.rejected.map((r) => r.reason)}`);

  // The book path of the 2001 ask, as it stands before the next trade.
  const worse = X.orderIndex(ASK, 2001n, 1n);
  const worsePath = engine.books[0].path(worse).map((s) => ({ hash: hex(s.hash), ask: s.ask.toString(), bid: s.bid.toString() }));

  // Honest witnesses to tamper with.
  const n0 = engine.segments.length;
  await engine.trade([await act(1, 1n, PLACE, [0n, BID, 2002n, 5n, IOC, 0n])]); // one fill, opens a long
  const buy = engine.segments[n0].inputs as any;
  await engine.trade([await act(2, 1n, PLACE, [0n, BID, 2001n, 15n, IOC, 0n])]); // two fills, nothing left crossing
  await engine.trade([
    await act(2, 2n, PLACE, [0n, BID, 1990n, 5n, GTC, 0n]), // rests: no fill
    await act(2, 3n, WITHDRAW, [1000n, 77n]),
  ]);
  const quiet = engine.segments[n0 + 2].inputs as any;
  // Account 3 rests an ask in market 1, then takes it back through self-trade prevention.
  await engine.trade([await act(1, 2n, PLACE, [1n, ASK, 30_100n, 1n, GTC, 0n]), await act(1, 3n, PLACE, [1n, BID, 30_100n, 1n, IOC, 0n])]);
  const selfTrade = engine.segments[n0 + 3].inputs as any;
  assert(engine.rejected.length === 0, `setup rejected: ${engine.rejected.map((r) => r.reason)}`);
  await engine.maintenance({ sweep: true, refresh: 2 });
  const maint = engine.segments[n0 + 4].inputs as any;
  // A tick with both sides of market 0's book populated (account 4's bid at 1990, asks from 2001).
  await engine.block(now + 1n, [await update(engine, 0n, 2001n, now + 1n)]);
  const tick = engine.segments[n0 + 5].inputs as any;
  assert(tick.updates[0].bid.has && tick.updates[0].ask.has, 'tick has both sides');
  for (const [pkg, seg] of [['seg_trade', buy], ['seg_trade', quiet], ['seg_trade', selfTrade], ['seg_refresh', maint], ['seg_block', tick]] as const) {
    await execute(pkg, seg); // honest witnesses run
  }
  const resign = async (inputs: any, i: number, u: number, nonce: bigint, kind: bigint, p: bigint[]) => {
    const a: SignedAction = await act(u, nonce, kind, p);
    inputs.actions[i] = { ...inputs.actions[i], nonce: nonce.toString(), p: a.p.map(hex), sig: sigToNoir(a.sig) };
  };

  // Authorization.
  let t = clone(buy);
  t.actions[0].sig.s = scalarToNoir(12345n);
  await expectFail('forged signature', 'seg_trade', t);
  t = clone(buy);
  t.actions[0].pk_x = hex(users[2].pk!.x);
  t.actions[0].pk_y = hex(users[2].pk!.y);
  await expectFail("another account's key", 'seg_trade', t, "signing key is not the account's");
  // The operator swaps in its own key as the account's master authorization, for an order with no
  // fill (no other leaf write would expose it).
  t = clone(quiet);
  const evil = await keysFromSeed(h, 666n);
  const p0 = [0n, BID, 1990n, 5n, GTC, 0n, 0n, 0n];
  t.actions[0].taker_pub.master_auth = hex(await M.masterAuthOf(h, evil.pk!.x, evil.pk!.y));
  t.actions[0].pk_x = hex(evil.pk!.x);
  t.actions[0].pk_y = hex(evil.pk!.y);
  t.actions[0].sig = sigToNoir(await sign(h, evil.sk, await X.actionMsg(h, engine.domain, PLACE, idx(2), M.MASTER_KEY, 2n, p0)));
  await expectFail('operator substitutes the signing key', 'seg_trade', t, 'Merkle path does not match root');
  t = clone(buy);
  await resign(t, 0, 1, 0n, PLACE, [0n, BID, 2002n, 5n, IOC, 0n]);
  await expectFail('replayed nonce', 'seg_trade', t, 'nonce');
  // Receipts (SPEC.md §11): sequence numbers follow execution order, and padding claims none.
  t = clone(buy);
  t.actions[0].seq = '1';
  await expectFail('action out of sequence order', 'seg_trade', t, 'sequence numbers must increase');
  const at = batchStart(0n, 0n, 0n, 0n, 1n);
  await expectFail('padding with a receipts root', 'padding', { out: nodeToNoir({ configHash: prover.configHash, start: at, end: at, receiptsRoot: 5n }) }, 'padding segment must be empty');

  // Matching.
  t = clone(buy);
  Object.assign(t.actions[0].fills[0], { index: hex(worse), price: '2001', seq: '1', book_path: worsePath });
  await expectFail('fill skips the best ask', 'seg_trade', t, 'not the best ask');
  // A self-trade must cancel the resting order; claiming it belongs to another account, to fill
  // it as a wash trade, breaks the book path.
  t = clone(selfTrade);
  t.actions[1].fills[0].order.account_index = idx(0).toString();
  await expectFail('self-trade disguised as a fill', 'seg_trade', t, 'maker order path');
  // A malicious engine stops a 30-lot IOC after two fills although the 2002 asks still cross.
  const before = engine.segments.length;
  engine.relax.add('fills');
  await engine.trade([await act(1, 4n, PLACE, [0n, BID, 2002n, 30n, IOC, 0n])]);
  engine.relax.clear();
  await expectFail('IOC stops with crossing liquidity left', 'seg_trade', engine.segments[before].inputs, 'crossing asks remain');
  t = clone(buy);
  await resign(t, 0, 1, 1n, PLACE, [0n, BID, 2200n, 5n, IOC, 0n]);
  await expectFail('limit price outside the band', 'seg_trade', t, 'limit price outside the band');

  // Order types: the same partial fill re-signed with a different time in force or flag.
  t = clone(buy);
  await resign(t, 0, 1, 1n, PLACE, [0n, BID, 2002n, 20n, FOK, 0n]); // 20 wanted, the one maker holds 10
  await expectFail('fill-or-kill order partly filled', 'seg_trade', t, 'fill-or-kill order not filled');
  t = clone(buy);
  await resign(t, 0, 1, 1n, PLACE, [0n, BID, 2002n, 5n, POST_ONLY, 0n]);
  await expectFail('post-only order takes liquidity', 'seg_trade', t, 'post-only order would take liquidity');
  t = clone(buy);
  await resign(t, 0, 1, 1n, PLACE, [0n, BID, 2002n, 5n, IOC, 1n]);
  await expectFail('reduce-only order opens a position', 'seg_trade', t, 'reduce-only order must reduce');

  // Margin: the circuit checks against the committed parameters, whatever the operator believed.
  t = clone(buy);
  t.params.markets[0].imr_ppm = '1000000000';
  await expectFail('order beyond initial margin', 'seg_trade', t, 'insufficient margin');
  t = clone(quiet);
  const big = await act(2, 3n, WITHDRAW, [999_000n, 77n]); // within collateral, beyond equity − IM
  t.actions[1] = { ...t.actions[1], p: big.p.map(hex), sig: sigToNoir(big.sig) };
  await expectFail('withdrawal beyond equity', 'seg_trade', t, 'insufficient margin');
  t = clone(buy);
  t.params.max_age = '0';
  t.start.time = (BigInt(t.start.time) + 10n).toString();
  await expectFail('risk-increasing order on a stale index', 'seg_trade', t, 'index too old');

  // Oracle and ticks.
  t = clone(tick);
  t.updates[0].price = '2002';
  await expectFail('oracle price not as signed', 'seg_block', t);
  const under = await Engine.create(api, params, prover.vkTreeRoot, protocol);
  under.relax.add('oracle-sigs');
  await under.beginBatch(1n, 0n, 0n, 0n);
  await under.block(now, [await update(under, 0n, 2000n, now, [2])]);
  await expectFail('index update below the signature threshold', 'seg_block', under.segments[0].inputs, 'not enough oracle signatures');
  // An engine that tolerates a 100% move builds the witness; the circuit applies the committed 10%.
  const looseParams = { ...params, markets: params.markets.map((m, i) => (i === 0 ? { ...m, maxJumpPpm: 2_000_000n } : m)) };
  const loose = await Engine.create(api, looseParams, prover.vkTreeRoot, protocol);
  await loose.beginBatch(1n, 0n, 0n, 0n);
  await loose.block(now, [await update(loose, 0n, 1000n, now)]);
  await loose.block(now + 1n, [await update(loose, 0n, 2000n, now + 1n)]);
  t = clone(loose.segments[1].inputs as any);
  t.params.markets[0].max_jump_ppm = params.markets[0].maxJumpPpm.toString();
  await expectFail('oracle jump beyond the bound', 'seg_block', t, 'oracle jump too large');
  t = clone(tick);
  t.block_time = (BigInt(t.start.time) - 1n).toString();
  await expectFail('block time regresses', 'seg_block', t, 'time regressed');
  // The operator hides the bids to move the mark: an empty side must be proved empty.
  t = clone(tick);
  t.updates[0].bid = { ...t.updates[0].bid, has: false, price: '0', seq: '0', order: { side: hex(0n), account_index: '0', lots: '0', expiry: '0' } };
  await expectFail('tick hides the best bid', 'seg_block', t, 'empty bid side path');
  t = clone(tick);
  t.updates[0].ask.seq = (BigInt(t.updates[0].ask.seq) + 2n).toString(); // a later ask at the same price (not the leaf's sibling)
  await expectFail('tick reports a worse best ask', 'seg_block', t, 'best ask path');

  // Encryption keys, openings and sweeps.
  const prio = engine.segments[1].inputs as any;
  t = clone(prio);
  t.items[0].k_enc = hex(424242n);
  await expectFail('registration encrypted under another key', 'seg_priority', t, 'k_enc does not open the commitment');
  t = clone(prio);
  t.items[1].account_index = idx(1).toString();
  await expectFail('deposit credited to another account', 'seg_priority', t, 'deposit index');
  t = clone(maint);
  t.items[0].priv_part.collateral = '999999999';
  await expectFail('refresh publishes an inflated opening', 'seg_refresh', t, 'account path');
  t = clone(maint);
  t.protocol[1].priv_part.collateral = (BigInt(t.protocol[1].priv_part.collateral) + 1000n).toString();
  await expectFail('sweep credits an inflated fee balance', 'seg_refresh', t, 'Merkle path does not match root');
  t = clone(maint);
  [t.protocol[0], t.protocol[1]] = [t.protocol[1], t.protocol[0]];
  await expectFail('sweep swaps the protocol accounts', 'seg_refresh', t, 'protocol account class');

  // Liquidation (SPEC.md §8.5). A fresh exchange: P provides liquidity; V (long 120 in market 0 and
  // 1 in market 1, with an ask resting) and W (long 5) go underwater when market 0 falls 13%. The
  // insurance account holds 10,000: enough to take over W, not V.
  const L = await Engine.create(api, params, prover.vkTreeRoot, protocol);
  const lu = await Promise.all([11n, 12n, 13n].map((x) => keysFromSeed(h, x)));
  const [P, V, W] = [2n, 3n, 4n];
  const lreqs: M.Request[] = [];
  for (const [i, k] of lu.entries()) {
    const encC = await M.encCommitment(h, k.kEnc);
    L.keyring.set(encC, k.kEnc);
    const sender = randomField();
    lreqs.push({ kind: M.KIND.REGISTER, a: await M.masterAuthOf(h, k.pk!.x, k.pk!.y), b: encC, sender, time: now });
    lreqs.push({ kind: M.KIND.DEPOSIT, a: BigInt(M.PROTOCOL_ACCOUNTS + i), b: [5_000_000n, 30_000n, 1_100n][i], sender, time: now });
  }
  lreqs.push({ kind: M.KIND.DEPOSIT, a: M.INSURANCE_INDEX, b: 10_000n, sender: randomField(), time: now });
  await L.beginBatch(1n, 0n, 0n, 0n);
  await L.block(now, [await update(L, 0n, 2000n, now), await update(L, 1n, 30_000n, now)]);
  await L.priority(lreqs);
  const lact = (u: number, nonce: bigint, p: bigint[]) => signAction(h, L.domain, lu[u], PLACE, BigInt(M.PROTOCOL_ACCOUNTS + u), nonce, p);
  await L.trade([
    await lact(0, 1n, [0n, ASK, 2000n, 400n, GTC, 0n]),
    await lact(0, 2n, [1n, ASK, 30_000n, 5n, GTC, 0n]),
    await lact(1, 1n, [0n, BID, 2000n, 120n, IOC, 0n]),
    await lact(1, 2n, [1n, BID, 30_000n, 1n, IOC, 0n]),
    await lact(2, 1n, [0n, BID, 2000n, 5n, IOC, 0n]),
    await lact(1, 3n, [0n, ASK, 2050n, 1n, GTC, 0n]),
  ]);
  await L.block(now + 2n, [await update(L, 0n, 1840n, now + 1n), await update(L, 0n, 1740n, now + 2n)]);
  await L.trade([await lact(0, 3n, [0n, BID, 1700n, 10n, GTC, 0n])]); // below V's close limit (the mark)
  assert(L.rejected.length === 0, `liquidation setup rejected: ${L.rejected.map((r) => r.reason)}`);
  assert(L.health(V).closeout && L.health(W).closeout && !L.health(P).liquidatable, 'liquidation setup health');
  /** The witness of one liquidation step, built by a relaxed engine that skips its own checks. */
  const relaxed = async (step: Parameters<Engine['liquidate']>[0][number]) => {
    const snap = L.snapshot();
    L.relax.add('liq');
    try {
      await L.liquidate([step]);
      return clone(L.segments[L.segments.length - 1].inputs) as any;
    } finally {
      L.relax.clear();
      L.restore(snap);
    }
  };
  const vOrder = [...L.orders[0].entries()].find(([, o]) => o.account === V)![0];
  const pOrder = [...L.orders[0].entries()].find(([, o]) => o.account === P)![0];
  await expectFail('liquidating a healthy account', 'seg_liquidate', await relaxed({ kind: 'cancel', account: P, market: 0, index: pOrder }), 'account is not liquidatable');
  await expectFail('closing before the orders are cancelled', 'seg_liquidate', await relaxed({ kind: 'close', account: V, market: 0 }), 'orders must be cancelled first');
  await L.liquidate([{ kind: 'cancel', account: V, market: 0, index: vOrder }]); // honest
  const cancelStep = clone(L.segments[L.segments.length - 1].inputs) as any;
  await execute('seg_liquidate', cancelStep);
  await expectFail('close below the liquidation limit', 'seg_liquidate', await relaxed({ kind: 'close', account: V, market: 0 }), 'best bid below the limit');
  await expectFail('takeover before the lowest-PnL position', 'seg_liquidate', await relaxed({ kind: 'takeover', account: V, market: 1 }), 'not the lowest unrealized PnL');
  await expectFail('takeover beyond the insurance margin', 'seg_liquidate', await relaxed({ kind: 'takeover', account: V, market: 0 }), 'insurance below initial margin');
  await expectFail('takeover of an account above close-out margin', 'seg_liquidate', await relaxed({ kind: 'takeover', account: P, market: 0 }), 'account is above close-out margin');
  await expectFail('deficit with positions left', 'seg_liquidate', await relaxed({ kind: 'deficit', account: V }), 'positions remain');
  await expectFail('ADL while the insurance can absorb', 'seg_liquidate', await relaxed({ kind: 'adl', account: W, market: 0, counterparty: P }), 'insurance can absorb');
  await expectFail('ADL against a position on the same side', 'seg_liquidate', await relaxed({ kind: 'adl', account: V, market: 0, counterparty: W }), 'counterparty not opposite');
  await expectFail('liquidating the insurance account', 'seg_liquidate', await relaxed({ kind: 'deficit', account: M.INSURANCE_INDEX }), 'only user accounts are liquidated');
  t = clone(cancelStep);
  t.params.max_age = '0';
  t.start.time = (BigInt(t.start.time) + 10n).toString();
  await expectFail('liquidation on a stale index', 'seg_liquidate', t, 'index too old for a liquidation');
  // The honest ends of both waterfalls execute: V is deleveraged against P, W taken over.
  await L.liquidate([{ kind: 'adl', account: V, market: 0, counterparty: P }, { kind: 'takeover', account: W, market: 0 }]);
  await execute('seg_liquidate', L.segments[L.segments.length - 1].inputs);

  // ModifyOrder and Transfer (SPEC.md §7.3): account 4 reduces its resting bid, then moves
  // collateral to account 3.
  const nm = engine.segments.length;
  const bid1990 = [...engine.orders[0].values()].find((o) => o.account === idx(2) && o.price === 1990n)!;
  const { MODIFY, TRANSFER } = X.KIND_ACT;
  await engine.trade([await act(2, 4n, MODIFY, [0n, BID, 1990n, bid1990.seq, 2n]), await act(2, 5n, TRANSFER, [5000n, idx(1)])]);
  assert(engine.rejected.length === 0, `modify/transfer setup rejected: ${engine.rejected.map((r) => r.reason)}`);
  const moves = clone(engine.segments[nm].inputs) as any;
  await execute('seg_trade', moves);
  t = clone(moves);
  await resign(t, 0, 2, 4n, MODIFY, [0n, BID, 1990n, bid1990.seq, 9n]);
  await expectFail('modification that adds lots', 'seg_trade', t, 'a modification only reduces an order');
  t = clone(moves);
  await resign(t, 1, 2, 5n, TRANSFER, [5_000_000n, idx(1)]);
  await expectFail('transfer above the collateral', 'seg_trade', t, 'collateral below the amount');
  t = clone(moves);
  await resign(t, 1, 2, 5n, TRANSFER, [5000n, 99n]);
  await expectFail('transfer to a missing account', 'seg_trade', t, 'no such account');
  t = clone(moves);
  await resign(t, 1, 2, 5n, TRANSFER, [5000n, idx(2)]);
  await expectFail('transfer to the same account', 'seg_trade', t, 'transfer to the same account');
  t = clone(moves);
  await resign(t, 1, 2, 5n, TRANSFER, [5000n, M.INSURANCE_INDEX]);
  t.actions[1].dest_pub.class = '1';
  await expectFail('transfer to a protocol account', 'seg_trade', t, 'transfers go to user accounts');
  t = clone(moves);
  t.actions[1].dest_k_enc = hex(5n);
  await expectFail('transfer published under another key', 'seg_trade', t, 'k_enc does not open the commitment');

  // Session keys, GTT and forced requests (SPEC.md §6.5, §7.2, §7.3). Q provides liquidity; R gives
  // a session key market 0 only, a 100,000 notional cap and an expiry, and its key rests a bid.
  const K = await Engine.create(api, params, prover.vkTreeRoot, protocol);
  const ku = await Promise.all([21n, 22n].map((x) => keysFromSeed(h, x)));
  const [Q, Rk] = [2n, 3n];
  const kaddr = [randomField(), randomField()];
  const kreqs: M.Request[] = [];
  for (const [i, k] of ku.entries()) {
    const encC = await M.encCommitment(h, k.kEnc);
    K.keyring.set(encC, k.kEnc);
    kreqs.push({ kind: M.KIND.REGISTER, a: await M.masterAuthOf(h, k.pk!.x, k.pk!.y), b: encC, sender: kaddr[i], time: now });
    kreqs.push({ kind: M.KIND.DEPOSIT, a: BigInt(M.PROTOCOL_ACCOUNTS + i), b: [2_000_000n, 1_000_000n][i], sender: kaddr[i], time: now });
  }
  await K.beginBatch(1n, 0n, 0n, 0n);
  await K.block(now, [await update(K, 0n, 2000n, now), await update(K, 1n, 30_000n, now)]);
  await K.priority(kreqs);
  const kact = (u: number, nonce: bigint, kind: bigint, p: bigint[]) => signAction(h, K.domain, ku[u], kind, BigInt(M.PROTOCOL_ACCOUNTS + u), nonce, p);
  const sessKey = await keysFromSeed(h, 31337n);
  const bySess = (nonce: bigint, kind: bigint, p: bigint[]) => signAction(h, K.domain, sessKey, kind, Rk, nonce, p, 0n);
  const keyExpiry = now + 1000n;
  await K.trade([
    await kact(0, 1n, PLACE, [0n, ASK, 2000n, 50n, GTC, 0n]),
    await kact(0, 2n, PLACE, [0n, ASK, 2001n, 50n, GTC, 0n]),
    await kact(0, 3n, PLACE, [0n, BID, 1990n, 50n, GTC, 0n]),
    await kact(0, 4n, PLACE, [0n, BID, 1989n, 5n, GTC, 0n]),
    await kact(0, 5n, PLACE, [0n, BID, 1988n, 5n, GTC, 0n]),
    await kact(0, 6n, PLACE, [0n, BID, 1987n, 5n, GTC, 0n]),
    await kact(1, 1n, X.KIND_ACT.ADD_KEY, [0n, sessKey.pk.x, sessKey.pk.y, 0b01n, 100_000n, keyExpiry]),
  ]);
  const ks = K.segments.length;
  await K.trade([await bySess(1n, PLACE, [0n, BID, 1995n, 10n, GTC, 0n])]);
  const sessPlace = clone(K.segments[ks].inputs) as any;
  await K.trade([await kact(1, 2n, PLACE, [0n, BID, 2000n, 20n, IOC, 0n])]); // R goes long 20
  assert(K.rejected.length === 0, `session setup rejected: ${K.rejected.map((r) => r.reason)}`);
  await execute('seg_trade', sessPlace);
  const reSess = async (inputs: any, nonce: bigint, kind: bigint, p: bigint[]) => {
    const a = await bySess(nonce, kind, p);
    inputs.actions[0] = { ...inputs.actions[0], kind: hex(kind), nonce: nonce.toString(), p: a.p.map(hex), sig: sigToNoir(a.sig) };
    return inputs;
  };
  await expectFail('session key outside its markets', 'seg_trade', await reSess(clone(sessPlace), 1n, PLACE, [1n, BID, 30_000n, 1n, GTC, 0n]), 'market not allowed for the session key');
  await expectFail('session key above its notional cap', 'seg_trade', await reSess(clone(sessPlace), 1n, PLACE, [0n, BID, 1995n, 100n, GTC, 0n]), "order above the session key's notional limit");
  await expectFail('session key withdrawing', 'seg_trade', await reSess(clone(sessPlace), 1n, WITHDRAW, [10n, 77n]), 'session keys only place, cancel and modify');
  await expectFail('session key adding a key', 'seg_trade', await reSess(clone(sessPlace), 1n, X.KIND_ACT.ADD_KEY, [1n, 5n, 6n, 1n, 1n, keyExpiry]), 'session keys only place, cancel and modify');
  await expectFail('session key transferring', 'seg_trade', await reSess(clone(sessPlace), 1n, X.KIND_ACT.TRANSFER, [10n, Q]), 'session keys only place, cancel and modify');
  await expectFail('session key nonce replayed', 'seg_trade', await reSess(clone(sessPlace), 0n, PLACE, [0n, BID, 1995n, 10n, GTC, 0n]), 'nonce');
  t = clone(sessPlace);
  t.start.time = (keyExpiry + 1n).toString();
  await expectFail('expired session key', 'seg_trade', t, 'session key expired');
  t = clone(sessPlace);
  t.actions[0].key = { ...t.actions[0].key, pk_x: hex(ku[0].pk.x), pk_y: hex(ku[0].pk.y) };
  t.actions[0].pk_x = hex(ku[0].pk.x);
  t.actions[0].pk_y = hex(ku[0].pk.y);
  t.actions[0].sig = sigToNoir(await sign(h, ku[0].sk, await X.actionMsg(h, K.domain, PLACE, Rk, 0n, 1n, [0n, BID, 1995n, 10n, GTC, 0n, 0n, 0n])));
  await expectFail('another key in the session slot', 'seg_trade', t, 'session key path');
  const st0 = BigInt(sessPlace.start.time);
  await expectFail('GTT order already expired', 'seg_trade', await reSess(clone(sessPlace), 1n, PLACE, [0n, BID, 1995n, 10n, X.TIF.GTT, 0n, st0]), 'order already expired');
  await expectFail('GTC order with an expiry', 'seg_trade', await reSess(clone(sessPlace), 1n, PLACE, [0n, BID, 1995n, 10n, GTC, 0n, st0 + 100n]), 'only GTT orders expire');
  // Forced requests: R closes its long against Q's bids; Q cancels its orders. The probe path a
  // close that stopped at once would need, on the book as it stands before the close:
  const probe = K.books[0].path(X.orderIndex(M.SIDE.ASK, 1900n, K.markets[0].nextSeq)).map((x) => ({ hash: hex(x.hash), ask: x.ask.toString(), bid: x.bid.toString() }));
  const kf = K.segments.length;
  await K.priority([
    { kind: M.KIND.FORCED_CLOSE, a: Rk, b: 0n, c: 1900n, sender: kaddr[1], time: now },
    { kind: M.KIND.FORCED_CANCEL_ALL, a: Q, b: 0n, sender: kaddr[0], time: now },
  ]);
  const forcedClose = clone(K.segments[kf].inputs) as any;
  const forcedCancel = clone(K.segments[kf + 1].inputs) as any;
  // The close first cancels R's own resting bid (self-trade prevention), then fills against Q.
  assert(forcedClose.n_fills === 2 && forcedCancel.n_cancels === 4, `forced setup: ${forcedClose.n_fills} steps, ${forcedCancel.n_cancels} cancels`);
  await execute('seg_forced', forcedClose);
  await execute('seg_forced', forcedCancel);
  t = clone(forcedClose);
  t.n_fills = 0;
  t.probe_path = probe;
  await expectFail('forced close stops with liquidity left', 'seg_forced', t, 'crossing bids remain');
  t = clone(forcedCancel);
  t.n_cancels = 3;
  await expectFail('forced cancel-all leaves cancellable orders', 'seg_forced', t, 'forced cancel-all must cancel every order it can');

  // Client-proof actions (SPEC.md §7.4). S is a lane-P account, U a lane-S one. An honest P-segment
  // grants S two session keys and withdraws 1,000 of its collateral; the tampered tube witnesses are
  // what an operator would need to apply actions no client proof authorized. The tube runs without its Chonk proof here (witness
  // generation does not check it), so each case shows the check the tube itself makes.
  const PE = await Engine.create(api, params, prover.vkTreeRoot, protocol, prover.clientVks);
  const pSecret = randomField();
  const pu = await Promise.all([41n, 42n].map((x) => keysFromSeed(h, x)));
  const [S, U] = [2n, 3n];
  const pAuth = [await M.masterAuthP(h, prover.clientVkHash, await M.authBinding(h, pSecret)), await M.masterAuthOf(h, pu[1].pk.x, pu[1].pk.y)];
  const preqs: M.Request[] = [];
  for (const [i, k] of pu.entries()) {
    const encC = await M.encCommitment(h, k.kEnc);
    PE.keyring.set(encC, k.kEnc);
    const sender = randomField();
    preqs.push({ kind: M.KIND.REGISTER, a: pAuth[i], b: encC, sender, time: now });
    preqs.push({ kind: M.KIND.DEPOSIT, a: BigInt(M.PROTOCOL_ACCOUNTS + i), b: 50_000n, sender, time: now });
  }
  await PE.beginBatch(1n, 0n, 0n, 0n);
  await PE.block(now);
  await PE.priority(preqs);
  const pSess = await keysFromSeed(h, 4242n);
  const byClient = (account: bigint, nonce: bigint, kind: bigint, p: bigint[]) => proveAction(h, PE.domain, pSecret, kind, account, nonce, p);
  const { ADD_KEY } = X.KIND_ACT;
  const ps = PE.segments.length;
  await PE.proven([
    await byClient(S, 1n, ADD_KEY, [0n, pSess.pk.x, pSess.pk.y, 0b01n, 100_000n, now + 1000n]),
    await byClient(S, 2n, ADD_KEY, [1n, pSess.pk.x, pSess.pk.y, 0b10n, 100_000n, now + 1000n]),
    await byClient(S, 3n, WITHDRAW, [1000n, 77n]),
  ]);
  assert(PE.rejected.length === 0, `client-proof setup rejected: ${PE.rejected.map((r) => r.reason)}`);
  const tube = clone(PE.segments[ps].inputs) as any;
  const runTube = (inputs: any) => ({ ...inputs, ...chonkPlaceholder() });
  await execute('tube', runTube(tube));
  const remsg = async (t: any, i: number) => {
    const a = t.actions[i];
    a.msg = hex(await X.actionMsg(h, PE.domain, BigInt(a.kind), BigInt(a.account_index), M.MASTER_KEY, BigInt(a.nonce), a.p.map((x: string) => BigInt(x))));
    return t;
  };
  /** The aggregation the IVC would output had client proofs authorized exactly these actions. */
  const reaggregate = async (t: any) => {
    let acc = 0n;
    for (let i = 0; i < Number(t.agg.count); i++) {
      const a = t.actions[i];
      acc = await h([M.DS.AGG, acc, BigInt(a.vk_hash), BigInt(a.msg), BigInt(a.account_index), BigInt(a.auth_binding)]);
    }
    t.agg.actions_hash = hex(acc);
    return t;
  };
  t = clone(tube);
  t.actions[0].p[4] = hex(10_000_000n); // a larger notional cap than the client granted
  await expectFail('client action no proof authorized', 'tube', runTube(await remsg(t, 0)), 'client actions do not match the proofs');
  t = clone(tube);
  t.actions[0].p[4] = hex(10_000_000n);
  await expectFail("client proof applied to another action", 'tube', runTube(t), 'proof authorizes another action');
  t = clone(tube);
  t.actions[1] = clone(tube.actions[9]);
  await expectFail('aggregated client action dropped', 'tube', runTube(t), 'client actions do not match the proofs');
  t = clone(tube);
  t.actions[1] = { ...t.actions[1], msg: t.actions[0].msg, kind: t.actions[0].kind, nonce: t.actions[0].nonce, p: t.actions[0].p };
  await expectFail('client proof replayed', 'tube', runTube(await reaggregate(t)), 'nonce');
  t = clone(tube);
  t.actions[0].kind = hex(PLACE);
  t.actions[0].p = [0n, BID, 2000n, 1n, GTC, 0n, 0n, 0n].map(hex);
  await expectFail('client proof placing an order', 'tube', runTube(await reaggregate(await remsg(t, 0))), 'client proofs only manage session keys and withdraw');
  t = clone(tube);
  t.actions[2].p[1] = hex(78n);
  await expectFail('client-proof withdrawal to another recipient', 'tube', runTube(t), 'proof authorizes another action');
  t = clone(tube);
  t.actions[2].p[0] = hex(60_000n);
  await expectFail('client-proof withdrawal above the collateral', 'tube', runTube(await reaggregate(await remsg(t, 2))), 'collateral below the amount');
  t = clone(tube);
  t.actions[2].k_enc = hex(5n);
  await expectFail('client-proof withdrawal under another key', 'tube', runTube(t), 'k_enc does not open the commitment');
  t = clone(tube);
  t.agg.count = 11;
  await expectFail('more client actions than proof slots', 'tube', runTube(t), 'too many client proofs');
  t = clone(tube);
  t.actions[0].vk_hash = hex(prover.clientVks.client_p256);
  await expectFail('client proof under another client circuit', 'tube', runTube(await reaggregate(t)), 'client proof does not control the account');
  t = clone(tube);
  t.agg.vk_tree_root = hex(randomField());
  await expectFail('client proofs under another VK tree', 'tube', runTube(t), 'client proofs verified under another VK tree');
  t = clone(tube);
  t.actions[0].key_path[0] = hex(1n);
  await expectFail('client action on a forged key slot', 'tube', runTube(t), 'key slot path');
  // Last, as it leaves PE's state past an action the rules refuse: a proof applied to U, whose
  // master key is a Schnorr key.
  PE.relax.add('client-auth');
  const pt = PE.segments.length;
  await PE.proven([await byClient(U, 1n, ADD_KEY, [0n, pSess.pk.x, pSess.pk.y, 0b01n, 100_000n, now + 1000n])]);
  PE.relax.delete('client-auth');
  await expectFail('client proof for a lane-S account', 'tube', runTube(PE.segments[pt].inputs), 'client proof does not control the account');

  for (const r of results) console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name}  (${r.how})`);
  console.log(`${results.filter((r) => r.pass).length}/${results.length} rejected as intended`);
  await api.destroy();
  process.exit(results.every((r) => r.pass) ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
