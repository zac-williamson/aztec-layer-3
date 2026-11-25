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
import { p256Key } from './p256.ts';
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
  // The cases below tamper with seg_trade witnesses of resting orders and cancellations, which the
  // engine would otherwise put in seg_quote segments; the seg_quote cases come last.
  engine.quoteSegments = false;
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
    reqs.push(await M.depositRequest(h, idx(i), 1_000_000n, sender, now));
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
  under.quoteSegments = false; // seg_trade witnesses, as below
  under.relax.add('oracle-sigs');
  await under.beginBatch(1n, 0n, 0n, 0n);
  await under.block(now, [await update(under, 0n, 2000n, now, [2])]);
  await expectFail('index update below the signature threshold', 'seg_block', under.segments[0].inputs, 'not enough oracle signatures');
  // An engine that tolerates a 100% move builds the witness; the circuit applies the committed 10%.
  const looseParams = { ...params, markets: params.markets.map((m, i) => (i === 0 ? { ...m, maxJumpPpm: 2_000_000n } : m)) };
  const loose = await Engine.create(api, looseParams, prover.vkTreeRoot, protocol);
  loose.quoteSegments = false; // seg_trade witnesses, as below
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
  t.updates[0].bid = { ...t.updates[0].bid, has: false, price: '0', seq: '0', order: { side: hex(0n), account_index: '0', lots: '0', expiry: '0', epoch: '0', display: false, reduce_only: false } };
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
  // The queue commits to each deposit's amount (SPEC.md §10.3): no other amount opens it.
  t = clone(prio);
  t.items[1].dep_amount = (BigInt(t.items[1].dep_amount) * 2n).toString();
  await expectFail('deposit credited with an inflated amount', 'seg_priority', t, 'deposit opening');
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
  L.quoteSegments = false; // seg_trade witnesses, as below
  const lu = await Promise.all([11n, 12n, 13n].map((x) => keysFromSeed(h, x)));
  const [P, V, W] = [2n, 3n, 4n];
  const lreqs: M.Request[] = [];
  for (const [i, k] of lu.entries()) {
    const encC = await M.encCommitment(h, k.kEnc);
    L.keyring.set(encC, k.kEnc);
    const sender = randomField();
    lreqs.push({ kind: M.KIND.REGISTER, a: await M.masterAuthOf(h, k.pk!.x, k.pk!.y), b: encC, sender, time: now });
    lreqs.push(await M.depositRequest(h, BigInt(M.PROTOCOL_ACCOUNTS + i), [5_000_000n, 30_000n, 1_100n][i], sender, now));
  }
  lreqs.push(await M.depositRequest(h, M.INSURANCE_INDEX, 10_000n, randomField(), now));
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
  // The risk sweep (SPEC.md §8.7): V is due for liquidation, so a refresh may not pass it.
  const riskSnap = L.snapshot();
  L.relax.add('liq');
  await L.maintenance({ refresh: 4 });
  L.relax.clear();
  const riskRefresh = clone(L.segments.at(-1)!.inputs) as any;
  L.restore(riskSnap);
  await expectFail('refresh of an account due for liquidation', 'seg_refresh', riskRefresh, 'account is due for liquidation');
  await expectFail('liquidating a healthy account', 'seg_liquidate', await relaxed({ kind: 'cancel', account: P }), 'account is not liquidatable');
  await expectFail('closing before the orders are cancelled', 'seg_liquidate', await relaxed({ kind: 'close', account: V, market: 0 }), 'orders must be cancelled first');
  await L.liquidate([{ kind: 'cancel', account: V }]); // honest: voids all of V's orders
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

  // Dead orders (SPEC.md §6.5): a tick reads only live orders, and maintenance removes only void or
  // expired ones. Account 2 cancels all, voiding its last ask at 2,002; account 3 then rests a GTT
  // bid at 1,995 that expires before the next tick. A relaxed engine ticks over them, or removes
  // account 4's live bid; the honest engine removes the dead orders first, once time reaches them.
  await engine.trade([await act(0, 6n, X.KIND_ACT.CANCEL_ALL, [])]);
  const tickAt = now + 5n;
  engine.relax.add('cleanup');
  let saved = engine.snapshot();
  await engine.block(tickAt, [await update(engine, 0n, 2001n, tickAt)]);
  const voidTop = clone(engine.segments.at(-1)!.inputs) as any;
  engine.restore(saved);
  await engine.trade([await act(1, 5n, PLACE, [0n, BID, 1995n, 1n, X.TIF.GTT, 0n, now + 3n])]);
  saved = engine.snapshot();
  await engine.block(tickAt, [await update(engine, 0n, 2001n, tickAt)]);
  const expiredTop = clone(engine.segments.at(-1)!.inputs) as any;
  engine.restore(saved);
  saved = engine.snapshot();
  await engine.maintenance({ clean: [{ market: 0, index: X.orderIndex(BID, 1990n, bid1990.seq) }] });
  const liveRemoval = clone(engine.segments.at(-1)!.inputs) as any;
  engine.restore(saved);
  engine.relax.delete('cleanup');
  assert(engine.rejected.length === 0, `dead-order setup rejected: ${engine.rejected.map((r) => r.reason)}`);
  const nh = engine.segments.length;
  await engine.block(tickAt, [await update(engine, 0n, 2001n, tickAt)]);
  const honest = engine.segments.slice(nh);
  assert(honest.map((x) => x.pkg).join(',') === 'seg_block,seg_refresh,seg_block', `dead-order handling: ${honest.map((x) => x.label).join(' | ')}`);
  for (const x of honest) await execute(x.pkg, x.inputs);
  await expectFail('tick over a void order', 'seg_block', voidTop, 'void order at the top of the book');
  await expectFail('tick over an expired order', 'seg_block', expiredTop, 'expired order at the top of the book');
  await expectFail('removal of a live order', 'seg_refresh', liveRemoval, 'order is live');

  // Session keys, GTT and forced requests (SPEC.md §6.5, §7.2, §7.3). Q provides liquidity; R gives
  // a session key market 0 only, a 100,000 notional cap and an expiry, and its key rests a bid.
  const K = await Engine.create(api, params, prover.vkTreeRoot, protocol);
  K.quoteSegments = false; // seg_trade witnesses, as below
  const ku = await Promise.all([21n, 22n].map((x) => keysFromSeed(h, x)));
  const [Q, Rk] = [2n, 3n];
  const kaddr = [randomField(), randomField()];
  const kreqs: M.Request[] = [];
  for (const [i, k] of ku.entries()) {
    const encC = await M.encCommitment(h, k.kEnc);
    K.keyring.set(encC, k.kEnc);
    kreqs.push({ kind: M.KIND.REGISTER, a: await M.masterAuthOf(h, k.pk!.x, k.pk!.y), b: encC, sender: kaddr[i], time: now });
    kreqs.push(await M.depositRequest(h, BigInt(M.PROTOCOL_ACCOUNTS + i), [2_000_000n, 1_000_000n][i], kaddr[i], now));
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
  await expectFail('session key withdrawing', 'seg_trade', await reSess(clone(sessPlace), 1n, WITHDRAW, [10n, 77n]), 'session keys only place, cancel, modify and cancel all');
  await expectFail('session key adding a key', 'seg_trade', await reSess(clone(sessPlace), 1n, X.KIND_ACT.ADD_KEY, [1n, 5n, 6n, 1n, 1n, keyExpiry]), 'session keys only place, cancel, modify and cancel all');
  await expectFail('session key transferring', 'seg_trade', await reSess(clone(sessPlace), 1n, X.KIND_ACT.TRANSFER, [10n, Q]), 'session keys only place, cancel, modify and cancel all');
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
  // Forced requests: R closes its long against Q's bids; Q cancels all its orders, which voids
  // them. The probe path a close that stopped at once would need, on the book as it stands before
  // the close:
  const probe = K.books[0].path(X.orderIndex(M.SIDE.ASK, 1900n, K.markets[0].nextSeq)).map((x) => ({ hash: hex(x.hash), ask: x.ask.toString(), bid: x.bid.toString() }));
  const kf = K.segments.length;
  await K.priority([
    { kind: M.KIND.FORCED_CLOSE, a: Rk, b: 0n, c: 1900n, sender: kaddr[1], time: now },
    { kind: M.KIND.FORCED_CANCEL_ALL, a: Q, b: 0n, sender: kaddr[0], time: now },
  ]);
  const forcedClose = clone(K.segments[kf].inputs) as any;
  const forcedCancel = clone(K.segments[kf + 1].inputs) as any;
  // The close first cancels R's own resting bid (self-trade prevention), then fills against Q.
  assert(forcedClose.n_fills === 2 && K.actv.get(Q)!.epoch === 1n && K.actv.get(Q)!.openOrders === 0n, `forced setup: ${forcedClose.n_fills} steps`);
  await execute('seg_forced', forcedClose);
  await execute('seg_forced', forcedCancel);
  t = clone(forcedClose);
  t.n_fills = 0;
  t.probe_path = probe;
  await expectFail('forced close stops with liquidity left', 'seg_forced', t, 'crossing bids remain');
  // Order epochs (SPEC.md §6.5). R's sell meets Q's void best bid, which matching removes instead of
  // filling. Filling it would need Q's activity from before the cancel-all; removing a live order
  // as void would need an activity whose epoch moved. Neither is in the activity tree.
  const kv = K.segments.length;
  await K.trade([await kact(1, 3n, PLACE, [0n, ASK, 1990n, 5n, IOC, 0n])]);
  assert(K.rejected.length === 0 && K.segments.length === kv + 1, `void-order setup: ${K.rejected.map((r) => r.reason)}`);
  const voidHit = clone(K.segments[kv].inputs) as any;
  assert(voidHit.actions[0].n_fills === 1, 'the sell meets one void order');
  await execute('seg_trade', voidHit);
  t = clone(voidHit);
  const qRec = K.accts.get(Q)!;
  Object.assign(t.actions[0].fills[0], {
    maker_actv: forcedCancel.actv,
    maker_pub: M.pubToNoir(qRec.pub),
    maker_priv: M.privToNoir(qRec.priv),
    maker_k_enc: hex(qRec.kEnc),
    maker_acct_path: K.accounts.path(Q).map(hex),
  });
  await expectFail('void order filled', 'seg_trade', t, 'Merkle path does not match root');
  t = clone(buy);
  t.actions[0].fills[0].maker_actv.epoch = '1';
  await expectFail('live order removed as void', 'seg_trade', t, 'Merkle path does not match root');

  // Client-proof actions (SPEC.md §7.4). S is a lane-P account, U a lane-S one. An honest P-segment
  // grants S two session keys and withdraws 1,000 of its collateral; the tampered tube witnesses are
  // what an operator would need to apply actions no client proof authorized. The tube runs without its Chonk proof here (witness
  // generation does not check it), so each case shows the check the tube itself makes.
  const PE = await Engine.create(api, params, prover.vkTreeRoot, protocol, prover.clientVks);
  PE.quoteSegments = false; // seg_trade witnesses, as below
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
    preqs.push(await M.depositRequest(h, BigInt(M.PROTOCOL_ACCOUNTS + i), 50_000n, sender, now));
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

  // Passkey assertions (client_webauthn, SPEC.md §7.4). The client circuit itself refuses an
  // assertion of another challenge, one without user presence, one from another relying party, and
  // a registration in place of an assertion.
  const passkey = p256Key();
  const wsalt = randomField();
  const wmsg = randomField();
  const wit = await prover.webauthnWitness(passkey, wsalt, 'l3x.example', 'https://l3x.example', wmsg, 2n);
  await execute('client_webauthn', wit);
  let wt = clone(wit) as any;
  wt.msg = hex(wmsg ^ 1n);
  await expectFail('passkey assertion of another challenge', 'client_webauthn', wt, 'assertion for another challenge');
  wt = clone(wit) as any;
  wt.authenticator_data[32] = 0x04;
  await expectFail('passkey assertion without user presence', 'client_webauthn', wt, 'user not present');
  wt = clone(await prover.webauthnWitness(passkey, wsalt, 'evil.example', 'https://evil.example', wmsg, 2n)) as any;
  wt.auth_binding = wit.auth_binding;
  await expectFail('passkey assertion from another site', 'client_webauthn', wt, 'key does not match the auth binding');
  wt = clone(wit) as any;
  const create = [...new TextEncoder().encode('{"type":"webauthn.create"')];
  create.forEach((b, i) => (wt.client_data[i] = b));
  await expectFail('passkey registration in place of an assertion', 'client_webauthn', wt, 'not a WebAuthn assertion');

  // Triggers (SPEC.md §6.5). A fresh exchange: account 3 buys 20 in market 0 from account 2 and
  // sets two stop-losses (at 1960 and 1955) and a take-profit (at 2100); account 2 bids at 1950.
  const T = await Engine.create(api, params, prover.vkTreeRoot, protocol);
  T.quoteSegments = false; // seg_trade witnesses, as below
  const tu = await Promise.all([21n, 22n].map((x) => keysFromSeed(h, x)));
  const treqs: M.Request[] = [];
  for (const [i, k] of tu.entries()) {
    const encC = await M.encCommitment(h, k.kEnc);
    T.keyring.set(encC, k.kEnc);
    const sender = randomField();
    treqs.push({ kind: M.KIND.REGISTER, a: await M.masterAuthOf(h, k.pk!.x, k.pk!.y), b: encC, sender, time: now });
    treqs.push(await M.depositRequest(h, BigInt(M.PROTOCOL_ACCOUNTS + i), 2_000_000n, sender, now));
  }
  await T.beginBatch(1n, 0n, 0n, 0n);
  await T.block(now, [await update(T, 0n, 2000n, now)]);
  await T.priority(treqs);
  const { PLACE_TRIGGER, CANCEL_TRIGGER } = X.KIND_ACT;
  const { UP, DOWN } = X.DIR;
  const tacct = (u: number) => BigInt(M.PROTOCOL_ACCOUNTS + u);
  const tact = (u: number, nonce: bigint, kind: bigint, p: bigint[]) => signAction(h, T.domain, tu[u], kind, tacct(u), nonce, p);
  const tresign = async (inputs: any, i: number, u: number, nonce: bigint, kind: bigint, p: bigint[]) => {
    const a = await tact(u, nonce, kind, p);
    inputs.actions[i] = { ...inputs.actions[i], nonce: nonce.toString(), p: a.p.map(hex), sig: sigToNoir(a.sig) };
  };
  await T.trade([await tact(0, 1n, PLACE, [0n, ASK, 2000n, 20n, GTC, 0n]), await tact(1, 1n, PLACE, [0n, BID, 2000n, 20n, IOC, 0n])]);
  await T.trade([await tact(0, 2n, PLACE, [0n, BID, 1950n, 50n, GTC, 0n])]);
  const tPlace = T.segments.length;
  await T.trade([await tact(1, 2n, PLACE_TRIGGER, [0n, ASK, 1940n, 10n, DOWN, 1960n]), await tact(1, 3n, PLACE_TRIGGER, [0n, ASK, 1940n, 5n, DOWN, 1955n])]);
  const placeW = T.segments[tPlace].inputs as any;
  const spareSeq = T.markets[0].nextSeq + 1n;
  await T.trade([await tact(1, 4n, PLACE_TRIGGER, [0n, ASK, 2090n, 5n, UP, 2100n]), await tact(1, 5n, PLACE_TRIGGER, [0n, ASK, 1800n, 1n, DOWN, 1800n])]);
  const tCancel = T.segments.length;
  await T.trade([await tact(1, 6n, CANCEL_TRIGGER, [0n, DOWN, 1800n, spareSeq])]);
  const cancelW = T.segments[tCancel].inputs as any;
  assert(T.rejected.length === 0 && T.accts.get(tacct(1))!.priv.positions[0].size === 20n, `trigger setup rejected: ${T.rejected.map((r) => r.reason)}`);
  await T.block(now + 10n, [await update(T, 0n, 1950n, now + 9n)]);
  const tickW = T.segments[T.segments.length - 1].inputs as any;
  assert(T.markets[0].triggerPending, 'trigger setup: the stops are not due');
  const pathOf = (tree: { path(i: bigint): { hash: bigint; ask: bigint; bid: bigint }[] }, i: bigint) =>
    tree.path(i).map((x) => ({ hash: hex(x.hash), ask: x.ask.toString(), bid: x.bid.toString() }));
  const trigNoir = (x: X.Trigger) => ({ dir: hex(x.dir), side: hex(x.side), account_index: x.account.toString(), lots: x.lots.toString(), limit: x.limit.toString(), epoch: x.epoch.toString(), entry: !!x.entry });
  const resting = [...T.triggers[0].entries()];
  const [laterIdx, later] = resting.find(([, x]) => x.price === 1955n)!;
  const [tpIdx, tp] = resting.find(([, x]) => x.price === 2100n)!;
  const leftPath = pathOf(T.triggerTrees[0], X.LEFTMOST);
  const laterPath = pathOf(T.triggerTrees[0], laterIdx);
  const tpPath = pathOf(T.triggerTrees[0], tpIdx);
  // A malicious engine lets account 2 trade while the stops are due.
  const tPending = T.segments.length;
  T.relax.add('triggers');
  await T.trade([await tact(0, 3n, PLACE, [0n, ASK, 1960n, 1n, GTC, 0n])]);
  T.relax.clear();
  const pendingW = T.segments[tPending].inputs as any;
  const probePath = pathOf(T.books[0], X.orderIndex(ASK, 1940n, T.markets[0].nextSeq));
  const tFire = T.segments.length;
  await T.fireTriggers([0]);
  const fireW = T.segments[tFire].inputs as any;
  assert(!T.markets[0].triggerPending && T.accts.get(tacct(1))!.priv.positions[0].size === 5n, 'the stops did not fire');
  for (const [pkg, seg] of [['seg_trade', placeW], ['seg_trade', cancelW], ['seg_block', tickW], ['seg_trigger', fireW]] as const) {
    await execute(pkg, seg); // honest witnesses run
  }
  t = clone(placeW);
  await tresign(t, 0, 1, 2n, PLACE_TRIGGER, [0n, ASK, 1940n, 10n, DOWN, 2010n]);
  await expectFail('trigger placed already due', 'seg_trade', t, 'trigger already due');
  t = clone(cancelW);
  t.actions[0].trigger.account_index = tacct(0).toString();
  await expectFail("another account's trigger cancelled", 'seg_trade', t, "not the account's trigger");
  t = clone(tickW);
  t.updates[0].down = { has: false, price: '0', seq: '0', trigger: trigNoir({ ...later, lots: 0n, dir: 0n, side: 0n, account: 0n, limit: 0n, epoch: 0n }), path: leftPath };
  await expectFail('tick hides the due stops', 'seg_block', t, 'there are DOWN triggers');
  t = clone(tickW);
  t.updates[0].down = { has: true, price: later.price.toString(), seq: later.seq.toString(), trigger: trigNoir(later), path: laterPath };
  await expectFail('tick reports a lower stop as the next due', 'seg_block', t, 'not the highest DOWN trigger');
  await expectFail('order trades while triggers are due', 'seg_trade', pendingW, 'triggers are due in this market');
  t = clone(fireW);
  Object.assign(t, { dir: hex(UP), price: tp.price.toString(), seq: tp.seq.toString(), trigger: trigNoir(tp), trigger_path: tpPath });
  await expectFail('take-profit fired before its price', 'seg_trigger', t, 'trigger not due');
  t = clone(fireW);
  Object.assign(t, { price: later.price.toString(), seq: later.seq.toString(), trigger: trigNoir(later), trigger_path: laterPath });
  await expectFail('stop fired out of order', 'seg_trigger', t, 'an earlier trigger is due first');
  t = clone(fireW);
  Object.assign(t, { n_fills: 0, probe_path: probePath });
  await expectFail('firing drops the stop with bids left within its limit', 'seg_trigger', t, 'crossing bids remain');

  // Rekey (SPEC.md §7.3). A fresh exchange: account R0 grants a session key, then its owner rekeys
  // it through the Bridge, which delivered the new encryption key to the operator.
  const R = await Engine.create(api, params, prover.vkTreeRoot, protocol);
  R.quoteSegments = false; // seg_trade witnesses, as below
  const rKeys = await Promise.all([31n, 32n].map((s) => keysFromSeed(h, s)));
  const rOwners = [randomField(), randomField()];
  const rReqs: M.Request[] = [];
  for (const [i, k] of rKeys.entries()) {
    const encC = await M.encCommitment(h, k.kEnc);
    R.keyring.set(encC, k.kEnc);
    rReqs.push({ kind: M.KIND.REGISTER, a: await M.masterAuthOf(h, k.pk!.x, k.pk!.y), b: encC, sender: rOwners[i], time: now });
    rReqs.push(await M.depositRequest(h, idx(i), 1_000_000n, rOwners[i], now));
  }
  await R.beginBatch(1n, 0n, 0n, 0n);
  await R.block(now, [await update(R, 0n, 2000n, now)]);
  await R.priority(rReqs);
  const rSession = await keysFromSeed(h, 33n);
  const R0 = idx(0);
  await R.trade([await signAction(h, R.domain, rKeys[0], X.KIND_ACT.ADD_KEY, R0, 1n, [0n, rSession.pk.x, rSession.pk.y, 0b1n, 1_000_000n, now + 1000n])]);
  const rNext = await keysFromSeed(h, 34n);
  const rNextC = await M.encCommitment(h, rNext.kEnc);
  R.keyring.set(rNextC, rNext.kEnc);
  const rekeyFrom = async (sender: bigint): Promise<M.Request> => ({ kind: M.KIND.REKEY, a: R0, b: await M.masterAuthOf(h, rNext.pk!.x, rNext.pk!.y), c: rNextC, sender, time: now });
  // The operator applies a rekey that R1's owner sent for R0: the circuit consumes it without
  // effect, so the state the operator claims is not the one the segment proves.
  const beforeRekey = R.snapshot();
  R.relax.add('rekey-owner');
  await R.priority([await rekeyFrom(rOwners[1])]);
  R.relax.delete('rekey-owner');
  const foreign = R.segments.at(-1)!;
  R.restore(beforeRekey);
  {
    const { returnValue } = (await execute('seg_priority', foreign.inputs)) as any;
    const proved = BigInt(returnValue.end.state);
    results.push({ name: "a rekey of someone else's account applied", pass: proved !== foreign.expectedEnd.state, how: proved !== foreign.expectedEnd.state ? 'consumed without effect: the proved state differs from the claimed one' : 'APPLIED' });
  }
  await R.priority([await rekeyFrom(rOwners[0])]);
  t = clone(R.segments.at(-1)!.inputs);
  t.items[0].k_enc = hex(424242n);
  await expectFail('rekey published under a key the operator was not given', 'seg_priority', t, 'k_enc does not open the commitment');
  // A relaxed engine lets the session key act after the rekey.
  R.relax.add('revoked-keys');
  await R.trade([await signAction(h, R.domain, rSession, X.KIND_ACT.PLACE, R0, 1n, [0n, M.SIDE.BID, 1990n, 1n, X.TIF.GTC, 0n], 0n)]);
  R.relax.delete('revoked-keys');
  assert(R.rejected.length === 0, `rekey setup rejected: ${R.rejected.map((r) => r.reason)}`);
  await expectFail('session key acts after a rekey', 'seg_trade', R.segments.at(-1)!.inputs, 'session key revoked by a rekey');

  // Fee tiers (SPEC.md §8.6): the operator chooses an account's tier, but only among those that
  // exist, and only for an account that exists.
  const beforeTiers = R.snapshot();
  R.relax.add('tiers');
  await R.maintenance({ tiers: [{ account: idx(1), tier: BigInt(M.FEE_TIERS) }] });
  R.relax.delete('tiers');
  const badTier = R.segments.at(-1)!.inputs;
  R.restore(beforeTiers);
  await expectFail('a fee tier that does not exist', 'seg_refresh', badTier, 'fee tier');
  await R.maintenance({ tiers: [{ account: idx(1), tier: 1n }] });
  t = clone(R.segments.at(-1)!.inputs);
  t.tiers[0].account_index = '9';
  await expectFail('a fee tier for an account that does not exist', 'seg_refresh', t, 'Merkle path does not match root');

  // Display [D1]: the flag is 0 or 1, and a displayed order is in the book's leaf, so the operator
  // cannot fill or cancel it as if undisplayed, which would skip publishing its new lots.
  t = clone(quiet);
  await resign(t, 0, 2, 2n, PLACE, [0n, BID, 1990n, 5n, GTC, 0n, 0n, 2n]);
  await expectFail('a display flag out of range', 'seg_trade', t, 'display flag');
  const rNonce = (i: bigint) => R.actv.get(i)!.nonce + 1n;
  await R.trade([await signAction(h, R.domain, rKeys[1], PLACE, idx(1), rNonce(idx(1)), [0n, ASK, 2001n, 2n, GTC, 0n, 0n, 1n])]);
  await R.trade([await signAction(h, R.domain, rNext, PLACE, R0, rNonce(R0), [0n, BID, 2001n, 1n, IOC, 0n])]);
  t = clone(R.segments.at(-1)!.inputs);
  assert(t.actions[0].fills[0].order.display === true, 'the fill is against the displayed ask');
  t.actions[0].fills[0].order.display = false;
  await expectFail('a displayed order filled as if undisplayed', 'seg_trade', t, 'maker order path');
  const shownAsk = [...R.orders[0].values()].find((o) => o.account === idx(1))!;
  await R.trade([await signAction(h, R.domain, rKeys[1], X.KIND_ACT.CANCEL, idx(1), rNonce(idx(1)), [0n, ASK, 2001n, shownAsk.seq])]);
  t = clone(R.segments.at(-1)!.inputs);
  t.actions[0].cancel_display = false;
  await expectFail('a displayed order cancelled as if undisplayed', 'seg_trade', t, 'book path does not match root');
  assert(R.rejected.length === 0, `display setup rejected: ${R.rejected.map((r) => r.reason)}`);

  // Stops that open a position (P2.20): the entry flag is 0 or 1, and an entry stop the owner
  // cannot afford when it fires is undone, whatever the operator claims.
  t = clone(quiet);
  await resign(t, 0, 2, 2n, X.KIND_ACT.PLACE_TRIGGER, [0n, BID, 1990n, 5n, X.DIR.UP, 2100n, 2n]);
  t.actions[0].kind = hex(X.KIND_ACT.PLACE_TRIGGER);
  await expectFail('an entry flag out of range', 'seg_trade', t, 'trigger payload');
  await R.trade([await signAction(h, R.domain, rKeys[1], WITHDRAW, idx(1), rNonce(idx(1)), [950_000n, 77n])]);
  await R.trade([await signAction(h, R.domain, rNext, PLACE, R0, rNonce(R0), [0n, ASK, 2005n, 300n, GTC, 0n])]);
  await R.trade([await signAction(h, R.domain, rKeys[1], X.KIND_ACT.PLACE_TRIGGER, idx(1), rNonce(idx(1)), [0n, BID, 2010n, 300n, X.DIR.UP, 2003n, 1n])]);
  assert(R.rejected.length === 0, `entry setup rejected: ${R.rejected.map((r) => r.reason)}`);
  await R.block(now + 2n, [await update(R, 0n, 2004n, now + 2n)]);
  R.relax.add('entry-margin');
  await R.fireTriggers([0]);
  R.relax.delete('entry-margin');
  const overreach = R.segments.at(-1)!;
  assert(overreach.pkg === 'seg_trigger' && overreach.label.includes('filled 300 of 300'), `entry firing: ${overreach.label}`);
  // The circuit undoes the fill, so the operator's witness, built on the filled state, either
  // fails against the restored roots or proves a state other than the one claimed.
  try {
    const { returnValue } = (await execute('seg_trigger', overreach.inputs)) as any;
    const proved = BigInt(returnValue.end.state);
    results.push({ name: 'an unaffordable entry stop filled', pass: proved !== overreach.expectedEnd.state, how: proved !== overreach.expectedEnd.state ? 'undone: the proved state differs from the claimed one' : 'FILLED' });
  } catch (e: any) {
    const msg = String(e?.message ?? e).split('\n')[0];
    results.push({ name: 'an unaffordable entry stop filled', pass: msg.includes('Merkle path does not match root'), how: `undone: ${msg.slice(0, 100)}` });
  }

  // Resting reduce-only orders (P2.21): one must fit within the position it reduces, and the
  // operator cannot trim one away by misstating its owner's position, which the trim rests on.
  const long2 = engine.accts.get(idx(2))!.priv.positions[0].size;
  assert(long2 > 0n, 'account 4 is long in market 0');
  t = clone(quiet);
  await resign(t, 0, 2, 2n, PLACE, [0n, ASK, 1990n, long2 + 1n, GTC, 1n]);
  await expectFail('a resting reduce-only order larger than the position', 'seg_trade', t, 'reduce-only order larger than the position');
  const q0 = engine.segments.length;
  await engine.trade([await act(2, engine.actv.get(idx(2))!.nonce + 1n, PLACE, [0n, ASK, 2003n, 1n, GTC, 1n])]);
  await engine.trade([await act(1, engine.actv.get(idx(1))!.nonce + 1n, PLACE, [0n, BID, 2003n, 1n, IOC, 0n])]);
  assert(engine.segments.length === q0 + 2 && engine.rejected.length === 0, `reduce-only setup: ${engine.rejected.map((r) => r.reason)}`);
  t = clone(engine.segments[q0 + 1].inputs);
  const roFill = t.actions[0].fills.findIndex((f: any) => f.order.reduce_only);
  assert(roFill >= 0, 'the buy meets the reduce-only ask');
  t.actions[0].fills[roFill].maker_priv.positions[0].size = '0';
  await expectFail('a reduce-only order trimmed by misstating its owner\'s position', 'seg_trade', t, 'Merkle path does not match root');

  // A signed rotation (P2.22) must name a master authorization.
  t = clone(quiet);
  await resign(t, 0, 2, 2n, X.KIND_ACT.SET_MASTER_AUTH, [0n]);
  t.actions[0].kind = hex(X.KIND_ACT.SET_MASTER_AUTH);
  await expectFail('a rotation to an empty master authorization', 'seg_trade', t, 'empty master authorization');

  // Quote segments (P2.25): an honest resting bid and an honest cancellation, then tampered with.
  engine.quoteSegments = true;
  const nonceOf = (u: number) => engine.actv.get(idx(u))!.nonce;
  await engine.trade([await act(0, nonceOf(0) + 1n, PLACE, [0n, ASK, 2005n, 5n, GTC, 0n])]); // an ask for the crossing case
  const bestAsk = [...engine.orders[0].values()].filter((o) => o.side === ASK).reduce((m, o) => (o.price < m ? o.price : m), X.MAX_PRICE);
  const seq0 = engine.markets[0].nextSeq;
  const crossPath = engine.books[0].path(X.orderIndex(BID, bestAsk, seq0)).map((x) => ({ hash: hex(x.hash), ask: x.ask.toString(), bid: x.bid.toString() }));
  const nq = nonceOf(1) + 1n;
  const qs = engine.segments.length;
  await engine.trade([await act(1, nq, PLACE, [0n, BID, 1980n, 2n, GTC, 0n])]);
  await engine.trade([await act(1, nq + 1n, X.KIND_ACT.CANCEL, [0n, BID, 1980n, seq0])]);
  assert(engine.segments[qs].pkg === 'seg_quote' && engine.segments[qs + 1].pkg === 'seg_quote' && engine.rejected.length === 0, 'quote setup');
  const quote = engine.segments[qs].inputs as any;
  const cancelQ = engine.segments[qs + 1].inputs as any;
  await execute('seg_quote', quote);
  await execute('seg_quote', cancelQ);
  t = clone(quote);
  await resign(t, 0, 1, nq, PLACE, [0n, BID, bestAsk, 2n, GTC, 0n]);
  t.actions[0].book_path = crossPath;
  await expectFail('a quote that would fill', 'seg_quote', t, 'the order would fill');
  t = clone(quote);
  await resign(t, 0, 1, nq, PLACE, [0n, BID, 1980n, 2n, IOC, 0n]);
  await expectFail('an IOC order as a quote', 'seg_quote', t, 'a quote rests');
  t = clone(quote);
  await resign(t, 0, 1, nq, PLACE, [0n, BID, 1980n, 10_000_000n, GTC, 0n]);
  await expectFail('a quote beyond its margin', 'seg_quote', t, 'insufficient margin');
  t = clone(quote);
  await resign(t, 0, 1, nq - 1n, PLACE, [0n, BID, 1980n, 2n, GTC, 0n]);
  await expectFail('a quote with a replayed nonce', 'seg_quote', t, 'nonce');
  t = clone(cancelQ);
  t.actions[0].order_lots = '1';
  await expectFail('a cancellation that misstates the order', 'seg_quote', t, 'book path does not match root');

  for (const r of results) console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name}  (${r.how})`);
  console.log(`${results.filter((r) => r.pass).length}/${results.length} rejected as intended`);
  await api.destroy();
  process.exit(results.every((r) => r.pass) ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
