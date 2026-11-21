// Adversarial witnesses for the segment circuits (SPEC.md §17). Each case builds an honest witness
// with the engine, tampers with it the way a malicious operator could, and checks that the circuit
// refuses it, with the expected assertion. Execution only, no proving: a witness that cannot be
// generated cannot be proved.
import { join } from 'node:path';
import { Noir } from '@aztec-foundation/noir-noir_js';
import { OUT, hex, randomField, readCircuit, readJson } from '../lib.ts';
import { Prover, assert, newApi } from '../pipeline.ts';
import { Engine, type SignedAction, signAction, signUpdate } from './engine.ts';
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
  const p0 = [0n, BID, 1990n, 5n, GTC, 0n];
  t.actions[0].taker_pub.master_auth = hex(await M.masterAuthOf(h, evil.pk!.x, evil.pk!.y));
  t.actions[0].pk_x = hex(evil.pk!.x);
  t.actions[0].pk_y = hex(evil.pk!.y);
  t.actions[0].sig = sigToNoir(await sign(h, evil.sk, await X.actionMsg(h, engine.domain, PLACE, idx(2), 2n, p0)));
  await expectFail('operator substitutes the signing key', 'seg_trade', t, 'Merkle path does not match root');
  t = clone(buy);
  await resign(t, 0, 1, 0n, PLACE, [0n, BID, 2002n, 5n, IOC, 0n]);
  await expectFail('replayed nonce', 'seg_trade', t, 'nonce');

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
  t.updates[0].bid = { ...t.updates[0].bid, has: false, price: '0', seq: '0', order: { side: hex(0n), account_index: '0', lots: '0' } };
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

  for (const r of results) console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name}  (${r.how})`);
  console.log(`${results.filter((r) => r.pass).length}/${results.length} rejected as intended`);
  await api.destroy();
  process.exit(results.every((r) => r.pass) ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
