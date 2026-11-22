// Native test (no network): the engine builds batches of real exchange actions across several
// markets, every segment is proved and checked against the engine, the root binds the header,
// conservation is checked exactly after every batch, and every account is then reconstructed and
// opened from the DA payloads alone.
import { join } from 'node:path';
import { OUT, hex, randomField, readJson, writeJson } from '../lib.ts';
import { type BatchWitness, type ProvedBatch, Prover, assert, executeBatch, foldReceipt, newApi, proveBatch, receiptLeaf, receiptPath } from '../pipeline.ts';
import { decodeBatch, openAccount, rebuildAccounts } from './da.ts';
import { Engine, signAction, signUpdate } from './engine.ts';
import { keysFromSeed } from './grumpkin.ts';
import * as M from './model.ts';
import { genesisState, protocolAccounts, testParams } from './params.ts';
import * as X from './rules.ts';

const log = (m: string) => console.log(`[native] ${m}`);
/** EXECUTE_ONLY=1 executes every segment and compares it with the engine, without proving. */
const EXECUTE_ONLY = !!process.env.EXECUTE_ONLY;
const show = (x: unknown) => JSON.stringify(x, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));

/**
 * Exact conservation (SPEC.md §8.8), in micro-units: every account's collateral, unrealized PnL at
 * the marks and exact unrealized funding, plus uncredited fees and insurance remainders, equals the
 * net credited deposits.
 */
function checkConservation(e: Engine, netDeposits: bigint, label: string) {
  let total = (e.feesPending * X.MICRO) + e.insuranceMicro;
  for (const rec of e.accts.values()) {
    total += (rec.priv.collateral) * X.MICRO;
    rec.priv.positions.forEach((p, m) => {
      total += (p.size * e.markets[m].markPrice - p.entry) * X.MICRO - p.size * (e.markets[m].cumFunding - p.funding);
    });
  }
  e.markets.forEach((m, i) => assert(m.oiLong === m.oiShort, `${label}: market ${i} open interest out of balance`));
  assert(total === netDeposits * X.MICRO, `${label}: conservation fails: ${total} != ${netDeposits * X.MICRO}`);
}

async function main() {
  const manifest = readJson(join(OUT, 'manifest.json'));
  const api = await newApi();
  const h = M.hasher(api);
  const { params, oracleSks } = await testParams(h);
  const prover = await Prover.create(api, manifest, await M.paramsHash(h, params));
  const settled: ProvedBatch[] = [];
  let receiptCount = 0;
  /** Proves (or executes) a batch, then checks every receipt's path to its receipts root (SPEC.md §11). */
  const settle = async (w: BatchWitness) => {
    const b = await (EXECUTE_ONLY ? executeBatch(prover, w, log) : proveBatch(prover, w, log));
    for (const r of engine.receipts) {
      const p = await receiptPath(api, b, r.segment, r.slot);
      assert(p.depth <= 24, 'receipt path too deep');
      assert((await foldReceipt(api, await receiptLeaf(api, r.seq, r.msg), p)) === b.receiptsRoot, `receipt ${r.seq} has no path to the receipts root`);
      receiptCount++;
    }
    settled.push(b);
    return b;
  };
  const protocol = await protocolAccounts(h);
  const engine = await Engine.create(api, params, BigInt(manifest.vkTree.root), protocol);
  // Execute-only runs may use circuits newer than the manifest, so they check genesis directly.
  const genesis = EXECUTE_ONLY ? await genesisState(api, protocol) : { trees: BigInt(manifest.genesisTrees), stateRoot: BigInt(manifest.genesisStateRoot) };
  assert((await engine.trees()) === genesis.trees, 'engine genesis != manifest genesis');
  const update = (market: bigint, price: bigint, external: bigint, time: bigint) => signUpdate(h, engine.domain, oracleSks, [0, 2], market, price, external, time);

  const now = BigInt(Math.floor(Date.now() / 1000)) - 10_000n;
  const users = await Promise.all([101n, 202n, 303n, 404n, 505n, 606n].map(async (seed) => ({ seed, addr: randomField(), keys: await keysFromSeed(h, seed) })));
  const [alice, bob, carol, dave, eve, frank] = users.map((u) => u.keys);
  const [A, B, C, D, E, F] = [2n, 3n, 4n, 5n, 6n, 7n]; // account indices after the two protocol accounts
  const reqs: M.Request[] = [];
  for (const [i, u] of users.entries()) {
    const masterAuth = await M.masterAuthOf(h, u.keys.pk!.x, u.keys.pk!.y);
    const encC = await M.encCommitment(h, u.keys.kEnc);
    engine.keyring.set(encC, u.keys.kEnc); // delivered by Bridge.register in a deployment
    reqs.push({ kind: M.KIND.REGISTER, a: masterAuth, b: encC, sender: u.addr, time: now - 100n + BigInt(i) });
  }
  reqs.push({ kind: M.KIND.DEPOSIT, a: A, b: 1_000_000n, sender: users[0].addr, time: now - 90n });
  reqs.push({ kind: M.KIND.DEPOSIT, a: B, b: 2_000_000n, sender: users[1].addr, time: now - 85n });
  reqs.push({ kind: M.KIND.DEPOSIT, a: C, b: 3_000_000n, sender: users[2].addr, time: now - 84n });
  reqs.push({ kind: M.KIND.DEPOSIT, a: D, b: 5_000_000n, sender: users[3].addr, time: now - 83n });
  reqs.push({ kind: M.KIND.DEPOSIT, a: E, b: 30_000n, sender: users[4].addr, time: now - 82n });
  reqs.push({ kind: M.KIND.DEPOSIT, a: F, b: 25_000n, sender: users[5].addr, time: now - 81n });
  reqs.push({ kind: M.KIND.DEPOSIT, a: 99n, b: 500n, sender: users[1].addr, time: now - 80n }); // no account 99: refund
  reqs.push({ kind: M.KIND.DEPOSIT, a: M.INSURANCE_INDEX, b: 20_000n, sender: users[2].addr, time: now - 79n }); // seed the insurance fund
  let netDeposits = 11_075_000n;
  const report: Record<string, unknown> = {};

  // Batch 1: indices for three markets, registrations, deposits, a refund.
  await engine.beginBatch(1n, 0n, 0n, 0n);
  await engine.block(now, [await update(0n, 2000n, 2002n, now - 5n), await update(1n, 30_000n, 30_010n, now - 5n), await update(2n, 100n, 100n, now - 5n)]);
  await engine.priority(reqs);
  checkConservation(engine, netDeposits, 'batch 1');
  const w1 = await engine.endBatch();
  log(`batch 1: ${w1.segments.map((s) => s.label).join(' | ')}; ${w1.daPayload.length} DA fields`);
  const b1 = await settle(w1);
  assert(b1.header[0] === genesis.stateRoot, 'batch 1 does not start from genesis');

  // Batch 2: trading in markets 0 and 1, with orders the rules must refuse mixed in.
  const act = (who: typeof alice, account: bigint, nonce: bigint, kind: bigint, p: bigint[]) => signAction(h, engine.domain, who, kind, account, nonce, p);
  const { BID, ASK } = M.SIDE;
  const { PLACE, CANCEL, WITHDRAW } = X.KIND_ACT;
  const { GTC, IOC, FOK, POST_ONLY } = X.TIF;
  await engine.beginBatch(2n, b1.end.priorityHead, b1.end.priorityCursor, b1.end.time);
  const t2 = now + 5n;
  await engine.block(t2);
  await engine.trade([
    await act(alice, A, 1n, PLACE, [0n, BID, 2000n, 100n, GTC, 0n]),
    await act(alice, A, 2n, PLACE, [0n, BID, 2000n, 10_000_000n, GTC, 0n]), // far beyond her margin
    await act(bob, B, 1n, PLACE, [0n, ASK, 1990n, 60n, IOC, 0n]), // sells 60 to Alice at 2000
    await act(bob, B, 1n, PLACE, [0n, ASK, 1990n, 1n, IOC, 0n]), // replayed nonce
    await act(carol, C, 1n, PLACE, [1n, ASK, 30_100n, 5n, POST_ONLY, 0n]),
    await act(bob, B, 2n, PLACE, [1n, BID, 30_200n, 1n, POST_ONLY, 0n]), // would cross Carol
    await act(bob, B, 2n, PLACE, [1n, BID, 30_150n, 10n, FOK, 0n]), // only 5 offered
    await act(bob, B, 2n, PLACE, [1n, BID, 30_150n, 3n, IOC, 0n]), // buys 3 from Carol at 30,100
    await act(bob, B, 3n, PLACE, [0n, ASK, 1990n, 5n, IOC, 1n]), // reduce-only, but Bob is short in market 0
    await act(alice, A, 2n, PLACE, [1n, BID, 29_900n, 1n, GTC, 0n]),
    await act(alice, A, 3n, CANCEL, [0n, BID, 2000n, 0n]), // the rest of her market-0 bid
    await act(bob, B, 3n, WITHDRAW, [1000n, users[1].addr]),
  ]);
  const reasons = engine.rejected.map((r) => r.reason);
  log(`engine refused: ${reasons.join('; ')}`);
  assert(
    reasons.join('|') === 'insufficient margin|nonce|post-only order would take liquidity|fill-or-kill order not filled|reduce-only order must reduce',
    'unexpected rejections',
  );
  netDeposits -= 1000n;
  // A mark tick for market 1 with both sides of its book populated: mid = (29,900 + 30,100) / 2.
  await engine.block(t2 + 1n, [await update(1n, 30_000n, 30_050n, t2)]);
  assert(engine.markets[1].bestBid === 29_900n && engine.markets[1].bestAsk === 30_100n, 'top of book');
  assert(engine.markets[1].markPrice === 30_000n, `market 1 mark ${engine.markets[1].markPrice}`);
  // Self-trade prevention: Carol's own resting ask is cancelled, then her bid takes Bob's ask.
  await engine.trade([
    await act(bob, B, 4n, PLACE, [1n, ASK, 30_120n, 1n, GTC, 0n]),
    await act(carol, C, 2n, PLACE, [1n, BID, 30_120n, 1n, IOC, 0n]),
  ]);
  assert(engine.rejected.length === 5, `unexpected rejection: ${engine.rejected.at(-1)?.reason}`);
  assert(engine.orders[1].size === 1, 'market 1 book after self-trade prevention');
  const feesBefore = engine.feesPending;
  await engine.maintenance({ sweep: true, refresh: 4 });
  assert(engine.accts.get(M.FEE_INDEX)!.priv.collateral === feesBefore, 'fees swept');
  checkConservation(engine, netDeposits, 'batch 2');
  const w2 = await engine.endBatch();
  log(`batch 2: ${w2.segments.map((s) => s.label).join(' | ')}; ${w2.daPayload.length} DA fields`);
  const b2 = await settle(w2);
  assert(b2.header[0] === b1.header[1], 'batch 2 does not chain from batch 1');

  // Batch 3: an hour later funding is due in markets 0 and 1, and the next ticks apply it. Carol
  // then takes 20 of Alice's market-0 position, which settles Alice's funding.
  await engine.beginBatch(3n, b2.end.priorityHead, b2.end.priorityCursor, b2.end.time);
  const t3 = now + 3700n;
  await engine.block(t3, [await update(0n, 2010n, 2050n, t3 - 1n), await update(1n, 30_010n, 30_000n, t3 - 1n)]);
  const m0 = engine.markets[0];
  log(`market 0 at t+3700: index ${m0.indexPrice}, mark ${m0.markPrice}, funding rate ${m0.fundingRate} ppm, cum ${m0.cumFunding}`);
  assert(m0.cumFunding !== 0n && engine.markets[1].cumFunding !== 0n, 'funding applied');
  await engine.trade([
    await act(carol, C, 3n, PLACE, [0n, BID, 2010n, 20n, GTC, 0n]),
    await act(alice, A, 4n, PLACE, [0n, ASK, 2005n, 20n, IOC, 1n]), // reduce-only close of 20
  ]);
  assert(engine.rejected.length === 5, `unexpected rejection: ${engine.rejected.at(-1)?.reason}`);
  await engine.maintenance({ sweep: true, refresh: 4 });
  checkConservation(engine, netDeposits, 'batch 3');
  const w3 = await engine.endBatch();
  log(`batch 3: ${w3.segments.map((s) => s.label).join(' | ')}; ${w3.daPayload.length} DA fields`);
  const b3 = await settle(w3);
  assert(b3.header[0] === b2.header[1], 'batch 3 does not chain from batch 2');

  // Batch 4: liquidation (SPEC.md §8.5). Eve and Frank buy in market 0 from Dave; Eve also rests
  // an ask. The index then falls 13% in two updates within one block, which leaves both underwater.
  // Eve: her ask is cancelled, part of her position closes against Dave's new bid, the insurance
  // account takes over the rest and absorbs her deficit. Frank: the insurance account, seeded small,
  // cannot also absorb his position, so it is auto-deleveraged against Dave's short at Frank's
  // bankruptcy price.
  await engine.beginBatch(4n, b3.end.priorityHead, b3.end.priorityCursor, b3.end.time);
  const t4 = now + 3800n;
  await engine.block(t4, [await update(0n, 2000n, 2000n, t4 - 1n)]);
  await engine.trade([
    await act(dave, D, 1n, PLACE, [0n, ASK, 2000n, 400n, GTC, 0n]),
    await act(eve, E, 1n, PLACE, [0n, BID, 2000n, 120n, IOC, 0n]),
    await act(frank, F, 1n, PLACE, [0n, BID, 2000n, 100n, IOC, 0n]),
    await act(eve, E, 2n, PLACE, [0n, ASK, 2050n, 1n, GTC, 0n]),
  ]);
  assert(engine.rejected.length === 5, `unexpected rejection: ${engine.rejected.at(-1)?.reason}`);
  await engine.block(t4 + 1n, [await update(0n, 1840n, 1840n, t4), await update(0n, 1740n, 1740n, t4 + 1n)]);
  assert(engine.markets[0].markPrice === 1740n, `market 0 mark after the fall: ${engine.markets[0].markPrice}`);
  await engine.trade([await act(dave, D, 2n, PLACE, [0n, BID, 1745n, 30n, GTC, 0n])]);
  assert(engine.rejected.length === 5, `unexpected rejection: ${engine.rejected.at(-1)?.reason}`);
  const before4 = { eve: engine.health(E), frank: engine.health(F) };
  log(`after the fall: eve equity ${before4.eve.equity} (MM ${before4.eve.mm / X.PPM}), frank equity ${before4.frank.equity} (MM ${before4.frank.mm / X.PPM})`);
  assert(before4.eve.liquidatable && before4.frank.closeout, 'both accounts liquidatable');
  const eveSteps = await engine.liquidateAccount(E);
  const frankSteps = await engine.liquidateAccount(F, () => D);
  const kinds = [...eveSteps, ...frankSteps].map((x) => x.kind).join(', ');
  log(`liquidation steps: ${kinds}`);
  assert(kinds === 'cancel, close, takeover, deficit, adl', `unexpected waterfall: ${kinds}`);
  const ins = engine.accts.get(M.INSURANCE_INDEX)!.priv;
  for (const [name, i] of [['eve', E], ['frank', F]] as const) {
    const p = engine.accts.get(i)!.priv;
    assert(p.collateral === 0n && p.positions.every((x) => x.size === 0n), `${name} not fully liquidated: ${show(p)}`);
  }
  assert(ins.positions[0].size === 90n && engine.accts.get(D)!.priv.positions[0].size === -90n, 'positions after liquidation');
  log(`insurance: long ${ins.positions[0].size} in market 0, collateral ${ins.collateral} (+${engine.insurancePending} liquidation fees pending); dave short ${-engine.accts.get(D)!.priv.positions[0].size}`);
  await engine.maintenance({ sweep: true, refresh: 4 });
  checkConservation(engine, netDeposits, 'batch 4');
  const w4 = await engine.endBatch();
  log(`batch 4: ${w4.segments.map((s) => s.label).join(' | ')}; ${w4.daPayload.length} DA fields`);
  const b4 = await settle(w4);
  assert(b4.header[0] === b3.header[1], 'batch 4 does not chain from batch 3');

  // Batch 5: session keys, GTT and forced requests (SPEC.md §6.5, §7.2, §7.3). Alice gives a
  // session key markets 0 and 1, a 500,000 notional cap and an expiry; it rests a GTT bid, and the
  // engine refuses its order in market 2, its oversized order and its withdrawal. Once the GTT bid
  // has expired, Bob's sell removes it and fills Carol's bid behind it. Alice revokes the key, whose
  // next order is refused. The queue then carries Carol's forced withdrawal, a forced withdrawal
  // Eve submits for Alice's account (no effect), Bob's forced close and Dave's forced cancel-all.
  await engine.beginBatch(5n, b4.end.priorityHead, b4.end.priorityCursor, b4.end.time);
  const t5 = now + 3900n;
  await engine.block(t5, [await update(0n, 1750n, 1750n, t5 - 1n), await update(1n, 30_010n, 30_010n, t5 - 1n)]);
  const sess = await keysFromSeed(h, 9001n);
  const SLOT = 3n;
  const { ADD_KEY, REVOKE_KEY } = X.KIND_ACT;
  const bySession = (nonce: bigint, kind: bigint, p: bigint[]) => signAction(h, engine.domain, sess, kind, A, nonce, p, SLOT);
  await engine.trade([
    await act(alice, A, 5n, ADD_KEY, [SLOT, sess.pk.x, sess.pk.y, 0b0011n, 500_000n, t5 + 1000n]),
    await bySession(1n, PLACE, [0n, BID, 1745n, 10n, X.TIF.GTT, 0n, t5 + 5n]),
    await bySession(2n, PLACE, [2n, BID, 100n, 1n, GTC, 0n]), // market 2 is outside the mask
    await bySession(2n, PLACE, [0n, BID, 1745n, 1000n, GTC, 0n]), // notional 1,745,000 > 500,000
    await bySession(2n, WITHDRAW, [10n, users[0].addr]), // session keys cannot withdraw
    await act(carol, C, 4n, PLACE, [0n, BID, 1740n, 15n, GTC, 0n]),
  ]);
  await engine.block(t5 + 10n);
  await engine.trade([
    await act(bob, B, 5n, PLACE, [0n, ASK, 1700n, 10n, IOC, 0n]), // removes the expired GTT bid, fills Carol
    await act(alice, A, 6n, REVOKE_KEY, [SLOT]),
    await bySession(2n, PLACE, [0n, BID, 1745n, 1n, GTC, 0n]), // revoked
  ]);
  const reasons5 = engine.rejected.slice(5).map((r) => r.reason);
  log(`engine refused: ${reasons5.join('; ')}`);
  assert(
    reasons5.join('|') ===
      "market not allowed for the session key|order above the session key's notional limit|session keys only place and cancel|signing key is not the slot's",
    'unexpected batch 5 rejections',
  );
  assert(engine.accts.get(C)!.priv.positions[0].size === 30n && engine.orders[0].size > 0, 'GTT removal and fill');
  assert(![...engine.orders[0].values()].some((o) => o.account === A), 'expired GTT bid still resting');
  const carolBefore = engine.accts.get(C)!.priv.collateral;
  await engine.priority([
    { kind: M.KIND.FORCED_WITHDRAW, a: C, b: users[2].addr, sender: users[2].addr, time: t5 },
    { kind: M.KIND.FORCED_WITHDRAW, a: A, b: users[4].addr, sender: users[4].addr, time: t5 }, // not the owner
    { kind: M.KIND.FORCED_CLOSE, a: B, b: 0n, c: 2100n, sender: users[1].addr, time: t5 },
    { kind: M.KIND.FORCED_CANCEL_ALL, a: D, b: 0n, sender: users[3].addr, time: t5 },
  ]);
  const forcedOut = carolBefore - engine.accts.get(C)!.priv.collateral;
  netDeposits -= forcedOut;
  log(`forced: carol withdrew ${forcedOut}; bob closed to ${engine.accts.get(B)!.priv.positions[0].size} in market 0; dave has ${engine.actv.get(D)!.openOrders} open orders`);
  assert(forcedOut > 0n && engine.accts.get(B)!.priv.positions[0].size === 0n && engine.actv.get(D)!.openOrders === 0n, 'forced requests');
  await engine.maintenance({ sweep: true, refresh: 4 });
  // Eight accounts, four refreshed per batch from batch 2: the cursor wrapped in batches 3 and 5,
  // so the current cycle began at batch 5's last block.
  assert(engine.cycleStart === t5 + 10n && engine.refreshCursor === 0n, `cycle start ${engine.cycleStart}, cursor ${engine.refreshCursor}`);
  checkConservation(engine, netDeposits, 'batch 5');
  const w5 = await engine.endBatch();
  log(`batch 5: ${w5.segments.map((s) => s.label).join(' | ')}; ${w5.daPayload.length} DA fields`);
  const b5 = await settle(w5);
  assert(b5.header[0] === b4.header[1], 'batch 5 does not chain from batch 4');

  // Exit from DA alone: rebuild the accounts tree from the genesis protocol leaves and the five
  // batches, then open every user's account and compare with the engine.
  const genesisLeaves = await Promise.all(protocol.map(async (p, i) => ({ index: BigInt(i), leaf: await M.accountLeaf(h, p.pub, M.emptyPriv(0n)), pub: p.pub })));
  const entries = [b1, b2, b3, b4, b5].flatMap((b, i) => decodeBatch(BigInt(i + 1), b.daPayload).accounts);
  const rebuilt = await rebuildAccounts(h, entries, genesisLeaves);
  assert(rebuilt.tree.root === b5.header[2], 'accounts tree rebuilt from DA != header.new_accounts_root');
  for (const [i, u] of users.entries()) {
    const opened = await openAccount(h, rebuilt, u.keys.kEnc, await M.masterAuthOf(h, u.keys.pk!.x, u.keys.pk!.y));
    const want = engine.accts.get(BigInt(2 + i))!.priv;
    assert(show(opened.priv) === show(want), `account ${2 + i} opened from DA differs from the engine`);
  }
  const pos = (idx: bigint) => engine.accts.get(idx)!.priv;
  log(`from DA: alice m0 ${pos(A).positions[0].size} m1 ${pos(A).positions[1].size}, collateral ${pos(A).collateral}; bob m0 ${pos(B).positions[0].size} m1 ${pos(B).positions[1].size}; carol m0 ${pos(C).positions[0].size} m1 ${pos(C).positions[1].size}`);
  log(`protocol: insurance ${pos(M.INSURANCE_INDEX).collateral} (+${engine.insuranceMicro} micro), fees ${pos(M.FEE_INDEX).collateral}`);
  assert(pos(A).positions[0].size === 40n && pos(B).positions[0].size === 0n && pos(C).positions[0].size === 30n, 'market 0 positions');
  assert(pos(B).positions[1].size === 2n && pos(C).positions[1].size === -2n, 'market 1 positions');

  report.batches = [b1, b2, b3, b4, b5].map((b) => ({ shape: b.shape, daFields: b.daPayload.length, ms: b.ms }));
  report.liquidation = { steps: kinds, before: before4 };
  report.equity = Object.fromEntries([...engine.accts.keys()].map((k) => [k.toString(), engine.equityOf(k).toString()]));
  report.markets = engine.markets.map((m) => ({ index: m.indexPrice, mark: m.markPrice, cumFunding: m.cumFunding, rate: m.fundingRate, oi: m.oiLong }));
  writeJson(join(OUT, 'native.json'), report);
  log(`${receiptCount} receipts, sequence numbers 1–${engine.lastSeq}, each with a path to its batch's receipts root`);
  log(`header of batch 5 ${hex(b5.headerHash)}`);
  await api.destroy();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
