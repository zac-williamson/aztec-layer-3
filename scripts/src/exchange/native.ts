// Native test (no network): the engine builds batches of real exchange actions across several
// markets, every segment is proved and checked against the engine (client-proof actions through
// the Chonk IVC and the tube), the root binds the header, conservation is checked exactly after
// every batch, and every account is then reconstructed and opened from the DA payloads alone.
import { join } from 'node:path';
import { OUT, hex, randomField, readJson, writeJson } from '../lib.ts';
import { type BatchWitness, type ProvedBatch, Prover, assert, executeBatch, foldReceipt, newApi, proveBatch, receiptLeaf, receiptPath } from '../pipeline.ts';
import { decodeBatch, openAccount, rebuildAccounts } from './da.ts';
import { Engine, proveAction, signAction, signUpdate } from './engine.ts';
import { keysFromSeed } from './grumpkin.ts';
import { p256Key } from './p256.ts';
import { sha256 } from './webauthn.ts';

const rpIdHashOf = (rpId: string) => BigInt(`0x${Buffer.from(sha256(new TextEncoder().encode(rpId))).toString('hex')}`);
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
  const engine = await Engine.create(api, params, BigInt(manifest.vkTree.root), protocol, prover.clientVks);
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
  reqs.push(await M.depositRequest(h, A, 1_000_000n, users[0].addr, now - 90n));
  reqs.push(await M.depositRequest(h, B, 2_000_000n, users[1].addr, now - 85n));
  reqs.push(await M.depositRequest(h, C, 3_000_000n, users[2].addr, now - 84n));
  reqs.push(await M.depositRequest(h, D, 5_000_000n, users[3].addr, now - 83n));
  reqs.push(await M.depositRequest(h, E, 30_000n, users[4].addr, now - 82n));
  reqs.push(await M.depositRequest(h, F, 25_000n, users[5].addr, now - 81n));
  reqs.push(await M.depositRequest(h, 99n, 500n, users[1].addr, now - 80n)); // no account 99: refund
  reqs.push(await M.depositRequest(h, M.INSURANCE_INDEX, 20_000n, users[2].addr, now - 79n)); // seed the insurance fund
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
      "market not allowed for the session key|order above the session key's notional limit|session keys only place, cancel, modify and cancel all|signing key is not the slot's",
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

  // Batch 6: client-proof actions (SPEC.md §7.1, §7.4). Grace registers in lane P: her master
  // authorization is the client circuit with her auth binding, so no Schnorr key controls her
  // account. A client proof grants a session key for market 0, which buys from Bob; in a later
  // P-segment, one proof revokes it and another withdraws 100,000. The engine refuses a proof
  // applied to Alice's account (lane S), a replayed nonce, a withdrawal any Schnorr key signs for
  // Grace's account, a proven withdrawal beyond her collateral, and the revoked key's next order.
  // Heidi registers in lane P with a P-256 key (client_p256): her key grant is aggregated with
  // Grace's in one P-segment, under the other client circuit, and she withdraws by P-256 proof.
  const grace = { secret: randomField(), addr: randomField(), keys: await keysFromSeed(h, 707n) };
  const G = 8n;
  const graceAuth = await M.masterAuthP(h, prover.clientVkHash, await M.authBinding(h, grace.secret));
  const graceEnc = await M.encCommitment(h, grace.keys.kEnc);
  engine.keyring.set(graceEnc, grace.keys.kEnc);
  const heidi = { key: p256Key(), salt: randomField(), addr: randomField(), keys: await keysFromSeed(h, 808n) };
  const Hd = 9n;
  const heidiAuth = await M.masterAuthP(h, prover.clientVks.client_p256, await M.p256Binding(h, heidi.key.pk, heidi.salt));
  const heidiEnc = await M.encCommitment(h, heidi.keys.kEnc);
  engine.keyring.set(heidiEnc, heidi.keys.kEnc);
  await engine.beginBatch(6n, b5.end.priorityHead, b5.end.priorityCursor, b5.end.time);
  const t6 = now + 4000n;
  await engine.block(t6, [await update(0n, 1750n, 1750n, t6 - 1n)]);
  await engine.priority([
    { kind: M.KIND.REGISTER, a: graceAuth, b: graceEnc, sender: grace.addr, time: t6 },
    await M.depositRequest(h, G, 500_000n, grace.addr, t6),
    { kind: M.KIND.REGISTER, a: heidiAuth, b: heidiEnc, sender: heidi.addr, time: t6 },
    await M.depositRequest(h, Hd, 300_000n, heidi.addr, t6),
  ]);
  netDeposits += 800_000n;
  // The client proves each action; without proving, the actions carry only the proofs' public inputs.
  const byProof = (account: bigint, nonce: bigint, kind: bigint, p: bigint[]) =>
    proveAction(h, engine.domain, grace.secret, kind, account, nonce, p, EXECUTE_ONLY ? undefined : prover);
  const byKey = (nonce: bigint, kind: bigint, p: bigint[]) =>
    proveAction(h, engine.domain, { key: heidi.key, salt: heidi.salt }, kind, Hd, nonce, p, EXECUTE_ONLY ? undefined : prover);
  const hSess = await keysFromSeed(h, 8008n);
  const gSess = await keysFromSeed(h, 7007n);
  const bySessG = (nonce: bigint, kind: bigint, p: bigint[]) => signAction(h, engine.domain, gSess, kind, G, nonce, p, 0n);
  await engine.proven([
    await byProof(G, 1n, ADD_KEY, [0n, gSess.pk.x, gSess.pk.y, 0b0001n, 400_000n, t6 + 1000n]),
    await byKey(1n, ADD_KEY, [5n, hSess.pk.x, hSess.pk.y, 0b0011n, 200_000n, t6 + 1000n]),
    await byProof(A, 7n, ADD_KEY, [1n, gSess.pk.x, gSess.pk.y, 0b0001n, 400_000n, t6 + 1000n]), // Alice's account is lane S
    await byProof(G, 1n, REVOKE_KEY, [0n]), // replayed nonce
  ]);
  await engine.trade([
    await act(bob, B, 6n, PLACE, [0n, ASK, 1755n, 20n, GTC, 0n]),
    await bySessG(1n, PLACE, [0n, BID, 1755n, 20n, IOC, 0n]), // buys Bob's 20
    await act(grace.keys, G, 2n, WITHDRAW, [100n, grace.addr]), // no Schnorr key is Grace's master key
  ]);
  await engine.proven([
    await byProof(G, 2n, REVOKE_KEY, [0n]),
    await byProof(G, 3n, WITHDRAW, [100_000n, grace.addr]),
    await byProof(G, 4n, WITHDRAW, [10_000_000n, grace.addr]), // more than her collateral
    await byKey(2n, WITHDRAW, [50_000n, heidi.addr]),
  ]);
  netDeposits -= 150_000n;
  await engine.trade([await bySessG(2n, PLACE, [0n, BID, 1700n, 1n, GTC, 0n])]); // revoked
  const reasons6 = engine.rejected.slice(9).map((r) => r.reason);
  log(`engine refused: ${reasons6.join('; ')}`);
  assert(
    reasons6.join('|') ===
      "client proof does not control the account|nonce|signing key is not the account's|collateral below the amount|signing key is not the slot's",
    'unexpected batch 6 rejections',
  );
  assert(engine.accts.get(G)!.priv.positions[0].size === 20n && engine.keyOf(G, 0).pkX === 0n && engine.actv.get(G)!.nonce === 3n, 'lane-P key grant, trade, revocation and withdrawal');
  assert(engine.keyOf(Hd, 5).pkX === hSess.pk.x && engine.actv.get(Hd)!.nonce === 2n, 'P-256 key grant and withdrawal');
  assert(engine.wdRecords.length === 2, 'the proven withdrawals are the batch\'s only records');
  await engine.maintenance({ sweep: true, refresh: 4 });
  checkConservation(engine, netDeposits, 'batch 6');
  const w6 = await engine.endBatch();
  log(`batch 6: ${w6.segments.map((s) => s.label).join(' | ')}; ${w6.daPayload.length} DA fields`);
  const b6 = await settle(w6);
  assert(b6.header[0] === b5.header[1], 'batch 6 does not chain from batch 5');

  // Batch 7: ModifyOrder and Transfer (SPEC.md §7.3). Dave rests a bid of 20 at 1,745 and Heidi's
  // session key a bid of 5 behind it at the same price; Dave reduces his to 8, which keeps its
  // place, so Bob's sell of 10 fills Dave's 8 before 2 of Heidi's. Heidi's key also reduces a
  // market-1 bid, and Alice transfers 25,000 to Heidi. The engine refuses a modification that adds
  // lots, a transfer beyond Alice's collateral, one to an account that does not exist, one to the
  // insurance account, and one Heidi's session key signs.
  await engine.beginBatch(7n, b6.end.priorityHead, b6.end.priorityCursor, b6.end.time);
  const t7 = now + 4100n;
  await engine.block(t7, [await update(0n, 1750n, 1750n, t7 - 1n), await update(1n, 30_010n, 30_010n, t7 - 1n)]);
  const { MODIFY, TRANSFER } = X.KIND_ACT;
  const byHeidiKey = (nonce: bigint, kind: bigint, p: bigint[]) => signAction(h, engine.domain, hSess, kind, Hd, nonce, p, 5n);
  await engine.trade([
    await act(dave, D, 3n, PLACE, [0n, BID, 1745n, 20n, GTC, 0n]),
    await byHeidiKey(1n, PLACE, [0n, BID, 1745n, 5n, GTC, 0n]),
    await byHeidiKey(2n, PLACE, [1n, BID, 29_900n, 2n, GTC, 0n]),
  ]);
  const daveBid = [...engine.orders[0].values()].find((o) => o.account === D && o.price === 1745n)!;
  const heidiBid = [...engine.orders[1].values()].find((o) => o.account === Hd)!;
  const aliceBefore = engine.accts.get(A)!.priv.collateral;
  const daveBefore = engine.accts.get(D)!.priv.positions[0].size;
  await engine.trade([
    await act(dave, D, 4n, MODIFY, [0n, BID, 1745n, daveBid.seq, 25n]), // adds lots
    await act(dave, D, 4n, MODIFY, [0n, BID, 1745n, daveBid.seq, 8n]),
    await byHeidiKey(3n, MODIFY, [1n, BID, 29_900n, heidiBid.seq, 1n]),
    await act(bob, B, 7n, PLACE, [0n, ASK, 1745n, 10n, IOC, 0n]), // Dave's 8 first, then 2 of Heidi's 5
    await act(alice, A, 7n, TRANSFER, [5_000_000n, Hd]), // more than her collateral
    await act(alice, A, 7n, TRANSFER, [25_000n, 99n]), // no account 99
    await act(alice, A, 7n, TRANSFER, [25_000n, M.INSURANCE_INDEX]), // a protocol account
    await byHeidiKey(4n, TRANSFER, [1n, A]), // session keys cannot transfer
    await act(alice, A, 7n, TRANSFER, [25_000n, Hd]),
  ]);
  const reasons7 = engine.rejected.slice(14).map((r) => r.reason);
  log(`engine refused: ${reasons7.join('; ')}`);
  assert(
    reasons7.join('|') ===
      'a modification only reduces an order|collateral below the amount|no such account|transfers go to user accounts|session keys only place, cancel, modify and cancel all',
    'unexpected batch 7 rejections',
  );
  assert(engine.accts.get(D)!.priv.positions[0].size === daveBefore + 8n && engine.accts.get(Hd)!.priv.positions[0].size === 2n, 'the modified bid kept its place');
  assert(engine.actv.get(Hd)!.openBid[1] === 1n && engine.actv.get(Hd)!.openBid[0] === 3n, "Heidi's open bids after the fill and the modification");
  assert(engine.accts.get(A)!.priv.collateral === aliceBefore - 25_000n, "Alice's transfer");
  await engine.maintenance({ sweep: true, refresh: 4 });
  checkConservation(engine, netDeposits, 'batch 7');
  const w7 = await engine.endBatch();
  log(`batch 7: ${w7.segments.map((s) => s.label).join(' | ')}; ${w7.daPayload.length} DA fields`);
  const b7 = await settle(w7);
  assert(b7.header[0] === b6.header[1], 'batch 7 does not chain from batch 6');

  // Batch 8: CancelAll in constant time (SPEC.md §6.5). Heidi's session key cancels all her orders
  // and Alice does the same with her master key; Carol's ForcedCancelAll through the queue voids
  // hers. Void orders stay in the books until matching meets them: Bob's sell removes Heidi's
  // market-0 bid instead of filling it, and Dave's sell removes Carol's. Ivan registers with a
  // passkey (client_webauthn) and grants a session key with a WebAuthn assertion.
  await engine.beginBatch(8n, b7.end.priorityHead, b7.end.priorityCursor, b7.end.time);
  const t8 = now + 4200n;
  await engine.block(t8, [await update(0n, 1750n, 1750n, t8 - 1n), await update(1n, 30_010n, 30_010n, t8 - 1n)]);
  const { CANCEL_ALL } = X.KIND_ACT;
  await engine.trade([await byHeidiKey(4n, CANCEL_ALL, []), await act(alice, A, 8n, CANCEL_ALL, [])]);
  const ivan = { passkey: p256Key(), salt: randomField(), rpId: 'l3x.example', origin: 'https://l3x.example', addr: randomField(), keys: await keysFromSeed(h, 909n) };
  const Iv = 10n;
  const ivanAuth = await M.masterAuthP(h, prover.clientVks.client_webauthn, await M.webauthnBinding(h, ivan.passkey.pk, rpIdHashOf(ivan.rpId), ivan.salt));
  const ivanEnc = await M.encCommitment(h, ivan.keys.kEnc);
  engine.keyring.set(ivanEnc, ivan.keys.kEnc);
  await engine.priority([
    { kind: M.KIND.FORCED_CANCEL_ALL, a: C, b: 0n, sender: users[2].addr, time: t8 },
    { kind: M.KIND.REGISTER, a: ivanAuth, b: ivanEnc, sender: ivan.addr, time: t8 },
    await M.depositRequest(h, Iv, 100_000n, ivan.addr, t8),
  ]);
  netDeposits += 100_000n;
  const iSess = await keysFromSeed(h, 9009n);
  await engine.proven([
    await proveAction(h, engine.domain, ivan, ADD_KEY, Iv, 1n, [0n, iSess.pk.x, iSess.pk.y, 0b0001n, 50_000n, t8 + 1000n], EXECUTE_ONLY ? undefined : prover),
  ]);
  assert(engine.keyOf(Iv, 0).pkX === iSess.pk.x && engine.actv.get(Iv)!.nonce === 1n, 'passkey key grant');
  const voided = (i: bigint) => {
    const x = engine.actv.get(i)!;
    return x.epoch > 0n && x.openOrders === 0n && x.openBid.every((b) => b === 0n) && x.openAsk.every((b) => b === 0n);
  };
  assert(voided(Hd) && voided(A) && voided(C), 'cancel-all voids every order');
  const restingOf = (i: bigint) => engine.orders.reduce((n, o) => n + [...o.values()].filter((x) => x.account === i).length, 0);
  const sizes = () => [B, D, Hd, C].map((i) => engine.accts.get(i)!.priv.positions[0].size).join(',');
  const before8 = { sizes: sizes(), heidi: restingOf(Hd), carol: restingOf(C) };
  await engine.trade([
    await act(bob, B, 8n, PLACE, [0n, ASK, 1745n, 3n, IOC, 0n]), // removes Heidi's void bid, fills nothing
    await act(dave, D, 5n, PLACE, [0n, ASK, 1740n, 5n, IOC, 0n]), // removes Carol's void bid, fills nothing
  ]);
  assert(Number(engine.rejected.length) === 19, `unexpected rejection: ${engine.rejected.at(-1)?.reason}`);
  assert(sizes() === before8.sizes, 'void orders were filled');
  assert(restingOf(Hd) === before8.heidi - 1 && restingOf(C) === before8.carol - 1, 'void orders not removed');
  await engine.maintenance({ sweep: true, refresh: 4 });
  checkConservation(engine, netDeposits, 'batch 8');
  const w8 = await engine.endBatch();
  log(`batch 8: ${w8.segments.map((s) => s.label).join(' | ')}; ${w8.daPayload.length} DA fields`);
  const b8 = await settle(w8);
  assert(b8.header[0] === b7.header[1], 'batch 8 does not chain from batch 7');

  // Exit from DA alone: rebuild the accounts tree from the genesis protocol leaves and the eight
  // batches, then open every user's account and compare with the engine.
  const genesisLeaves = await Promise.all(protocol.map(async (p, i) => ({ index: BigInt(i), leaf: await M.accountLeaf(h, p.pub, M.emptyPriv(0n)), pub: p.pub })));
  const entries = [b1, b2, b3, b4, b5, b6, b7, b8].flatMap((b, i) => decodeBatch(BigInt(i + 1), b.daPayload).accounts);
  const rebuilt = await rebuildAccounts(h, entries, genesisLeaves);
  assert(rebuilt.tree.root === b8.header[2], 'accounts tree rebuilt from DA != header.new_accounts_root');
  for (const [i, u] of users.entries()) {
    const opened = await openAccount(h, rebuilt, u.keys.kEnc, await M.masterAuthOf(h, u.keys.pk!.x, u.keys.pk!.y));
    const want = engine.accts.get(BigInt(2 + i))!.priv;
    assert(show(opened.priv) === show(want), `account ${2 + i} opened from DA differs from the engine`);
  }
  const graceOpened = await openAccount(h, rebuilt, grace.keys.kEnc, graceAuth);
  assert(graceOpened.index === G && show(graceOpened.priv) === show(engine.accts.get(G)!.priv), 'lane-P account opened from DA differs from the engine');
  const ivanOpened = await openAccount(h, rebuilt, ivan.keys.kEnc, ivanAuth);
  assert(ivanOpened.index === Iv && show(ivanOpened.priv) === show(engine.accts.get(Iv)!.priv), 'passkey account opened from DA differs from the engine');
  const heidiOpened = await openAccount(h, rebuilt, heidi.keys.kEnc, heidiAuth);
  assert(heidiOpened.index === Hd && show(heidiOpened.priv) === show(engine.accts.get(Hd)!.priv), 'P-256 account opened from DA differs from the engine');
  const pos = (idx: bigint) => engine.accts.get(idx)!.priv;
  log(`from DA: alice m0 ${pos(A).positions[0].size} m1 ${pos(A).positions[1].size}, collateral ${pos(A).collateral}; bob m0 ${pos(B).positions[0].size} m1 ${pos(B).positions[1].size}; carol m0 ${pos(C).positions[0].size} m1 ${pos(C).positions[1].size}; grace m0 ${pos(G).positions[0].size}`);
  log(`protocol: insurance ${pos(M.INSURANCE_INDEX).collateral} (+${engine.insuranceMicro} micro), fees ${pos(M.FEE_INDEX).collateral}`);
  assert(pos(A).positions[0].size === 40n && pos(B).positions[0].size === -30n && pos(C).positions[0].size === 30n && pos(G).positions[0].size === 20n, 'market 0 positions');
  assert(pos(B).positions[1].size === 2n && pos(C).positions[1].size === -2n, 'market 1 positions');

  report.batches = [b1, b2, b3, b4, b5, b6, b7, b8].map((b) => ({ shape: b.shape, daFields: b.daPayload.length, ms: b.ms }));
  report.liquidation = { steps: kinds, before: before4 };
  report.equity = Object.fromEntries([...engine.accts.keys()].map((k) => [k.toString(), engine.equityOf(k).toString()]));
  report.markets = engine.markets.map((m) => ({ index: m.indexPrice, mark: m.markPrice, cumFunding: m.cumFunding, rate: m.fundingRate, oi: m.oiLong }));
  writeJson(join(OUT, 'native.json'), report);
  log(`${receiptCount} receipts, sequence numbers 1–${engine.lastSeq}, each with a path to its batch's receipts root`);
  log(`header of batch 8 ${hex(b8.headerHash)}`);
  await api.destroy();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
