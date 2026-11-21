// Native test (no network): the engine builds batches of real exchange actions across several
// markets, every segment is proved and checked against the engine, the root binds the header,
// conservation is checked exactly after every batch, and every account is then reconstructed and
// opened from the DA payloads alone.
import { join } from 'node:path';
import { OUT, hex, randomField, readJson, writeJson } from '../lib.ts';
import { Prover, assert, newApi, proveBatch } from '../pipeline.ts';
import { decodeBatch, openAccount, rebuildAccounts } from './da.ts';
import { Engine, signAction, signUpdate } from './engine.ts';
import { keysFromSeed } from './grumpkin.ts';
import * as M from './model.ts';
import { protocolAccounts, testParams } from './params.ts';
import * as X from './rules.ts';

const log = (m: string) => console.log(`[native] ${m}`);
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
  const protocol = await protocolAccounts(h);
  const engine = await Engine.create(api, params, BigInt(manifest.vkTree.root), protocol);
  assert((await engine.trees()) === BigInt(manifest.genesisTrees), 'engine genesis != manifest genesis');
  const update = (market: bigint, price: bigint, external: bigint, time: bigint) => signUpdate(h, engine.domain, oracleSks, [0, 2], market, price, external, time);

  const now = BigInt(Math.floor(Date.now() / 1000)) - 10_000n;
  const users = await Promise.all([101n, 202n, 303n].map(async (seed) => ({ seed, addr: randomField(), keys: await keysFromSeed(h, seed) })));
  const [alice, bob, carol] = users.map((u) => u.keys);
  const [A, B, C] = [2n, 3n, 4n]; // account indices after the two protocol accounts
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
  reqs.push({ kind: M.KIND.DEPOSIT, a: 99n, b: 500n, sender: users[1].addr, time: now - 80n }); // no account 99: refund
  reqs.push({ kind: M.KIND.DEPOSIT, a: M.INSURANCE_INDEX, b: 50_000n, sender: users[2].addr, time: now - 79n }); // seed the insurance fund
  let netDeposits = 6_050_000n;
  const report: Record<string, unknown> = {};

  // Batch 1: indices for three markets, registrations, deposits, a refund.
  await engine.beginBatch(1n, 0n, 0n, 0n);
  await engine.block(now, [await update(0n, 2000n, 2002n, now - 5n), await update(1n, 30_000n, 30_010n, now - 5n), await update(2n, 100n, 100n, now - 5n)]);
  await engine.priority(reqs);
  checkConservation(engine, netDeposits, 'batch 1');
  const w1 = await engine.endBatch();
  log(`batch 1: ${w1.segments.map((s) => s.label).join(' | ')}; ${w1.daPayload.length} DA fields`);
  const b1 = await proveBatch(prover, w1, log);
  assert(b1.header[0] === BigInt(manifest.genesisStateRoot), 'batch 1 does not start from genesis');

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
  const b2 = await proveBatch(prover, w2, log);
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
  const b3 = await proveBatch(prover, w3, log);
  assert(b3.header[0] === b2.header[1], 'batch 3 does not chain from batch 2');

  // Exit from DA alone: rebuild the accounts tree from the genesis protocol leaves and the three
  // batches, then open every user's account and compare with the engine.
  const genesisLeaves = await Promise.all(protocol.map(async (p, i) => ({ index: BigInt(i), leaf: await M.accountLeaf(h, p.pub, M.emptyPriv(0n)), pub: p.pub })));
  const entries = [b1, b2, b3].flatMap((b, i) => decodeBatch(BigInt(i + 1), b.daPayload).accounts);
  const rebuilt = await rebuildAccounts(h, entries, genesisLeaves);
  assert(rebuilt.tree.root === b3.header[2], 'accounts tree rebuilt from DA != header.new_accounts_root');
  for (const [i, u] of users.entries()) {
    const opened = await openAccount(h, rebuilt, u.keys.kEnc, await M.masterAuthOf(h, u.keys.pk!.x, u.keys.pk!.y));
    const want = engine.accts.get(BigInt(2 + i))!.priv;
    assert(show(opened.priv) === show(want), `account ${2 + i} opened from DA differs from the engine`);
  }
  const pos = (idx: bigint) => engine.accts.get(idx)!.priv;
  log(`from DA: alice m0 ${pos(A).positions[0].size} m1 ${pos(A).positions[1].size}, collateral ${pos(A).collateral}; bob m0 ${pos(B).positions[0].size} m1 ${pos(B).positions[1].size}; carol m0 ${pos(C).positions[0].size} m1 ${pos(C).positions[1].size}`);
  log(`protocol: insurance ${pos(M.INSURANCE_INDEX).collateral} (+${engine.insuranceMicro} micro), fees ${pos(M.FEE_INDEX).collateral}`);
  assert(pos(A).positions[0].size === 40n && pos(B).positions[0].size === -60n && pos(C).positions[0].size === 20n, 'market 0 positions');
  assert(pos(B).positions[1].size === 2n && pos(C).positions[1].size === -2n, 'market 1 positions');

  report.batches = [b1, b2, b3].map((b) => ({ shape: b.shape, daFields: b.daPayload.length, ms: b.ms }));
  report.equity = Object.fromEntries([...engine.accts.keys()].map((k) => [k.toString(), engine.equityOf(k).toString()]));
  report.markets = engine.markets.map((m) => ({ index: m.indexPrice, mark: m.markPrice, cumFunding: m.cumFunding, rate: m.fundingRate, oi: m.oiLong }));
  writeJson(join(OUT, 'native.json'), report);
  log(`header of batch 3 ${hex(b3.headerHash)}`);
  await api.destroy();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
