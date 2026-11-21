// P1 native test (no network): the engine builds a batch of real exchange actions, every segment
// is proved and checked against the engine, the root binds the header, and an account is then
// reconstructed and opened from the DA payload alone.
import { join } from 'node:path';
import { OUT, hex, randomField, readJson } from '../lib.ts';
import { Prover, assert, newApi, proveBatch } from '../pipeline.ts';
import { decodeBatch, openAccount, rebuildAccounts } from './da.ts';
import { Engine, signAction } from './engine.ts';
import * as X from './rules.ts';
import { keysFromSeed, sign } from './grumpkin.ts';
import * as M from './model.ts';
import { testParams } from './params.ts';

const log = (m: string) => console.log(`[p1-native] ${m}`);

async function main() {
  const manifest = readJson(join(OUT, 'manifest.json'));
  const api = await newApi();
  const h = M.hasher(api);
  const { params, oracleSk } = await testParams(h);
  const prover = await Prover.create(api, manifest, await M.paramsHash(h, params));
  const engine = await Engine.create(api, params, BigInt(manifest.vkTree.root));
  assert((await engine.trees()) === BigInt(manifest.genesisTrees), 'engine genesis != manifest genesis');

  const now = BigInt(Math.floor(Date.now() / 1000));
  const users = await Promise.all([101n, 202n].map(async (seed) => ({ seed, addr: randomField(), keys: await keysFromSeed(h, seed) })));
  const reqs: M.Request[] = [];
  for (const [i, u] of users.entries()) {
    const masterAuth = await M.masterAuthOf(h, u.keys.pk!.x, u.keys.pk!.y);
    const encC = await M.encCommitment(h, u.keys.kEnc);
    engine.keyring.set(encC, u.keys.kEnc); // delivered by Bridge.register in a deployment
    reqs.push({ kind: M.KIND.REGISTER, a: masterAuth, b: encC, sender: u.addr, time: now - 100n + BigInt(i) });
  }
  reqs.push({ kind: M.KIND.DEPOSIT, a: 0n, b: 1_000_000n, sender: users[0].addr, time: now - 90n });
  reqs.push({ kind: M.KIND.DEPOSIT, a: 1n, b: 2_000_000n, sender: users[1].addr, time: now - 85n });
  reqs.push({ kind: M.KIND.DEPOSIT, a: 9n, b: 500n, sender: users[1].addr, time: now - 80n }); // no account 9: refund

  await engine.beginBatch(1n, 0n, 0n, 0n);
  const t = now - 10n;
  await engine.block(now, { price: 2000n, time: t, sig: await sign(h, oracleSk, await M.oracleMessage(h, engine.domain, 2000n, t)) });
  await engine.priority(reqs);
  const w = await engine.endBatch();
  log(`batch 1: ${w.segments.map((s) => s.label).join(' | ')}; ${w.daPayload.length} DA fields, ${w.withdrawalRecords.length} refund(s)`);
  const b = await proveBatch(prover, w, log);
  assert(b.header[0] === BigInt(manifest.genesisStateRoot), 'batch 1 does not start from genesis');
  log(`${b.shape}: header ${hex(b.headerHash)}`);

  // Batch 2: trading. Alice rests a bid; Bob sells into it with an IOC order; Alice cancels the
  // rest; Bob withdraws. Two orders the rules must refuse are mixed in.
  const [alice, bob] = users.map((u) => u.keys);
  const act = (who: typeof alice, account: bigint, nonce: bigint, kind: bigint, p: bigint[]) =>
    signAction(h, engine.domain, who, kind, account, nonce, p);
  const { BID, ASK } = M.SIDE;
  await engine.beginBatch(2n, b.end.priorityHead, b.end.priorityCursor, b.end.time);
  const t2 = now + 5n;
  await engine.block(t2);
  await engine.trade([
    await act(alice, 0n, 1n, X.KIND_ACT.PLACE, [BID, 2000n, 100n, X.TIF.GTC]),
    await act(alice, 0n, 2n, X.KIND_ACT.PLACE, [BID, 2000n, 10_000_000n, X.TIF.GTC]), // far beyond her margin
    await act(bob, 1n, 1n, X.KIND_ACT.PLACE, [ASK, 1990n, 60n, X.TIF.IOC]),
    await act(bob, 1n, 1n, X.KIND_ACT.PLACE, [ASK, 1990n, 1n, X.TIF.IOC]), // replayed nonce
    await act(alice, 0n, 2n, X.KIND_ACT.CANCEL, [BID, 2000n, 0n, 0n]),
    await act(bob, 1n, 2n, X.KIND_ACT.WITHDRAW, [1000n, users[1].addr, 0n, 0n]),
  ]);
  await engine.refresh(2); // republish both accounts under fresh keystreams (SPEC.md §9.5)
  log(`engine refused: ${engine.rejected.map((r) => r.reason).join('; ')}`);
  assert(engine.rejected.map((r) => r.reason).join('|') === 'insufficient margin|nonce', 'unexpected rejections');
  const w2 = await engine.endBatch();
  log(`batch 2: ${w2.segments.map((s) => s.label).join(' | ')}; ${w2.daPayload.length} DA fields, ${w2.withdrawalRecords.length} withdrawal(s)`);
  const b2 = await proveBatch(prover, w2, log);
  assert(b2.header[0] === b.header[1], 'batch 2 does not chain from batch 1');

  // Exit from DA alone: rebuild the accounts tree over both batches and open both accounts.
  const entries = [...decodeBatch(1n, b.daPayload).accounts, ...decodeBatch(2n, b2.daPayload).accounts];
  const { tree, latest } = await rebuildAccounts(h, entries);
  assert(tree.root === b2.header[2], 'accounts tree rebuilt from DA != header.new_accounts_root');
  const a0 = await openAccount(h, latest, alice.kEnc, await M.masterAuthOf(h, alice.pk!.x, alice.pk!.y));
  const a1 = await openAccount(h, latest, bob.kEnc, await M.masterAuthOf(h, bob.pk!.x, bob.pk!.y));
  assert(a0.priv.size === 60n && a0.priv.entry === 120_000n && a0.priv.collateral === 1_000_000n, `alice ${JSON.stringify(a0.priv, (_k, v) => (typeof v === 'bigint' ? v.toString() : v))}`);
  assert(a1.priv.size === -60n && a1.priv.entry === -120_000n && a1.priv.collateral === 2_000_000n - 1000n, 'bob');
  log(`from DA: alice long ${a0.priv.size} at notional ${a0.priv.entry}; bob short ${-a1.priv.size}, collateral ${a1.priv.collateral}`);
  log(`book after batch 2: ${engine.orders.size} resting orders; open interest ${engine.market.oiLong}/${engine.market.oiShort}`);
  await api.destroy();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
