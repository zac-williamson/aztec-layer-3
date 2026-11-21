// Adversarial witnesses for the P1 segment circuits and the root (SPEC.md §17). Each case builds
// an honest witness with the engine, tampers with it the way a malicious operator could, and
// checks that the circuit refuses it, with the expected assertion. Execution only, no proving:
// a witness that cannot be generated cannot be proved.
import { join } from 'node:path';
import { Noir } from '@aztec-foundation/noir-noir_js';
import { OUT, hex, randomField, readCircuit, readJson } from '../lib.ts';
import { Prover, assert, newApi } from '../pipeline.ts';
import { Engine, type SignedAction, signAction } from './engine.ts';
import { keysFromSeed, scalarToNoir, sign, sigToNoir } from './grumpkin.ts';
import * as M from './model.ts';
import { testParams } from './params.ts';
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
  const { params, oracleSk } = await testParams(h);
  const prover = await Prover.create(api, manifest, await M.paramsHash(h, params));
  const engine = await Engine.create(api, params, prover.vkTreeRoot);
  const now = BigInt(Math.floor(Date.now() / 1000));
  const oracle = async (price: bigint, time: bigint) => ({ price, time, sig: await sign(h, oracleSk, await M.oracleMessage(h, engine.domain, price, time)) });

  // Three accounts with collateral, an index, and five resting asks from account 0.
  const users = await Promise.all([1n, 2n, 3n].map((s) => keysFromSeed(h, s)));
  const reqs: M.Request[] = [];
  for (const [i, k] of users.entries()) {
    const encC = await M.encCommitment(h, k.kEnc);
    engine.keyring.set(encC, k.kEnc);
    const sender = randomField();
    reqs.push({ kind: M.KIND.REGISTER, a: await M.masterAuthOf(h, k.pk!.x, k.pk!.y), b: encC, sender, time: now });
    reqs.push({ kind: M.KIND.DEPOSIT, a: BigInt(i), b: 1_000_000n, sender, time: now });
  }
  await engine.beginBatch(1n, 0n, 0n, 0n);
  await engine.block(now, await oracle(2000n, now));
  await engine.priority(reqs);
  const act = (u: number, nonce: bigint, kind: bigint, p: bigint[]) => signAction(h, engine.domain, users[u], kind, BigInt(u), nonce, p);
  const { BID, ASK } = M.SIDE;
  await engine.trade([
    await act(0, 1n, X.KIND_ACT.PLACE, [ASK, 2000n, 10n, X.TIF.GTC]),
    await act(0, 2n, X.KIND_ACT.PLACE, [ASK, 2001n, 10n, X.TIF.GTC]),
    await act(0, 3n, X.KIND_ACT.PLACE, [ASK, 2002n, 10n, X.TIF.GTC]),
    await act(0, 4n, X.KIND_ACT.PLACE, [ASK, 2002n, 10n, X.TIF.GTC]),
    await act(0, 5n, X.KIND_ACT.PLACE, [ASK, 2002n, 10n, X.TIF.GTC]),
  ]);
  assert(engine.rejected.length === 0, 'setup rejected');

  // The book path of the 2001 ask, as it stands before the next trade.
  const worse = X.orderIndex(ASK, 2001n, 1n);
  const worsePath = engine.book.path(worse).map((s) => ({ hash: hex(s.hash), ask: s.ask.toString(), bid: s.bid.toString() }));

  // Honest trades to tamper with: account 1 buys 5 (one fill), then account 2 buys 15 IOC (two
  // fills, nothing crossing left).
  const n0 = engine.segments.length;
  await engine.trade([await act(1, 1n, X.KIND_ACT.PLACE, [BID, 2002n, 5n, X.TIF.IOC])]);
  const buy = engine.segments[n0].inputs as any;
  await engine.trade([await act(2, 1n, X.KIND_ACT.PLACE, [BID, 2001n, 15n, X.TIF.IOC])]);
  assert(engine.rejected.length === 0, `setup rejected: ${engine.rejected.map((r) => r.reason)}`);

  const buy2 = engine.segments[n0 + 1].inputs as any;
  // A resting order with no fill, and a withdrawal, from account 2.
  await engine.trade([
    await act(2, 2n, X.KIND_ACT.PLACE, [BID, 1990n, 5n, X.TIF.GTC]),
    await act(2, 3n, X.KIND_ACT.WITHDRAW, [1000n, 77n, 0n, 0n]),
  ]);
  const quiet = engine.segments[n0 + 2].inputs as any;
  await engine.refresh(2);
  const refresh = engine.segments[n0 + 3].inputs as any;
  for (const seg of [buy, buy2, quiet, refresh]) await execute(seg === refresh ? 'seg_refresh' : 'seg_trade', seg); // honest witnesses run
  const resign = async (inputs: any, i: number, u: number, nonce: bigint, kind: bigint, p: bigint[]) => {
    const a: SignedAction = await act(u, nonce, kind, p);
    inputs.actions[i] = { ...inputs.actions[i], nonce: nonce.toString(), p: p.map(hex), sig: sigToNoir(a.sig) };
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
  t.actions[0].taker_pub.master_auth = hex(await M.masterAuthOf(h, evil.pk!.x, evil.pk!.y));
  t.actions[0].pk_x = hex(evil.pk!.x);
  t.actions[0].pk_y = hex(evil.pk!.y);
  t.actions[0].sig = sigToNoir(await sign(h, evil.sk, await X.actionMsg(h, engine.domain, X.KIND_ACT.PLACE, 2n, 2n, [BID, 1990n, 5n, X.TIF.GTC])));
  await expectFail('operator substitutes the signing key', 'seg_trade', t, 'Merkle path does not match root');
  t = clone(buy);
  await resign(t, 0, 1, 0n, X.KIND_ACT.PLACE, [BID, 2002n, 5n, X.TIF.IOC]);
  await expectFail('replayed nonce', 'seg_trade', t, 'nonce');

  // Matching.
  t = clone(buy);
  Object.assign(t.actions[0].fills[0], { index: hex(worse), price: '2001', seq: '1', book_path: worsePath });
  await expectFail('fill skips the best ask', 'seg_trade', t, 'not the best ask');
  t = clone(buy);
  t.actions[0].fills[0].order.account_index = '1';
  await expectFail('self trade', 'seg_trade', t, 'self trade');
  // A malicious engine stops a 30-lot IOC after two fills although the 2002 ask still crosses.
  const before = engine.segments.length;
  engine.relax.add('fills');
  await engine.trade([await act(1, 2n, X.KIND_ACT.PLACE, [BID, 2002n, 30n, X.TIF.IOC])]);
  engine.relax.clear();
  await expectFail('IOC stops with crossing liquidity left', 'seg_trade', engine.segments[before].inputs, 'crossing asks remain');
  t = clone(buy);
  await resign(t, 0, 1, 1n, X.KIND_ACT.PLACE, [BID, 2200n, 5n, X.TIF.IOC]);
  await expectFail('limit price outside the band', 'seg_trade', t, 'limit price outside the band');

  // Margin: the circuit checks against the committed parameters, whatever the operator believed.
  t = clone(buy);
  await resign(t, 0, 1, 1n, X.KIND_ACT.PLACE, [BID, 2002n, 5n, X.TIF.IOC]);
  t.params.imr_ppm = '1000000000';
  await expectFail('order beyond initial margin', 'seg_trade', t, 'insufficient margin');
  t = clone(quiet);
  t.actions[1] = { ...t.actions[1], p: [1_000_000n, 77n, 0n, 0n].map(hex), sig: sigToNoir((await act(2, 3n, X.KIND_ACT.WITHDRAW, [1_000_000n, 77n, 0n, 0n])).sig) };
  await expectFail('withdrawal beyond equity', 'seg_trade', t, 'insufficient margin');

  // Oracle.
  const blockInputs = engine.segments[0].inputs as any;
  t = clone(blockInputs);
  t.update.price = '2001';
  await expectFail('oracle price not as signed', 'seg_block', t);
  // An engine that tolerates a 100% move builds the witness; the circuit applies the committed 10%.
  const loose = await Engine.create(api, { ...params, maxJumpPpm: 2_000_000n }, prover.vkTreeRoot);
  await loose.beginBatch(1n, 0n, 0n, 0n);
  await loose.block(now, await oracle(1000n, now));
  await loose.block(now + 1n, await oracle(2000n, now + 1n));
  t = clone(loose.segments[1].inputs as any);
  t.params.max_jump_ppm = params.maxJumpPpm.toString();
  await expectFail('oracle jump beyond the bound', 'seg_block', t, 'oracle jump too large');
  t = clone(blockInputs);
  t.block_time = (now - 1n).toString();
  t.start.time = now.toString();
  await expectFail('block time regresses', 'seg_block', t, 'time regressed');

  // Encryption keys and openings.
  const prio = engine.segments[1].inputs as any;
  t = clone(prio);
  t.items[0].k_enc = hex(424242n);
  await expectFail('registration encrypted under another key', 'seg_priority', t, 'k_enc does not open the commitment');
  t = clone(prio);
  t.items[1].account_index = '2';
  await expectFail('deposit credited to another account', 'seg_priority', t, 'deposit index');
  t = clone(refresh);
  t.items[0].priv_part.collateral = '999999999';
  await expectFail('refresh publishes an inflated opening', 'seg_refresh', t, 'account path');

  for (const r of results) console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name}  (${r.how})`);
  await api.destroy();
  process.exit(results.every((r) => r.pass) ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
