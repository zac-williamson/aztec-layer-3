// End to end on an in-process Aztec 6.0.0 local network, with client proving and node
// transaction-proof verification on (SPEC.md §15, the P1 exit criterion, extended for P2.1):
//
//  1. Deploy the collateral token and the Bridge, whose genesis holds the operator's insurance and
//     fee accounts. Alice and Bob register (their encryption keys reach the operator as
//     constrained private events) and deposit; Bob also deposits to an account that does not exist.
//  2. The operator reads the queue and the delivered keys from the chain, executes everything in
//     its engine, proves the batch (a block with 2-of-3 signed indices for three markets, priority
//     segments, merged, root) and settles it. Bob claims his refund using only the published DA.
//  3. Batch 2: Alice rests a bid in market 0 and Bob sells into it; Alice offers in market 1 and
//     Bob buys; Alice cancels her rest and Bob withdraws. Bob claims the withdrawal from the DA.
//     The operator posts a bond. Bob challenges the receipt of his withdrawal and the operator
//     answers with its path in batch 2's receipts root; a receipt for an action the operator
//     dropped goes unanswered and the bond pays Bob.
//     Bob then forces a withdrawal of his free collateral through the Bridge, paying the request
//     fee. Batch 3, an hour of L2 time later: new indices, so funding is applied; the forced
//     withdrawal is processed and Bob claims it from the DA; fees are swept and the accounts
//     refreshed.
//  4. The operator stops. Alice queues one more deposit, which nobody processes; after t_force
//     anyone can activate desert mode.
//  5. For each user, a fresh exit client, given only the node, the Bridge address and the user's
//     seed, rebuilds the frozen accounts tree from the deployment event and the DA logs and opens
//     the user's leaf. Each registers a claim valued at the frozen indices with funding accrued to
//     the freeze; Alice's unprocessed deposit is refunded; after the claim window both withdraw.
//     The operator then claims the fee account from the DA in the same way; it is paid only from
//     the residual and only t_late after the window, which leaves the vault with funding rounding.
//
// Writes scripts/out/e2e.json.
import { homedir } from 'node:os';
import { join } from 'node:path';
import { getInitialTestAccountsData } from '@aztec-labs/accounts/testing';
import { TEST_FEE_PADDING, setupLocalNetwork } from '@aztec-labs/aztec/testing';
import { Contract } from '@aztec-labs/aztec.js/contracts';
import { TxStatus } from '@aztec-labs/aztec.js/tx';
import { EmbeddedWallet } from '@aztec-labs/wallets/embedded';
import { OUT, SHAPE, hex, randomField, readJson, timed, writeJson } from '../lib.ts';
import { type ProvedBatch, Prover, assert, newApi, proveBatch, receiptLeaf, receiptPath } from '../pipeline.ts';
import { allPublicEvents, artifact, big, daLogs, eventMeta, rawArtifact } from './chain.ts';
import { Engine, signAction, signUpdate } from './engine.ts';
import * as X from './rules.ts';
import { exitFromDa, withdrawalPath } from './exit.ts';
import { keysFromSeed, sign } from './grumpkin.ts';
import * as M from './model.ts';
import { TEST_FEE_SEED, protocolAccounts, testParams } from './params.ts';

const log = (m: string) => console.log(`[e2e] ${m}`);
const T_FORCE = 3600n;
const T_CLAIM = 86_400n;
const REQUEST_FEE = 100n;
const T_REFRESH = 14n * 86_400n;
const T_LATE = 3600n;
// Receipts (SPEC.md §11): the operator's receipt key, the challenge rules and its bond.
const RECEIPT_SEED = 0x6c33782e72637074n; // "l3x.rcpt"
const T_SETTLE = 60n;
const T_RESP = 600n;
const SLASH = 4000n;
const BOND = 10_000n;
const ALICE_SEED = 0xa11cen;
const BOB_SEED = 0xb0bn;

async function main() {
  const manifest = readJson(join(OUT, 'manifest.json'));
  const report: Record<string, any> = { startedAt: new Date().toISOString(), aztecVersion: manifest.aztecVersion };
  const accounts = await getInitialTestAccountsData();
  const platform = `${process.arch}-${process.platform === 'darwin' ? 'macos' : 'linux'}`;
  const bbConfig = {
    bbWorkingDirectory: join(OUT, 'bb-work'),
    bbBinaryPath: join(homedir(), '.aztec', 'versions', manifest.aztecVersion, 'node_modules', '@aztec-foundation', 'bb.js', 'build', platform, 'bb'),
  };
  log('starting in-process local network (realProofs: true)');
  const network = await setupLocalNetwork({
    fundedAddresses: accounts.map((a: any) => a.address),
    config: { realProofs: true, p2pEnabled: false, ...bbConfig } as any,
  });
  const api = await newApi();
  const h = M.hasher(api);
  try {
    const node = network.node;
    const info: any = await node.getNodeInfo();
    const wallet = await EmbeddedWallet.create(node as any, {
      ephemeral: true,
      pxe: { proverEnabled: true, syncChainTip: 'checkpointed', ...bbConfig } as any,
    });
    wallet.setMinFeePadding(TEST_FEE_PADDING);
    const [operator, alice, bob] = await Promise.all(
      accounts.slice(0, 3).map(async (d: any) => (await wallet.createSchnorrInitializerlessAccount(d.secret, d.salt, d.signingKey)).address),
    );
    const wait = { waitForStatus: TxStatus.CHECKPOINTED, timeout: 1800, interval: 0.5 };
    const l2Time = async () => BigInt(((await node.getBlock((await node.getBlockNumber()) as any)) as any).header.globalVariables.timestamp);

    // Deployment-specific parameters: this chain, a fresh instance id, the test oracle keys; the
    // protocol accounts belong to the operator.
    const { params, oracleSks } = await testParams(h, BigInt(info.l1ChainId), randomField());
    const protocol = await protocolAccounts(h, [big(operator), big(operator)]);
    const prover = await Prover.create(api, manifest, await M.paramsHash(h, params));
    log(`config hash ${hex(prover.configHash)}`);
    const receiptKey = await keysFromSeed(h, RECEIPT_SEED);
    const receiptDomain = await M.domainOf(h, params);

    // 1. Deploy, register, deposit.
    const tokenArtifact = artifact('l3x_token-L3XToken');
    const bridgeArtifact = artifact('l3x_bridge-L3XBridge');
    const token = (await Contract.deploy(wallet as any, tokenArtifact, [operator]).send({ from: operator, wait } as any) as any).contract;
    const bridgeDep = await Contract.deploy(wallet as any, bridgeArtifact, [
      operator,
      BigInt(manifest.hashes.ROOT_VK_HASH),
      prover.configHash,
      token.address,
      T_FORCE,
      T_CLAIM,
      T_REFRESH,
      T_LATE,
      REQUEST_FEE,
      { domain: receiptDomain, pk_x: receiptKey.pk.x, pk_y: receiptKey.pk.y, t_settle: T_SETTLE, t_resp: T_RESP, slash: SLASH },
      [operator, operator],
      protocol.map((p) => p.pub.masterAuth),
      protocol.map((p) => p.pub.encCommitment),
    ]).send({ from: operator, wait } as any);
    const bridge = (bridgeDep as any).contract;
    report.bridge = bridge.address.toString();
    log(`token ${token.address}, bridge ${bridge.address}`);
    const bridgeAt: any = await Contract.at(bridge.address, bridgeArtifact, wallet as any);
    const tokenAt: any = await Contract.at(token.address, tokenArtifact, wallet as any);
    const asOf = (_who: any) => bridgeAt;
    const balance = async (who: any) => big((await tokenAt.methods.balance_of(who).simulate({ from: operator })).result);
    for (const who of [alice, bob]) {
      await token.methods.mint(who, 5_000_000n).send({ from: operator, wait });
      await tokenAt.methods.approve(bridge.address, 5_000_000n).send({ from: who, wait });
    }

    const users = {
      alice: { addr: alice, keys: await keysFromSeed(h, ALICE_SEED) },
      bob: { addr: bob, keys: await keysFromSeed(h, BOB_SEED) },
    };
    for (const [name, u] of Object.entries(users)) {
      const masterAuth = await M.masterAuthOf(h, u.keys.pk!.x, u.keys.pk!.y);
      const encC = await M.encCommitment(h, u.keys.kEnc);
      const [, ms] = await timed(() => asOf(u.addr).methods.register(masterAuth, encC, u.keys.kEnc).send({ from: u.addr, wait }));
      log(`${name} registered (private, key delivered to the operator) in ${ms.toFixed(0)} ms`);
      report[`${name}RegisterMs`] = Math.round(ms);
    }
    const [A, B] = [2n, 3n]; // after the insurance (0) and fee (1) accounts
    await asOf(alice).methods.deposit(A, 1_000_000n).send({ from: alice, wait });
    await asOf(bob).methods.deposit(B, 2_000_000n).send({ from: bob, wait });
    await asOf(bob).methods.deposit(42n, 777n).send({ from: bob, wait }); // no account 42: refund
    log(`deposits queued; vault holds ${await balance(bridge.address)}`);

    // 2. The operator reads the queue and its delivered keys from the chain, and settles batch 1.
    const engine = await Engine.create(api, params, BigInt(manifest.vkTree.root), protocol);
    const raw = rawArtifact('l3x_bridge-L3XBridge');
    const delivered = await (wallet as any).getPrivateEvents(await eventMeta(raw, 'KeyDelivered'), {
      contractAddress: bridge.address,
      scopes: [operator],
    });
    for (const ev of delivered) engine.keyring.set(big(ev.event.enc_commitment), big(ev.event.k_enc));
    log(`operator received ${delivered.length} encryption keys by constrained delivery`);
    report.keysDelivered = delivered.length;
    assert(delivered.length === 2, 'operator did not receive both keys');

    const queued = await allPublicEvents(node, await eventMeta(raw, 'PriorityRequested'), bridge.address);
    const requests: M.Request[] = [];
    for (const ev of queued as any[]) {
      const r: M.Request = { kind: big(ev.kind), a: big(ev.a), b: big(ev.b), c: big(ev.c), sender: big(ev.sender), time: big(ev.time) };
      assert((await M.requestEntry(h, r)) === big(ev.entry), `request ${ev.index} does not match its entry`);
      requests.push(r);
    }
    const sim = async (method: string, args: unknown[] = []) => (await bridge.methods[method](...args).simulate({ from: operator })).result;

    async function settle(name: string, b: ProvedBatch) {
      const da = [...b.daPayload, ...Array<bigint>(SHAPE.DA_MAX - b.daPayload.length).fill(0n)];
      const args = [b.header, b.rootProof, b.rootVk, da, b.daPayload.length, b.marketData];
      const [, ms] = await timed(() => bridge.methods.settle(...args).send({ from: operator, wait }));
      const t = (await sim('get_tip')) as any[];
      assert(big(t[0]) === b.header[1], `${name}: tip != header`);
      log(`${name}: ${b.shape} settled in ${ms.toFixed(0)} ms`);
      return Math.round(ms);
    }

    /** Builds, proves and settles the next batch from the chain tip. */
    async function runBatch(name: string, build: () => Promise<void>) {
      const tip = (await sim('get_tip')) as any[];
      const head = big(((await sim('get_priority', [big(tip[4])])) as any[])[0]);
      await engine.beginBatch(big(tip[2]) + 1n, head, big(tip[4]), big(tip[3]));
      await build();
      const w = await engine.endBatch();
      log(`${name}: ${w.segments.map((x) => x.label).join(' | ')}`);
      const b = await proveBatch(prover, w, (m) => log(m));
      report[name] = { shape: b.shape, ms: b.ms, daFields: b.daPayload.length, settleMs: await settle(name, b) };
      return b;
    }
    // Publishers 0 and 2 sign; the threshold is two of three.
    const update = (market: bigint, price: bigint, time: bigint) => signUpdate(h, engine.domain, oracleSks, [0, 2], market, price, price, time);

    await runBatch('batch1', async () => {
      const t = await l2Time();
      await engine.block(t, [await update(0n, 2000n, t), await update(1n, 30_000n, t), await update(2n, 100n, t)]);
      await engine.priority(requests);
    });

    // Bob's refund record is in the DA; he claims it with nothing but the published payload.
    const refund = requests[4];
    const refundSalt = await M.requestEntry(h, refund);
    const refundRecord = await M.withdrawalRecord(h, refund.sender, refund.b, refundSalt, 1n, 0);
    const logs1 = await daLogs(node, bridge.address);
    const rp = await withdrawalPath(h, logs1[0].payload, 1n, refundRecord);
    let bobBefore = await balance(bob);
    await asOf(bob).methods.claim_withdrawal(1n, rp.index, bob, refund.b, refundSalt, rp.path).send({ from: bob, wait });
    assert((await balance(bob)) === bobBefore + 777n, 'refund not paid');
    log('bob claimed his 777 refund from the vault using the DA alone');

    // Batch 2: trading. Users sign with their master keys; nonces start at 1.
    const act = (who: keyof typeof users, account: bigint, nonce: bigint, kind: bigint, p: bigint[]) =>
      signAction(h, engine.domain, users[who].keys, kind, account, nonce, p);
    const { BID, ASK } = M.SIDE;
    const { PLACE, CANCEL, WITHDRAW } = X.KIND_ACT;
    let issued2 = 0n;
    const b2 = await runBatch('batch2', async () => {
      const t = await l2Time();
      issued2 = t;
      await engine.block(t, [await update(0n, 2100n, t)]);
      await engine.trade([
        await act('alice', A, 1n, PLACE, [0n, BID, 2100n, 100n, X.TIF.GTC, 0n]),
        await act('bob', B, 1n, PLACE, [0n, ASK, 2090n, 60n, X.TIF.IOC, 0n]),
        await act('alice', A, 2n, CANCEL, [0n, BID, 2100n, 0n]),
        await act('alice', A, 3n, PLACE, [1n, ASK, 30_000n, 2n, X.TIF.POST_ONLY, 0n]),
        await act('bob', B, 2n, PLACE, [1n, BID, 30_010n, 2n, X.TIF.IOC, 0n]),
        await act('bob', B, 3n, WITHDRAW, [1000n, big(bob)]),
      ]);
      assert(engine.rejected.length === 0, `engine refused ${JSON.stringify(engine.rejected.map((r) => r.reason))}`);
    });
    const wdSalt = await h([M.DS.WDSALT, users.bob.keys.kEnc, 2n, 0n]);
    const wdRecord = await M.withdrawalRecord(h, big(bob), 1000n, wdSalt, 2n, 0);
    const logs2 = await daLogs(node, bridge.address);
    const wp = await withdrawalPath(h, logs2[1].payload, 2n, wdRecord);
    bobBefore = await balance(bob);
    await asOf(bob).methods.claim_withdrawal(2n, wp.index, bob, 1000n, wdSalt, wp.path).send({ from: bob, wait });
    assert((await balance(bob)) === bobBefore + 1000n, 'withdrawal not paid');
    log('bob claimed his 1000 withdrawal using the DA and his key alone');

    // Receipts and accountability (SPEC.md §11). The operator posts a bond and signs a receipt for
    // every action it sequences. Bob challenges the receipt of his withdrawal, and the operator
    // answers with the action's path in batch 2's receipts root. The operator also signed a receipt
    // for an action it then dropped; Bob challenges it, nobody can answer, and the bond pays him.
    await token.methods.mint(operator, BOND).send({ from: operator, wait });
    await tokenAt.methods.approve(bridge.address, BOND).send({ from: operator, wait });
    await asOf(operator).methods.post_bond(BOND).send({ from: operator, wait });
    const toScalar = (x: bigint) => ({ lo: x & ((1n << 128n) - 1n), hi: x >> 128n });
    const signReceipt = async (msg: bigint, seq: bigint, issued: bigint) => sign(h, receiptKey.sk, await h([51n, receiptDomain, msg, seq, issued]));
    const receipts2 = [...engine.receipts];
    const bobWd = receipts2[receipts2.length - 1]; // Bob's withdrawal, the batch's last signed action
    const sig1 = await signReceipt(bobWd.msg, bobWd.seq, issued2);
    await (node as any).warpL2TimeAtLeastBy(Number(T_SETTLE + 10n));
    bobBefore = await balance(bob);
    await asOf(bob).methods.challenge(bobWd.msg, bobWd.seq, issued2, toScalar(sig1.s), toScalar(sig1.e)).send({ from: bob, wait });
    const rpath = await receiptPath(api, b2, bobWd.segment, bobWd.slot);
    await asOf(operator)
      .methods.answer(bobWd.msg, bobWd.seq, 2n, rpath.depth, rpath.bits, [...rpath.path, ...Array(24 - rpath.path.length).fill(0n)])
      .send({ from: operator, wait });
    log(`bob challenged the receipt of his withdrawal (seq ${bobWd.seq}); the operator answered with a ${rpath.depth}-level path`);
    const dropped = { msg: randomField(), seq: engine.lastSeq + 1000n };
    const sig2 = await signReceipt(dropped.msg, dropped.seq, issued2);
    await asOf(bob).methods.challenge(dropped.msg, dropped.seq, issued2, toScalar(sig2.s), toScalar(sig2.e)).send({ from: bob, wait });
    await (node as any).warpL2TimeAtLeastBy(Number(T_RESP + 10n));
    await asOf(alice).methods.slash(await receiptLeaf(api, dropped.seq, dropped.msg)).send({ from: alice, wait });
    const bobNet = (await balance(bob)) - bobBefore;
    assert(bobNet === SLASH - REQUEST_FEE, `bob's net from the two challenges: ${bobNet}`);
    log(`a dropped receipt went unanswered: the bond paid bob ${SLASH} (net ${bobNet} after the answered challenge's fee)`);
    report.receipts = { answeredDepth: rpath.depth, slashed: SLASH };
    const bondLeft = BOND - SLASH;

    // Bob forces a withdrawal of his free collateral through the Bridge (SPEC.md §7.3), paying the
    // request fee to the operator; the next batch must process it.
    const opBefore = await balance(operator);
    await asOf(bob).methods.submit_forced(M.KIND.FORCED_WITHDRAW, B, bob, 0n).send({ from: bob, wait });
    assert((await balance(operator)) === opBefore + REQUEST_FEE, 'request fee not paid to the operator');
    const queued2 = (await allPublicEvents(node, await eventMeta(raw, 'PriorityRequested'), bridge.address)) as any[];
    const forced: M.Request[] = [];
    for (const ev of queued2.slice(requests.length)) {
      const q: M.Request = { kind: big(ev.kind), a: big(ev.a), b: big(ev.b), c: big(ev.c), sender: big(ev.sender), time: big(ev.time) };
      assert((await M.requestEntry(h, q)) === big(ev.entry), `request ${ev.index} does not match its entry`);
      forced.push(q);
    }
    requests.push(...forced);
    log(`bob queued a forced withdrawal (fee ${REQUEST_FEE} to the operator)`);

    // An hour of L2 time later funding is due; the next indices apply it.
    await (node as any).warpL2TimeAtLeastBy(Number(params.fundingInterval + 60n));
    const bobCollateral = engine.accts.get(B)!.priv.collateral;
    await runBatch('batch3', async () => {
      const t = await l2Time();
      await engine.block(t, [await update(0n, 2200n, t), await update(1n, 30_300n, t)]);
      await engine.priority(forced);
      await engine.maintenance({ sweep: true, refresh: 4 });
    });
    log(`funding applied: market 0 cum ${engine.markets[0].cumFunding}, market 1 cum ${engine.markets[1].cumFunding} (micro-units per lot)`);
    assert(engine.markets[0].cumFunding > 0n && engine.markets[1].cumFunding > 0n, 'funding not applied');
    // The forced withdrawal's record is the batch's first; Bob claims it from the DA alone.
    const forcedAmount = bobCollateral - engine.accts.get(B)!.priv.collateral;
    assert(forcedAmount > 0n, 'forced withdrawal moved nothing');
    const fwSalt = await h([M.DS.WDSALT, users.bob.keys.kEnc, 3n, 0n]);
    const fwRecord = await M.withdrawalRecord(h, big(bob), forcedAmount, fwSalt, 3n, 0);
    const fp = await withdrawalPath(h, (await daLogs(node, bridge.address))[2].payload, 3n, fwRecord);
    bobBefore = await balance(bob);
    await asOf(bob).methods.claim_withdrawal(3n, fp.index, bob, forcedAmount, fwSalt, fp.path).send({ from: bob, wait });
    assert((await balance(bob)) === bobBefore + forcedAmount, 'forced withdrawal not paid');
    log(`bob's forced withdrawal of ${forcedAmount} was processed and claimed from the DA`);
    report.forcedWithdrawal = forcedAmount;

    // 4. The operator stops. Alice queues a deposit nobody processes; after t_force, desert mode.
    await asOf(alice).methods.deposit(A, 5_000n).send({ from: alice, wait });
    const pendingIndex = BigInt(requests.length);
    // The local network's sequencer builds every block at the next slot, so L2 time is moved with its
    // debug API rather than waited for.
    log(`operator stopped; advancing L2 time by t_force (${T_FORCE} s) so alice's deposit is overdue`);
    await (node as any).warpL2TimeAtLeastBy(Number(T_FORCE + 60n));
    await asOf(bob).methods.activate_desert().send({ from: bob, wait });
    const d = (await sim('get_desert')) as any[];
    assert(d[0] === true || d[0] === 1n, 'desert mode not active');
    log('desert mode active');

    // 5. Fresh exit clients: node + Bridge address + each user's seed.
    const frozen = { accountsRoot: big(d[1]), marketDataHash: big(d[2]) };
    const before = { alice: await balance(alice), bob: await balance(bob) };
    const exits: Record<string, any> = {};
    for (const [name, seed, addr] of [['alice', ALICE_SEED, alice], ['bob', BOB_SEED, bob]] as const) {
      const [exit, exitMs] = await timed(() => exitFromDa(h, node, bridge.address, seed, frozen));
      const ps = exit.priv.positions.map((p, m) => `m${m} ${p.size}`).filter((x) => !x.endsWith(' 0'));
      log(`${name}: exit client rebuilt the frozen tree from ${exit.batches} DA logs in ${exitMs.toFixed(0)} ms; positions ${ps.join(', ')}, collateral ${exit.priv.collateral}; equity at the frozen indices: ${exit.equity}`);
      const want = X.equityAt(engine.accts.get(exit.index)!.priv, engine.markets.map((m) => m.indexPrice), engine.markets.map((m) => m.cumFunding));
      assert(exit.equity === want, `${name}: exit equity ${exit.equity} != engine ${want}`);
      exits[name] = { ...exit, ms: Math.round(exitMs) };
      await asOf(addr)
        .methods.exit_register(exit.index, addr, exit.pub.masterAuth, exit.pub.encCommitment, exit.pub.class, exit.plaintext, exit.path, exit.marketData)
        .send({ from: addr, wait });
    }
    await asOf(alice).methods.desert_refund(pendingIndex, A, 5_000n, alice).send({ from: alice, wait });
    log(`advancing L2 time past the claim window (${T_CLAIM} s)`);
    await (node as any).warpL2TimeAtLeastBy(Number(T_CLAIM + 60n));
    for (const [name, addr] of [['alice', alice], ['bob', bob]] as const) {
      await asOf(addr).methods.exit_withdraw(exits[name].index).send({ from: addr, wait });
    }
    const paid = { alice: (await balance(alice)) - before.alice, bob: (await balance(bob)) - before.bob };
    // The vault covers every claim, so each user receives exactly its equity at the frozen indices,
    // Alice also her refunded deposit.
    assert(paid.alice === 5_000n + exits.alice.equity, `alice received ${paid.alice}`);
    assert(paid.bob === exits.bob.equity, `bob received ${paid.bob}`);
    // What remains is the fee account's swept balance plus the funding rounding the users' claims
    // gave up (at most one unit per position).
    const vault = (await balance(bridge.address)) - bondLeft; // the bond is held apart from the vault
    const fees = engine.accts.get(M.FEE_INDEX)!.priv.collateral + engine.accts.get(M.INSURANCE_INDEX)!.priv.collateral;
    assert(vault >= fees && vault - fees <= 4n, `vault left with ${vault}, protocol balances ${fees}`);
    log(`alice received 5000 refund + ${exits.alice.equity}; bob received ${exits.bob.equity}; the vault keeps ${vault} (fees ${fees} + rounding)`);
    // The operator claims the fee account from the DA like any user, and is paid last: only from
    // the residual, and only t_late after the window (SPEC.md §12).
    const feeExit = await exitFromDa(h, node, bridge.address, TEST_FEE_SEED, frozen);
    assert(feeExit.index === M.FEE_INDEX && feeExit.equity === fees, `fee account claim ${feeExit.equity}`);
    await asOf(operator)
      .methods.exit_register(feeExit.index, operator, feeExit.pub.masterAuth, feeExit.pub.encCommitment, feeExit.pub.class, feeExit.plaintext, feeExit.path, feeExit.marketData)
      .send({ from: operator, wait });
    await (node as any).warpL2TimeAtLeastBy(Number(T_LATE + 60n));
    const opBefore2 = await balance(operator);
    await asOf(operator).methods.exit_withdraw(feeExit.index).send({ from: operator, wait });
    const feePaid = (await balance(operator)) - opBefore2;
    const residual = (await balance(bridge.address)) - bondLeft;
    assert(feePaid === fees && residual <= 4n, `fee account paid ${feePaid}, vault left with ${residual}`);
    log(`after t_late the operator claimed the fee account's ${feePaid}; the vault keeps ${residual} of funding rounding`);
    report.feeClaim = feePaid;
    report.exit = Object.fromEntries(
      Object.entries(exits).map(([k, e]) => [k, { batches: e.batches, ms: e.ms, positions: e.priv.positions, collateral: e.priv.collateral, equity: e.equity }]),
    );
    report.vaultResidual = residual;
    report.paid = paid;
    report.status = 'passed';
  } catch (e) {
    report.status = 'failed';
    report.error = String((e as any)?.stack ?? e).slice(0, 4000);
    throw e;
  } finally {
    report.finishedAt = new Date().toISOString();
    writeJson(join(OUT, 'e2e.json'), report);
    await api.destroy();
    await network.stop();
  }
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error(err);
    process.exit(1);
  },
);
