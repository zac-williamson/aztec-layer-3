// P1 end to end on an in-process Aztec 6.0.0 local network, with client proving and node
// transaction-proof verification on (SPEC.md §15, P1 exit criterion):
//
//  1. Deploy the collateral token and the Bridge. Alice and Bob register (their encryption keys
//     reach the operator as constrained private events) and deposit; Bob also deposits to an
//     account that does not exist.
//  2. The operator reads the queue and the delivered keys from the chain, executes everything in
//     its engine, proves the batch (block + oracle update + priority segments, merged, root) and
//     settles it. Bob claims his refund from the vault using only the published DA.
//  3. Batch 2: the index moves to 2100; Alice rests a bid, Bob sells into it with an IOC order,
//     Alice cancels the rest and Bob withdraws. Bob claims the withdrawal using the DA alone.
//     Batch 3: the index moves to 2200 and both accounts are refreshed.
//  4. The operator stops. Alice queues one more deposit, which nobody processes; after t_force
//     anyone can activate desert mode.
//  5. For each user, a fresh exit client, given only the node, the Bridge address and the user's
//     seed, rebuilds the frozen accounts tree from the DA logs and opens the user's leaf. Each
//     registers a claim valued at the frozen index (Alice long, Bob short); Alice's unprocessed
//     deposit is refunded; after the claim window both withdraw, and the vault is empty.
//
// Writes scripts/out/p1-e2e.json.
import { homedir } from 'node:os';
import { join } from 'node:path';
import { getInitialTestAccountsData } from '@aztec-labs/accounts/testing';
import { TEST_FEE_PADDING, setupLocalNetwork } from '@aztec-labs/aztec/testing';
import { Contract } from '@aztec-labs/aztec.js/contracts';
import { TxStatus } from '@aztec-labs/aztec.js/tx';
import { EmbeddedWallet } from '@aztec-labs/wallets/embedded';
import { OUT, SHAPE, hex, randomField, readJson, timed, writeJson } from '../lib.ts';
import { type ProvedBatch, Prover, assert, newApi, proveBatch } from '../pipeline.ts';
import { allPublicEvents, artifact, big, daLogs, eventMeta, rawArtifact } from './chain.ts';
import { Engine, signAction } from './engine.ts';
import * as X from './rules.ts';
import { exitFromDa, withdrawalPath } from './exit.ts';
import { keysFromSeed, sign } from './grumpkin.ts';
import * as M from './model.ts';
import { testParams } from './params.ts';

const log = (m: string) => console.log(`[p1-e2e] ${m}`);
const T_FORCE = 3600n;
const T_CLAIM = 86_400n;
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

    // Deployment-specific parameters: this chain, a fresh instance id, the test oracle key.
    const { params, oracleSk } = await testParams(h, BigInt(info.l1ChainId), randomField());
    const prover = await Prover.create(api, manifest, await M.paramsHash(h, params));
    log(`config hash ${hex(prover.configHash)}`);

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
    await asOf(alice).methods.deposit(0n, 1_000_000n).send({ from: alice, wait });
    await asOf(bob).methods.deposit(1n, 2_000_000n).send({ from: bob, wait });
    await asOf(bob).methods.deposit(42n, 777n).send({ from: bob, wait }); // no account 42: refund
    log(`deposits queued; vault holds ${await balance(bridge.address)}`);

    // 2. The operator reads the queue and its delivered keys from the chain, and settles batch 1.
    const engine = await Engine.create(api, params, BigInt(manifest.vkTree.root));
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
      const r: M.Request = { kind: big(ev.kind), a: big(ev.a), b: big(ev.b), sender: big(ev.sender), time: big(ev.time) };
      assert((await M.requestEntry(h, r)) === big(ev.entry), `request ${ev.index} does not match its entry`);
      requests.push(r);
    }
    const sim = async (method: string, args: unknown[] = []) => (await bridge.methods[method](...args).simulate({ from: operator })).result;

    async function settle(name: string, b: ProvedBatch, market: [bigint, bigint]) {
      const da = [...b.daPayload, ...Array<bigint>(SHAPE.DA_MAX - b.daPayload.length).fill(0n)];
      const args = [b.header, b.rootProof, b.rootVk, da, b.daPayload.length, market];
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
      const market: [bigint, bigint] = [engine.market.indexPrice, engine.market.indexTime];
      report[name] = { shape: b.shape, ms: b.ms, daFields: b.daPayload.length, settleMs: await settle(name, b, market) };
      return b;
    }
    const oracle = async (price: bigint, time: bigint) => ({
      price,
      time,
      sig: await sign(h, oracleSk, await M.oracleMessage(h, engine.domain, price, time)),
    });

    await runBatch('batch1', async () => {
      const t = await l2Time();
      await engine.block(t, await oracle(2000n, t));
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
    await runBatch('batch2', async () => {
      const t = await l2Time();
      await engine.block(t, await oracle(2100n, t));
      await engine.trade([
        await act('alice', 0n, 1n, X.KIND_ACT.PLACE, [BID, 2100n, 100n, X.TIF.GTC]),
        await act('bob', 1n, 1n, X.KIND_ACT.PLACE, [ASK, 2090n, 60n, X.TIF.IOC]),
        await act('alice', 0n, 2n, X.KIND_ACT.CANCEL, [BID, 2100n, 0n, 0n]),
        await act('bob', 1n, 2n, X.KIND_ACT.WITHDRAW, [1000n, big(bob), 0n, 0n]),
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

    await runBatch('batch3', async () => {
      const t = await l2Time();
      await engine.block(t, await oracle(2200n, t));
      await engine.refresh(2);
    });

    // 4. The operator stops. Alice queues a deposit nobody processes; after t_force, desert mode.
    await asOf(alice).methods.deposit(0n, 5_000n).send({ from: alice, wait });
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
      log(`${name}: exit client rebuilt the frozen tree from ${exit.batches} DA logs in ${exitMs.toFixed(0)} ms; position ${exit.priv.size} at notional ${exit.priv.entry}, collateral ${exit.priv.collateral}; equity at index ${exit.indexPrice}: ${exit.equity}`);
      exits[name] = { ...exit, ms: Math.round(exitMs) };
      await asOf(addr)
        .methods.exit_register(
          exit.index,
          addr,
          exit.pub.masterAuth,
          exit.pub.encCommitment,
          exit.pub.class,
          M.enc(exit.priv.collateral),
          M.enc(exit.priv.size),
          M.enc(exit.priv.entry),
          exit.priv.blind,
          exit.path,
          exit.indexPrice,
          exit.indexTime,
        )
        .send({ from: addr, wait });
    }
    await asOf(alice).methods.desert_refund(pendingIndex, 0n, 5_000n, alice).send({ from: alice, wait });
    log(`advancing L2 time past the claim window (${T_CLAIM} s)`);
    await (node as any).warpL2TimeAtLeastBy(Number(T_CLAIM + 60n));
    for (const [name, addr] of [['alice', alice], ['bob', bob]] as const) {
      await asOf(addr).methods.exit_withdraw(exits[name].index).send({ from: addr, wait });
    }
    const paid = { alice: (await balance(alice)) - before.alice, bob: (await balance(bob)) - before.bob };
    // Alice: long 60 entered at 2100, valued at 2200: 1,000,000 + 60 · 100. Bob: the mirror image,
    // less his 1000 withdrawal.
    assert(paid.alice === 5_000n + 1_006_000n, `alice received ${paid.alice}`);
    assert(paid.bob === 1_993_000n, `bob received ${paid.bob}`);
    const vault = await balance(bridge.address);
    assert(vault === 0n, `vault left with ${vault}`);
    log(`alice received 5000 refund + 1006000; bob received 1993000; the vault is empty`);
    report.exit = Object.fromEntries(
      Object.entries(exits).map(([k, e]) => [k, { batches: e.batches, ms: e.ms, size: e.priv.size, entry: e.priv.entry, collateral: e.priv.collateral, equity: e.equity }]),
    );
    report.paid = paid;
    report.status = 'passed';
  } catch (e) {
    report.status = 'failed';
    report.error = String((e as any)?.stack ?? e).slice(0, 4000);
    throw e;
  } finally {
    report.finishedAt = new Date().toISOString();
    writeJson(join(OUT, 'p1-e2e.json'), report);
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
