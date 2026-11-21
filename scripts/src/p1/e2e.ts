// P1 end to end on an in-process Aztec 6.0.0 local network, with client proving and node
// transaction-proof verification on (SPEC.md §15, P1 exit criterion):
//
//  1. Deploy the collateral token and the Bridge. Alice and Bob register (their encryption keys
//     reach the operator as constrained private events) and deposit; Bob also deposits to an
//     account that does not exist.
//  2. The operator reads the queue and the delivered keys from the chain, executes everything in
//     its engine, proves the batch (block + oracle update + priority segment, merged, root) and
//     settles it. Bob claims his refund from the vault using only the published DA.
//  3. The operator stops. Alice queues one more deposit, which nobody processes; after t_force
//     anyone can activate desert mode.
//  4. A fresh exit client, given only the node, the Bridge address and Alice's seed, rebuilds the
//     frozen accounts tree from the DA logs and opens Alice's leaf. Alice registers her claim, gets
//     her unprocessed deposit refunded, and after the claim window withdraws her collateral.
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
import { Engine } from './engine.ts';
import { exitFromDa, withdrawalPath } from './exit.ts';
import { keysFromSeed, sign } from './grumpkin.ts';
import * as M from './model.ts';
import { testParams } from './params.ts';

const log = (m: string) => console.log(`[p1-e2e] ${m}`);
const T_FORCE = 40n;
const T_CLAIM = 90n;
const ALICE_SEED = 0xa11cen;
const BOB_SEED = 0xb0bn;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

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

    const tip0 = (await sim('get_tip')) as any[];
    const head0 = big(((await sim('get_priority', [big(tip0[4])])) as any[])[0]);
    await engine.beginBatch(1n, head0, big(tip0[4]), big(tip0[3]));
    const t1 = await l2Time();
    const price = 2000n;
    await engine.block(t1, { price, time: t1, sig: await sign(h, oracleSk, await M.oracleMessage(h, engine.domain, price, t1)) });
    await engine.priority(requests);
    const w1 = await engine.endBatch();
    log(`batch 1: ${w1.segments.map((s) => s.label).join(' | ')}`);
    const b1 = await proveBatch(prover, w1, (m) => log(m));
    report.batch1 = { shape: b1.shape, ms: b1.ms, daFields: b1.daPayload.length, settleMs: await settle('batch 1', b1, [price, t1]) };

    // Bob's refund record is in the DA; he claims it with nothing but the published payload.
    const refund = requests[4];
    const record = await M.withdrawalRecord(h, refund.sender, refund.b, await M.requestEntry(h, refund), 1n, 0);
    const [batchLog] = await daLogs(node, bridge.address);
    const { index, path } = await withdrawalPath(h, batchLog.payload, 1n, record);
    const bobBefore = await balance(bob);
    await asOf(bob).methods.claim_withdrawal(1n, index, bob, refund.b, await M.requestEntry(h, refund), path).send({ from: bob, wait });
    assert((await balance(bob)) === bobBefore + 777n, 'refund not paid');
    log('bob claimed his 777 refund from the vault using the DA alone');

    // 3. The operator stops. Alice queues a deposit nobody processes; after t_force, desert mode.
    await asOf(alice).methods.deposit(0n, 5_000n).send({ from: alice, wait });
    const pendingIndex = BigInt(requests.length);
    log(`operator stopped; waiting ${T_FORCE} s for alice's pending deposit to become overdue`);
    await sleep(Number(T_FORCE + 3n) * 1000);
    await asOf(bob).methods.activate_desert().send({ from: bob, wait });
    const d = (await sim('get_desert')) as any[];
    assert(d[0] === true || d[0] === 1n, 'desert mode not active');
    log('desert mode active');

    // 4. A fresh exit client: node + Bridge address + Alice's seed.
    const [exit, exitMs] = await timed(() =>
      exitFromDa(h, node, bridge.address, ALICE_SEED, { accountsRoot: big(d[1]), marketDataHash: big(d[2]) }),
    );
    log(`exit client rebuilt the frozen tree from ${exit.batches} DA log(s) in ${exitMs.toFixed(0)} ms; account ${exit.index}, collateral ${exit.priv.collateral}, equity ${exit.equity}`);
    const aliceBefore = await balance(alice);
    await asOf(alice)
      .methods.exit_register(
        exit.index,
        alice,
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
      .send({ from: alice, wait });
    await asOf(alice).methods.desert_refund(pendingIndex, 0n, 5_000n, alice).send({ from: alice, wait });
    await sleep(Number(T_CLAIM + 3n) * 1000);
    await asOf(alice).methods.exit_withdraw(exit.index).send({ from: alice, wait });
    const aliceAfter = await balance(alice);
    assert(aliceAfter - aliceBefore === 5_000n + 1_000_000n, `alice received ${aliceAfter - aliceBefore}`);
    log(`alice exited: refund 5000 + equity 1000000 paid; vault now ${await balance(bridge.address)}`);
    report.exit = { batches: exit.batches, ms: Math.round(exitMs), equity: exit.equity, paid: aliceAfter - aliceBefore };
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
