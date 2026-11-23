// L3X on the public Aztec testnet: the P1 exit criterion (SPEC.md §15) on a public network, with
// real client proofs, real batch proofs and the network's own sequencers, in two runs that share
// nothing but published data:
//
//   node src/exchange/testnet.ts operate
//     Deploys the confidential collateral token and the Bridge. Alice and Bob register, shield
//     public balances into credits and deposit them; the operator sweeps the deposits and proves
//     and settles three batches: the deposits, trading in two markets, and a fee sweep with a
//     refresh. The operator then stops, and Bob forces a withdrawal through the Bridge that nobody
//     processes.
//
//   node src/exchange/testnet.ts exit
//     A fresh process with an empty wallet: given only the node, the Bridge's address and each
//     user's keys, it waits until Bob's request is t_force old, activates desert mode, rebuilds the
//     frozen accounts tree from the DA logs, registers each user's claim, and after the claim
//     window withdraws it. The operator claims the fee account last, t_late after the window.
//
//   node src/exchange/testnet.ts l1
//     The collateral token's L1 bridge (SPEC.md §10.6) between Sepolia and the testnet: a test
//     ERC-20 and Aztec's TokenPortal on Sepolia, the token bridge and a bridged token on L2. Alice
//     deposits from L1 to her public balance and as a credit, and exits some of each back to L1;
//     once each exit's epoch is proven, the portal releases the ERC-20. The run resumes where it
//     stopped, since an epoch takes about 40 minutes to close and be proven.
//
//   node src/exchange/testnet.ts local
//     The exchange runs against an in-process local network, whose L2 time is warped instead of
//     waited for: a rehearsal of the testnet run.
//
// On testnet the sponsored FPC pays every L2 fee. Testnet-only keys are kept in
// scripts/out/testnet-keys.json and the run's record in scripts/out/testnet.json (both ignored by
// git); deployments/aztec-testnet.json keeps the public part of the record.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { getSchnorrInitializerlessAccountContractAddress } from '@aztec-labs/accounts/schnorr';
import { setupLocalNetwork } from '@aztec-labs/aztec/testing';
import { AztecAddress, EthAddress } from '@aztec-labs/aztec.js/addresses';
import { BatchCall, Contract, getContractInstanceFromInstantiationParams } from '@aztec-labs/aztec.js/contracts';
import { SponsoredFeePaymentMethod } from '@aztec-labs/aztec.js/fee';
import { Fr, GrumpkinScalar } from '@aztec-labs/aztec.js/fields';
import { isL1ToL2MessageReady } from '@aztec-labs/aztec.js/messaging';
import { createAztecNodeClient } from '@aztec-labs/aztec.js/node';
import { TxHash, TxStatus } from '@aztec-labs/aztec.js/tx';
import { getFeeJuiceBalance } from '@aztec-labs/aztec.js/utils';
import { OutboxContract } from '@aztec-labs/ethereum/contracts';
import { SponsoredFPCContract } from '@aztec-labs/noir-contracts.js/SponsoredFPC';
import { computeL2ToL1MessageHash, computeSecretHash } from '@aztec-labs/stdlib/hash';
import { computeL2ToL1MembershipWitness } from '@aztec-labs/stdlib/messaging';
import { EmbeddedWallet } from '@aztec-labs/wallets/embedded';
import { TestERC20Abi } from '@aztec-foundation/l1-artifacts/TestERC20Abi';
import { TestERC20Bytecode } from '@aztec-foundation/l1-artifacts/TestERC20Bytecode';
import { TokenPortalAbi } from '@aztec-foundation/l1-artifacts/TokenPortalAbi';
import { TokenPortalBytecode } from '@aztec-foundation/l1-artifacts/TokenPortalBytecode';
import { type Hex, createPublicClient, createWalletClient, decodeEventLog, encodeFunctionData, formatEther, http, parseAbi, toHex, zeroAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';
import { OUT, ROOT, SHAPE, hex, randomField, readJson, timed, writeJson } from '../lib.ts';
import { type ProvedBatch, Prover, assert, newApi, proveBatch } from '../pipeline.ts';
import { type Credit, creditId } from './ctoken.ts';
import { allPublicEvents, artifact, big, eventMeta, rawArtifact } from './chain.ts';
import { Engine, signAction, signUpdate } from './engine.ts';
import { exitFromDa } from './exit.ts';
import { keysFromSeed } from './grumpkin.ts';
import * as M from './model.ts';
import { TEST_FEE_SEED, protocolAccounts, testParams } from './params.ts';
import * as X from './rules.ts';

export const NODE_URL = process.env.AZTEC_NODE_URL ?? 'https://aztec-testnet.drpc.org';
const SEPOLIA_RPC = process.env.SEPOLIA_RPC_URL ?? 'https://ethereum-sepolia-rpc.publicnode.com';
const KEYS = join(OUT, 'testnet-keys.json');
const PUBLIC_RECORD = join(ROOT, 'deployments', 'aztec-testnet.json');

// L2 time is real time on testnet (72 s slots), so the windows are minutes, not days.
const T_FORCE = 900n;
const T_CLAIM = 600n;
const T_REFRESH = 14n * 86_400n;
const T_LATE = 120n;
const REQUEST_FEE = 100n;
const T_DEP = 3600n;
const T_PAYOUT = 600n;
const MIN_DEPOSIT = 100n;
const T_SETTLE = 60n;
const T_RESP = 600n;
const SLASH = 4000n;
const FUNDING = 5_000_000n;
const ACCOUNT_A = 2n; // after the insurance (0) and fee (1) accounts
const ACCOUNT_B = 3n;

const log = (m: string) => console.log(`[testnet ${new Date().toISOString().slice(11, 19)}] ${m}`);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

type L2Key = { secret: string; salt: string; signingKey: string };
type Keys = {
  note: string;
  l1: { privateKey: string; address: string };
  l2: { operator: L2Key; alice: L2Key; bob: L2Key };
  exchange: { alice: string; bob: string; receipt: string };
};

/** The testnet-only keys, creating the L2 accounts' and the users' exchange keys on first use. */
export function loadKeys(): Keys {
  const k: Partial<Keys> = JSON.parse(readFileSync(KEYS, 'utf8'));
  if (!k.l2 || !k.exchange) {
    const l2 = (): L2Key => ({ secret: Fr.random().toString(), salt: Fr.random().toString(), signingKey: GrumpkinScalar.random().toString() });
    k.l2 ??= { operator: l2(), alice: l2(), bob: l2() };
    // Exchange seeds below 2^128; keysFromSeed hashes them.
    const seed = () => hex(randomField() >> 126n);
    k.exchange ??= { alice: seed(), bob: seed(), receipt: seed() };
    writeFileSync(KEYS, `${JSON.stringify(k, null, 2)}\n`, { mode: 0o600 });
  }
  return k as Keys;
}

const l2Key = (k: L2Key) => ({ secret: Fr.fromString(k.secret), salt: Fr.fromString(k.salt), signingKey: GrumpkinScalar.fromString(k.signingKey) });

/** Where a run happens: the node, how fees are paid, how L2 time passes, and where it is recorded. */
type Network = {
  node: any;
  /** The send options' fee settings: the sponsored FPC on testnet; none locally, where accounts hold fee juice. */
  fee?: { paymentMethod: SponsoredFeePaymentMethod };
  /** Moves L2 time on a local network; undefined on testnet, where it is waited for. */
  warp?: (seconds: number) => Promise<void>;
  record: string;
  publish: boolean;
};

async function testnet(): Promise<Network> {
  const node: any = createAztecNodeClient(NODE_URL);
  const fpc = await getContractInstanceFromInstantiationParams(SponsoredFPCContract.artifact, { salt: new Fr(0) });
  log(`node ${NODE_URL}; the sponsored FPC holds ${(await getFeeJuiceBalance(fpc.address, node)) / 10n ** 18n} fee juice`);
  return { node, fee: { paymentMethod: new SponsoredFeePaymentMethod(fpc.address) }, record: join(OUT, 'testnet.json'), publish: true };
}

function bbConfig(manifest: any) {
  const platform = `${process.arch}-${process.platform === 'darwin' ? 'macos' : 'linux'}`;
  return {
    bbWorkingDirectory: join(OUT, 'bb-work'),
    bbBinaryPath: join(homedir(), '.aztec', 'versions', manifest.aztecVersion, 'node_modules', '@aztec-foundation', 'bb.js', 'build', platform, 'bb'),
  };
}

/** A wallet with an empty in-memory PXE that proves every transaction, holding the three accounts. */
async function walletOf(net: Network, manifest: any, keys: Keys) {
  const info: any = await net.node.getNodeInfo();
  assert(info.nodeVersion === manifest.aztecVersion, `node runs ${info.nodeVersion}, contracts are built for ${manifest.aztecVersion}`);
  const wallet = await EmbeddedWallet.create(net.node, { ephemeral: true, pxe: { proverEnabled: true, syncChainTip: 'checkpointed', ...bbConfig(manifest) } as any });
  // Base fees move between estimate and inclusion; the payer is charged the fees in force.
  wallet.setMinFeePadding(4);
  const fpc = await getContractInstanceFromInstantiationParams(SponsoredFPCContract.artifact, { salt: new Fr(0) });
  await wallet.registerContract(fpc, SponsoredFPCContract.artifact);
  const make = async (k: L2Key) => {
    const { secret, salt, signingKey } = l2Key(k);
    return (await wallet.createSchnorrInitializerlessAccount(secret, salt, signingKey)).address;
  };
  const accounts = { operator: await make(keys.l2.operator), alice: await make(keys.l2.alice), bob: await make(keys.l2.bob) };
  return { info, wallet, ...accounts };
}

const wait = { waitForStatus: TxStatus.CHECKPOINTED, timeout: 3600, interval: 3 };

/** The latest block's timestamp: L2 time. */
const l2Time = async (node: any) => BigInt((await node.getBlock(await node.getBlockNumber())).header.globalVariables.timestamp);

/** Waits until L2 time is past `t`; a local network instead warps the time of its next block past it. */
async function untilL2Time(net: Network, t: bigint, what: string) {
  for (let i = 0; ; i++) {
    const now = await l2Time(net.node);
    if (now > t) return;
    if (net.warp) return net.warp(Number(t - now) + 1);
    if (i % 8 === 0) log(`waiting ${t - now} s of L2 time for ${what}`);
    await sleep(15_000);
  }
}

/**
 * Writes the sections of the record this run owns over the record on disk, so runs in separate
 * processes (the exit and the L1 bridge run may overlap) never overwrite each other's results.
 */
function save(net: Network, record: Record<string, any>, owned: string[]) {
  const onDisk = existsSync(net.record) ? readJson(net.record) : {};
  for (const k of owned) onDisk[k] = record[k];
  writeJson(net.record, onDisk);
  if (!net.publish) return;
  // The public part: addresses, configuration, transactions and results; no keys, no openings.
  const { network, l2, config, operate, exit, l1 } = onDisk;
  writeJson(PUBLIC_RECORD, { network, l2, config, operate, exit, l1 });
}

/** Sends one transaction, records it under `steps`, and resolves to the mined send. */
function sender(net: Network, persist: () => void, steps: any[]) {
  return async (label: string, interaction: any, from: any) => {
    const [sent, ms] = await timed(() => interaction.send({ from, wait, ...(net.fee ? { fee: net.fee } : {}) }));
    const r: any = (sent as any).receipt;
    steps.push({ label, txHash: r.txHash.toString(), block: Number(r.blockNumber), ms: Math.round(ms) });
    persist();
    log(`${label}: block ${r.blockNumber}, ${(ms / 1000).toFixed(0)} s`);
    return sent as any;
  };
}

async function operate(net: Network) {
  const keys = loadKeys();
  const manifest = readJson(join(OUT, 'manifest.json'));
  const { info, wallet, operator, alice, bob } = await walletOf(net, manifest, keys);
  const node = net.node;
  const api = await newApi();
  const h = M.hasher(api);
  const record: Record<string, any> = {
    network: { nodeUrl: net.publish ? NODE_URL : 'local', aztecVersion: info.nodeVersion, l1ChainId: info.l1ChainId, rollupVersion: info.rollupVersion },
    operate: { startedAt: new Date().toISOString(), steps: [] as any[] },
  };
  // A new deployment: any earlier exit run refers to the old Bridge.
  const persist = () => save(net, record, ['network', 'l2', 'config', 'operate', 'exit']);
  const tx = sender(net, persist, record.operate.steps);
  try {
    log(`Aztec ${info.nodeVersion}, L1 chain ${info.l1ChainId}; operator ${operator}, alice ${alice}, bob ${bob}`);
    const { params, oracleSks } = await testParams(h, BigInt(info.l1ChainId), randomField());
    const protocol = await protocolAccounts(h, [big(operator), big(operator)]);
    const prover = await Prover.create(api, manifest, await M.paramsHash(h, params));
    const receiptKey = await keysFromSeed(h, BigInt(keys.exchange.receipt));
    const receiptDomain = await M.domainOf(h, params);
    record.config = {
      configHash: hex(prover.configHash),
      rootVkHash: manifest.hashes.ROOT_VK_HASH,
      instance: hex(params.instance),
      tForce: Number(T_FORCE),
      tClaim: Number(T_CLAIM),
      tLate: Number(T_LATE),
      tRefresh: Number(T_REFRESH),
      tDep: Number(T_DEP),
      tPayout: Number(T_PAYOUT),
      requestFee: Number(REQUEST_FEE),
    };

    // 1. Deploy. The operator is the test token's minter: nothing is bridged in this run.
    const tokenArtifact = artifact('ctoken-ConfidentialToken');
    const bridgeArtifact = artifact('l3x_bridge-L3XBridge');
    const token = (await tx('deploy token', Contract.deploy(wallet as any, tokenArtifact, [operator]), operator)).contract;
    const bridgeDep = await tx(
      'deploy bridge',
      Contract.deploy(wallet as any, bridgeArtifact, [
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
        { t_dep: T_DEP, t_payout: T_PAYOUT, min_deposit: MIN_DEPOSIT },
        [operator, operator],
        protocol.map((p) => p.pub.masterAuth),
        protocol.map((p) => p.pub.encCommitment),
      ]),
      operator,
    );
    const bridge = bridgeDep.contract;
    record.l2 = {
      token: token.address.toString(),
      bridge: bridge.address.toString(),
      bridgeDeployBlock: Number(bridgeDep.receipt.blockNumber),
      operator: operator.toString(),
      alice: alice.toString(),
      bob: bob.toString(),
    };
    persist();
    const bridgeAt: any = await Contract.at(bridge.address, bridgeArtifact, wallet as any);
    const tokenAt: any = await Contract.at(token.address, tokenArtifact, wallet as any);
    const balance = async (who: any) => big((await tokenAt.methods.balance_of_public(who).simulate({ from: operator })).result);
    const sim = async (method: string, args: unknown[] = []) => (await bridgeAt.methods[method](...args).simulate({ from: operator })).result;

    // 2. Fund, register, shield and deposit; Alice's and Bob's transactions go out together.
    await tx('mint to alice and bob', new BatchCall(wallet as any, [token.methods.mint(alice, FUNDING), token.methods.mint(bob, FUNDING)]), operator);
    const users = {
      alice: { addr: alice, keys: await keysFromSeed(h, BigInt(keys.exchange.alice)), account: ACCOUNT_A, amount: 1_000_000n },
      bob: { addr: bob, keys: await keysFromSeed(h, BigInt(keys.exchange.bob)), account: ACCOUNT_B, amount: 2_000_000n },
    };
    const each = <T,>(f: (name: string, u: (typeof users)['alice'], i: number) => Promise<T>) => Promise.all(Object.entries(users).map(([name, u], i) => f(name, u, i)));
    await each(async (name, u) => {
      const masterAuth = await M.masterAuthOf(h, u.keys.pk!.x, u.keys.pk!.y);
      await tx(`${name} registers`, bridgeAt.methods.register(masterAuth, await M.encCommitment(h, u.keys.kEnc), u.keys.kEnc), u.addr);
    });
    const empty: Credit = { amount: 0n, blind: 0n };
    const credits = await each(async (name, u) => {
      const blind = randomField();
      await tx(`${name} shields`, tokenAt.methods.shield(u.amount, blind), u.addr);
      return { amount: u.amount, blind } as Credit;
    });
    // Each deposit moves a hidden amount into a credit the Bridge holds, under the depositor's
    // authorization of exactly that token call, and delivers the opening to the operator.
    const deposits = await each(async (name, u, i) => {
      const [salt, changeBlind, nonce] = [randomField(), randomField(), randomField()];
      const inputs = [credits[i], empty];
      const blind = await M.depositBlind(h, u.account, big(u.addr), big(u.addr), salt);
      const action = tokenAt.methods.transfer(u.addr, bridge.address, u.amount, inputs, blind, changeBlind, nonce);
      const witness = await (wallet as any).createAuthWit(u.addr, { caller: bridge.address, call: await action.getFunctionCall() });
      await tx(`${name} deposits`, bridgeAt.methods.deposit(u.account, u.amount, u.addr, salt, inputs, changeBlind, nonce).with({ authWitnesses: [witness] }), u.addr);
      return creditId(h, bridge.address, u.amount, blind);
    });

    // 3. The operator reads the delivered keys and openings and sweeps the deposits.
    const raw = rawArtifact('l3x_bridge-L3XBridge');
    const engine = await Engine.create(api, params, BigInt(manifest.vkTree.root), protocol);
    const delivered = await (wallet as any).getPrivateEvents(await eventMeta(raw, 'KeyDelivered'), { contractAddress: bridge.address, scopes: [operator] });
    for (const ev of delivered) engine.keyring.set(big(ev.event.enc_commitment), big(ev.event.k_enc));
    assert(delivered.length === 2, `the operator received ${delivered.length} keys`);
    const openings = new Map<bigint, any>();
    const byCommitment = new Map<bigint, M.DepositOpening>();
    for (const { event: e } of await (wallet as any).getPrivateEvents(await eventMeta(raw, 'DepositDelivered'), { contractAddress: bridge.address, scopes: [operator] })) {
      const o = { account_index: big(e.account_index), amount: big(e.amount), refund_to: big(e.refund_to), depositor: big(e.depositor), salt: big(e.salt) };
      const blind = await M.depositBlind(h, o.account_index, o.refund_to, o.depositor, o.salt);
      openings.set(await creditId(h, bridge.address, o.amount, blind), o);
      byCommitment.set(await M.depositCommitment(h, o.amount, o.salt), { amount: o.amount, salt: o.salt });
    }
    assert(deposits.every((c) => openings.has(c)), 'the operator cannot open every deposit');
    log(`the operator received ${delivered.length} encryption keys and ${openings.size} deposit openings by constrained delivery`);
    const noDeposit = { account_index: 0n, amount: 0n, refund_to: 0n, depositor: 0n, salt: 0n };
    const noPayout = { batch: 0n, index: 0, recipient: 0n, amount: 0n, salt: 0n, path: Array(M.WD_HEIGHT).fill(0n), blind: 0n };
    const pad = <T,>(xs: T[], z: T) => [...xs, ...Array(4 - xs.length).fill(z)];
    const swept = deposits.map((c) => openings.get(c)!);
    await tx('custody sweeps both deposits', bridgeAt.methods.custody(pad(swept, noDeposit), swept.length, pad([], noPayout), 0), operator);
    assert((await balance(bridge.address)) === 3_000_000n, 'vault after custody');

    const pq = await eventMeta(raw, 'PriorityRequested');
    const requests: M.Request[] = [];
    for (const ev of (await allPublicEvents(node, pq, bridge.address)) as any[]) {
      const r: M.Request = { kind: big(ev.kind), a: big(ev.a), b: big(ev.b), c: big(ev.c), sender: big(ev.sender), time: big(ev.time) };
      assert((await M.requestEntry(h, r)) === big(ev.entry), `request ${ev.index} does not match its entry`);
      if (r.kind === M.KIND.DEPOSIT) r.deposit = byCommitment.get(r.b);
      requests.push(r);
    }
    // Two registrations, then the two deposits custody queued with their amounts committed.
    const queuedDeposits = requests.filter((r) => r.kind === M.KIND.DEPOSIT);
    assert(requests.length === 4 && queuedDeposits.length === 2 && queuedDeposits.every((r) => r.deposit && r.b !== r.deposit.amount), `queued requests: ${requests.length}`);

    // 4. Three batches, each proved and settled within T_LAG of the L2 time it was built at.
    async function runBatch(name: string, build: (t: bigint) => Promise<void>) {
      const tip = (await sim('get_tip')) as any[];
      const head = big(((await sim('get_priority', [big(tip[4])])) as any[])[0]);
      await engine.beginBatch(big(tip[2]) + 1n, head, big(tip[4]), big(tip[3]));
      const t = await l2Time(node);
      await build(t);
      const w = await engine.endBatch();
      log(`${name}: ${w.segments.map((x) => x.label).join(' | ')}`);
      const [pb, proveMs] = (await timed(() => proveBatch(prover, w, (m) => log(m)))) as [ProvedBatch, number];
      const da = [...pb.daPayload, ...Array<bigint>(SHAPE.DA_MAX - pb.daPayload.length).fill(0n)];
      const sent = await tx(`${name} settles`, bridgeAt.methods.settle(pb.header, pb.rootProof, pb.rootVk, da, pb.daPayload.length, pb.marketData), operator);
      assert(big(((await sim('get_tip')) as any[])[0]) === pb.header[1], `${name}: tip != header`);
      const settledAt = BigInt((await node.getBlock(sent.receipt.blockNumber)).header.globalVariables.timestamp);
      Object.assign(record.operate.steps.at(-1), { shape: pb.shape, daFields: pb.daPayload.length, proveMs: Math.round(proveMs), batchTime: Number(t), lagS: Number(settledAt - t) });
      persist();
    }
    const update = (market: bigint, price: bigint, t: bigint) => signUpdate(h, engine.domain, oracleSks, [0, 2], market, price, price, t);
    await runBatch('batch 1', async (t) => {
      await engine.block(t, [await update(0n, 2000n, t), await update(1n, 30_000n, t), await update(2n, 100n, t)]);
      await engine.priority(requests);
    });
    const act = (who: keyof typeof users, nonce: bigint, kind: bigint, p: bigint[]) => signAction(h, engine.domain, users[who].keys, kind, users[who].account, nonce, p);
    const { BID, ASK } = M.SIDE;
    await runBatch('batch 2', async (t) => {
      await engine.block(t, [await update(0n, 2100n, t)]);
      await engine.trade([
        await act('alice', 1n, X.KIND_ACT.PLACE, [0n, BID, 2100n, 100n, X.TIF.GTC, 0n]),
        await act('bob', 1n, X.KIND_ACT.PLACE, [0n, ASK, 2090n, 60n, X.TIF.IOC, 0n]),
        await act('alice', 2n, X.KIND_ACT.PLACE, [1n, ASK, 30_000n, 2n, X.TIF.POST_ONLY, 0n]),
        await act('bob', 2n, X.KIND_ACT.PLACE, [1n, BID, 30_010n, 2n, X.TIF.IOC, 0n]),
      ]);
      assert(engine.rejected.length === 0, `engine refused ${JSON.stringify(engine.rejected.map((r) => r.reason))}`);
    });
    await runBatch('batch 3', async (t) => {
      await engine.block(t, [await update(1n, 30_050n, t)]);
      await engine.maintenance({ sweep: true, refresh: 4 });
    });
    const sizes = (i: bigint) => engine.accts.get(i)!.priv.positions.map((p) => p.size);
    log(`positions: alice ${sizes(ACCOUNT_A)}, bob ${sizes(ACCOUNT_B)}`);
    const equityOf = (i: bigint) => X.equityAt(engine.accts.get(i)!.priv, engine.markets.map((m) => m.indexPrice), engine.markets.map((m) => m.cumFunding));
    record.operate.expected = {
      alice: equityOf(ACCOUNT_A).toString(),
      bob: equityOf(ACCOUNT_B).toString(),
      'fee account': engine.accts.get(M.FEE_INDEX)!.priv.collateral.toString(),
    };

    // 5. The operator stops. Bob forces a withdrawal through the Bridge; nobody processes it.
    await tx('bob approves the request fee', tokenAt.methods.approve(bridge.address, REQUEST_FEE), bob);
    await tx('bob forces a withdrawal', bridgeAt.methods.submit_forced(M.KIND.FORCED_WITHDRAW, ACCOUNT_B, bob, 0n), bob);
    const tip = (await sim('get_tip')) as any[];
    const forcedAt = big(((await sim('get_priority', [big(tip[4])])) as any[])[2]);
    record.operate.forcedAt = Number(forcedAt);
    record.operate.status = 'passed';
    log(`the operator has stopped; desert mode may be activated after L2 time ${forcedAt + T_FORCE}`);
  } catch (e) {
    record.operate.status = 'failed';
    record.operate.error = String((e as any)?.stack ?? e).slice(0, 4000);
    throw e;
  } finally {
    record.operate.finishedAt = new Date().toISOString();
    persist();
    await api.destroy();
    await wallet.stop();
  }
}

async function exit(net: Network) {
  const keys = loadKeys();
  const manifest = readJson(join(OUT, 'manifest.json'));
  const record = existsSync(net.record) ? readJson(net.record) : {};
  assert(record.operate?.status === 'passed', 'run `testnet.ts operate` first');
  // A fresh wallet: an empty PXE, the users' keys and the contracts' addresses. Nothing else.
  const { wallet, operator, alice, bob } = await walletOf(net, manifest, keys);
  const node = net.node;
  const api = await newApi();
  const h = M.hasher(api);
  record.exit = { startedAt: new Date().toISOString(), steps: [] as any[] };
  const persist = () => save(net, record, ['exit']);
  const tx = sender(net, persist, record.exit.steps);
  try {
    const bridgeAddress = AztecAddress.fromStringUnsafe(record.l2.bridge);
    const tokenAddress = AztecAddress.fromStringUnsafe(record.l2.token);
    const bridgeArtifact = artifact('l3x_bridge-L3XBridge');
    const tokenArtifact = artifact('ctoken-ConfidentialToken');
    await wallet.registerContract(await node.getContract(bridgeAddress), bridgeArtifact);
    await wallet.registerContract(await node.getContract(tokenAddress), tokenArtifact);
    const bridgeAt: any = await Contract.at(bridgeAddress, bridgeArtifact, wallet as any);
    const tokenAt: any = await Contract.at(tokenAddress, tokenArtifact, wallet as any);
    const balance = async (who: any) => big((await tokenAt.methods.balance_of_public(who).simulate({ from: bob })).result);
    const sim = async (method: string, args: unknown[] = []) => (await bridgeAt.methods[method](...args).simulate({ from: bob })).result;

    let d = (await sim('get_desert')) as any[];
    if (!(d[0] === true || d[0] === 1n)) {
      const tip = (await sim('get_tip')) as any[];
      const pending = (await sim('get_priority', [big(tip[4])])) as any[];
      await untilL2Time(net, big(pending[2]) + T_FORCE, "Bob's forced withdrawal to be t_force overdue");
      await tx('bob activates desert mode', bridgeAt.methods.activate_desert(), bob);
      d = (await sim('get_desert')) as any[];
    }
    const frozen = { accountsRoot: big(d[1]), marketDataHash: big(d[2]) };
    const claimClose = big(d[3]);
    log(`desert mode: frozen accounts root ${hex(frozen.accountsRoot)}; claims close at L2 time ${claimClose}`);

    // Each claimant rebuilds the frozen tree from the DA alone and opens its own leaf.
    const claimants = [
      ['alice', BigInt(keys.exchange.alice), alice],
      ['bob', BigInt(keys.exchange.bob), bob],
      ['fee account', TEST_FEE_SEED, operator],
    ] as const;
    const exits: Record<string, any> = {};
    for (const [name, seed, addr] of claimants) {
      const [e, ms] = await timed(() => exitFromDa(h, node, bridgeAddress, seed, frozen));
      const ps = e.priv.positions.map((p, m) => `m${m} ${p.size}`).filter((x) => !x.endsWith(' 0'));
      log(`${name}: rebuilt the frozen tree from ${e.batches} DA logs in ${(ms / 1000).toFixed(1)} s; account ${e.index}, positions [${ps.join(', ')}], collateral ${e.priv.collateral}, equity ${e.equity}`);
      assert(e.equity.toString() === record.operate.expected[name], `${name}: equity from the DA ${e.equity} != the operator's ${record.operate.expected[name]}`);
      exits[name] = { ...e, addr, ms: Math.round(ms) };
      await tx(`${name} registers its claim`, bridgeAt.methods.exit_register(e.index, addr, e.pub.masterAuth, e.pub.encCommitment, e.pub.class, e.plaintext, e.path, e.marketData), addr);
    }

    await untilL2Time(net, claimClose, 'the claim window to close');
    const paid: Record<string, string> = {};
    const withdraw = async (name: string) => {
      const e = exits[name];
      const before = await balance(e.addr);
      await tx(`${name} withdraws its claim`, bridgeAt.methods.exit_withdraw(e.index), e.addr);
      const got = (await balance(e.addr)) - before;
      assert(got === e.equity, `${name} received ${got}; its equity is ${e.equity}`);
      paid[name] = got.toString();
    };
    await withdraw('alice');
    await withdraw('bob');
    // The protocol's own account is paid last, and only t_late after the window (SPEC.md §12).
    await untilL2Time(net, claimClose + T_LATE, 't_late to pass after the window');
    await withdraw('fee account');
    const residual = await balance(bridgeAddress);
    log(`paid ${JSON.stringify(paid)}; the vault keeps ${residual}`);
    record.exit.paid = paid;
    record.exit.vaultResidual = residual.toString();
    record.exit.rebuild = Object.fromEntries(Object.entries(exits).map(([k, e]) => [k, { batches: e.batches, ms: e.ms, account: Number(e.index), equity: e.equity.toString() }]));
    record.exit.status = 'passed';
  } catch (e) {
    record.exit.status = 'failed';
    record.exit.error = String((e as any)?.stack ?? e).slice(0, 4000);
    throw e;
  } finally {
    record.exit.finishedAt = new Date().toISOString();
    persist();
    await api.destroy();
    await wallet.stop();
  }
}

/** Aztec's Hash.sha256ToField: a zero byte, then the first 31 bytes of the SHA-256. */
const sha256ToField = (data: Hex) => BigInt(`0x${createHash('sha256').update(Buffer.from(data.slice(2), 'hex')).digest().subarray(0, 31).toString('hex')}`);
const withdrawAbi = parseAbi(['function withdraw(address,uint256,address)']);

async function l1(net: Network) {
  const keys = loadKeys();
  const manifest = readJson(join(OUT, 'manifest.json'));
  const record = existsSync(net.record) ? readJson(net.record) : {};
  record.network ??= {};
  const { info, wallet, operator, alice } = await walletOf(net, manifest, keys);
  const node = net.node;
  const l1Addresses = info.l1ContractAddresses;
  const chain = { ...sepolia, id: Number(info.l1ChainId) };
  const account = privateKeyToAccount(keys.l1.privateKey as Hex);
  const pub = createPublicClient({ chain, transport: http(SEPOLIA_RPC) });
  const l1w = createWalletClient({ account, chain, transport: http(SEPOLIA_RPC) });
  const eth = await pub.getBalance({ address: account.address });
  assert(eth > 0n, `the L1 deployer ${account.address} holds no Sepolia ETH`);
  log(`L1 deployer ${account.address} holds ${formatEther(eth)} Sepolia ETH`);
  const r = (record.l1 ??= { startedAt: new Date().toISOString(), steps: [] as any[] });
  // Credit openings stay out of the public record.
  const openings = (record.l1Openings ??= {});
  const persist = () => save(net, record, ['l1', 'l1Openings']);
  const tx = sender(net, persist, r.steps);
  const l1Tx = async (label: string, hash: Hex) => {
    const receipt = await pub.waitForTransactionReceipt({ hash, timeout: 900_000 });
    assert(receipt.status === 'success', `${label}: L1 transaction ${hash} reverted`);
    r.steps.push({ label, l1TxHash: hash, l1Block: Number(receipt.blockNumber), gasUsed: Number(receipt.gasUsed) });
    persist();
    log(`${label}: L1 block ${receipt.blockNumber}, ${receipt.gasUsed} gas`);
    return receipt;
  };
  const write = async (label: string, address: Hex, abi: any, functionName: string, args: unknown[]) =>
    l1Tx(label, await l1w.writeContract({ address, abi, functionName, args } as any));
  const bridgeArtifact = artifact('ctbridge-ConfidentialTokenBridge');
  const tokenArtifact = artifact('ctoken-ConfidentialToken');
  const recipient = account.address;
  try {
    // 1. Deploy, once: the ERC-20 and the portal on Sepolia, the bridge and its token on L2.
    if (!r.portal) {
      const erc20 = (await l1Tx('deploy the ERC-20 on L1', await l1w.deployContract({ abi: TestERC20Abi, bytecode: TestERC20Bytecode, args: ['L3X Test USD', 'TUSD', account.address] })))
        .contractAddress as Hex;
      const portal = (await l1Tx('deploy the TokenPortal on L1', await l1w.deployContract({ abi: TokenPortalAbi, bytecode: TokenPortalBytecode, args: [] }))).contractAddress as Hex;
      const bridge = (await tx('deploy the token bridge', Contract.deploy(wallet as any, bridgeArtifact, [EthAddress.fromString(portal)]), operator)).contract;
      const token = (await tx('deploy the bridged token', Contract.deploy(wallet as any, tokenArtifact, [bridge.address]), operator)).contract;
      await tx('bind the token to its bridge', bridge.methods.set_token(token.address), operator);
      await write('initialize the portal', portal, TokenPortalAbi, 'initialize', [l1Addresses.registryAddress.toString(), erc20, bridge.address.toString()]);
      await write('make the deployer an ERC-20 minter', erc20, TestERC20Abi, 'addMinter', [account.address]);
      await write('mint 10,000 on L1', erc20, TestERC20Abi, 'mint', [account.address, 10_000n]);
      Object.assign(r, { erc20, portal, l2Bridge: bridge.address.toString(), l2Token: token.address.toString() });
      persist();
      log(`L1: ERC-20 ${erc20}, portal ${portal}; L2: bridge ${r.l2Bridge}, token ${r.l2Token}`);
    } else {
      for (const [addr, art] of [[r.l2Bridge, bridgeArtifact], [r.l2Token, tokenArtifact]] as const) {
        await wallet.registerContract(await node.getContract(AztecAddress.fromStringUnsafe(addr)), art);
      }
    }
    const bridgeAt: any = await Contract.at(AztecAddress.fromStringUnsafe(r.l2Bridge), bridgeArtifact, wallet as any);
    const tokenAt: any = await Contract.at(AztecAddress.fromStringUnsafe(r.l2Token), tokenArtifact, wallet as any);
    const publicBalance = async (who: any) => big((await tokenAt.methods.balance_of_public(who).simulate({ from: alice })).result);
    const erc20Balance = async (who: Hex) => (await pub.readContract({ address: r.erc20, abi: TestERC20Abi, functionName: 'balanceOf', args: [who] })) as bigint;

    /** Deposits through the portal; returns the claim's secret and the message's key and leaf index. */
    async function deposit(kind: 'public' | 'private', amount: bigint) {
      const secret = Fr.random();
      const secretHash = (await computeSecretHash(secret)).toString() as Hex;
      await write(`approve the portal for ${amount}`, r.erc20, TestERC20Abi, 'approve', [r.portal, amount]);
      const receipt =
        kind === 'public'
          ? await write(`deposit ${amount} to alice's public balance`, r.portal, TokenPortalAbi, 'depositToAztecPublic', [alice.toString() as Hex, amount, secretHash])
          : await write(`deposit ${amount} without a recipient`, r.portal, TokenPortalAbi, 'depositToAztecPrivate', [amount, secretHash]);
      const ev: any = receipt.logs
        .filter((l) => l.address.toLowerCase() === r.portal.toLowerCase())
        .map((l) => decodeEventLog({ abi: TokenPortalAbi, data: l.data, topics: l.topics }))
        .find((d: any) => d.eventName.startsWith('DepositToAztec'));
      assert(!!ev, 'the portal emitted no deposit event');
      return { secret, key: Fr.fromString(ev.args.key), index: BigInt(ev.args.index) };
    }
    /** An L1-to-L2 message is consumable once a checkpointed L2 block includes it. */
    async function untilReady(label: string, key: Fr) {
      const [, ms] = await timed(async () => {
        while (!(await isL1ToL2MessageReady(node, key, 'checkpointed'))) await sleep(15_000);
      });
      log(`${label}: the message reached L2 in ${(ms / 1000).toFixed(0)} s`);
    }

    // 2. Deposits, once: one to Alice's public balance, one claimed as her credit.
    if (!r.claimed) {
      const d1 = await deposit('public', 1000n);
      await untilReady('public deposit', d1.key);
      await tx('alice claims 1000 to her public balance', bridgeAt.methods.claim_public(alice, 1000n, d1.secret, d1.index), alice);
      assert((await publicBalance(alice)) === 1000n, 'public claim');
      const d2 = await deposit('private', 600n);
      await untilReady('deposit without a recipient', d2.key);
      const blind = Fr.random().toBigInt();
      await tx('alice claims 600 as a credit', bridgeAt.methods.claim_confidential(alice, 600n, blind, d2.secret, d2.index), alice);
      openings.credit = hex(blind);
      r.claimed = true;
      persist();
    }

    // 3. Exits, once: 400 of her public balance and 250 of her credit; 350 of change stays on L2.
    if (!r.exits) {
      const to = EthAddress.fromString(recipient);
      const e1 = await tx('alice exits 400 of her public balance', bridgeAt.methods.exit_public(to, 400n, EthAddress.ZERO), alice);
      assert((await publicBalance(alice)) === 600n, 'public exit burn');
      const change = Fr.random().toBigInt();
      openings.change = hex(change);
      const credits = [{ amount: 600n, blind: BigInt(openings.credit) }, { amount: 0n, blind: 0n }];
      const e2 = await tx('alice exits 250 of her credit', bridgeAt.methods.exit_confidential(to, 250n, credits, change, EthAddress.ZERO), alice);
      r.exits = [
        { label: 'public exit', amount: '400', txHash: e1.receipt.txHash.toString() },
        { label: 'confidential exit', amount: '250', txHash: e2.receipt.txHash.toString() },
      ];
      persist();
    }

    // 4. Releases: once an exit's epoch is proven, the Outbox root covers its message and the
    // portal releases the ERC-20.
    const outbox = new OutboxContract(pub as any, l1Addresses.outboxAddress.toString());
    for (const e of r.exits) {
      if (e.released) continue;
      const content = new Fr(sha256ToField(encodeFunctionData({ abi: withdrawAbi, functionName: 'withdraw', args: [recipient, BigInt(e.amount), zeroAddress] })));
      const message = await computeL2ToL1MessageHash({
        l2Sender: AztecAddress.fromStringUnsafe(r.l2Bridge),
        l1Recipient: EthAddress.fromString(r.portal),
        content,
        rollupVersion: new Fr(info.rollupVersion),
        chainId: new Fr(info.l1ChainId),
      });
      let witness: any;
      const [, ms] = await timed(async () => {
        for (let i = 0; !witness; i++) {
          witness = await computeL2ToL1MembershipWitness(node, outbox as any, message, TxHash.fromString(e.txHash));
          if (witness) break;
          if (i % 10 === 0) log(`${e.label}: waiting for its epoch to be proven on L1`);
          await sleep(60_000);
        }
      });
      const before = await erc20Balance(recipient);
      await write(`${e.label}: the portal releases ${e.amount}`, r.portal, TokenPortalAbi, 'withdraw', [
        recipient,
        BigInt(e.amount),
        false,
        BigInt(witness.epochNumber),
        BigInt(witness.numCheckpointsInEpoch),
        witness.leafIndex,
        witness.siblingPath.toBufferArray().map((b: Buffer) => toHex(b)),
      ]);
      assert((await erc20Balance(recipient)) === before + BigInt(e.amount), `${e.label}: the portal did not release ${e.amount}`);
      Object.assign(e, { released: true, epoch: Number(witness.epochNumber), waitedS: Math.round(ms / 1000) });
      persist();
    }

    // The credit's change stays on L2: Alice spends it to her public balance, and the portal then
    // holds exactly the token's supply on L2.
    if (!r.changeSpent) {
      const change = [{ amount: 350n, blind: BigInt(openings.change) }, { amount: 0n, blind: 0n }];
      await tx('alice spends her 350 of change', tokenAt.methods.unshield(alice, 350n, change, 0n), alice);
      r.changeSpent = true;
    }
    const supply = await publicBalance(alice);
    const portalHolds = await erc20Balance(r.portal);
    assert(supply === 950n && portalHolds === 950n, `L2 supply ${supply}, portal holds ${portalHolds}`);
    log(`the portal holds ${portalHolds}, exactly the token's supply on L2`);
    r.portalHolds = portalHolds.toString();
    r.status = 'passed';
  } catch (e) {
    r.status = 'failed';
    r.error = String((e as any)?.stack ?? e).slice(0, 4000);
    throw e;
  } finally {
    r.finishedAt = new Date().toISOString();
    persist();
    await wallet.stop();
  }
}

/** Both runs on an in-process local network that funds the three accounts' fees at genesis. */
async function local() {
  const keys = loadKeys();
  const manifest = readJson(join(OUT, 'manifest.json'));
  const funded = await Promise.all(
    Object.values(keys.l2).map(async (k) => {
      const { secret, salt, signingKey } = l2Key(k);
      return getSchnorrInitializerlessAccountContractAddress(signingKey, salt, secret);
    }),
  );
  log('starting an in-process local network (realProofs: true)');
  const network = await setupLocalNetwork({ fundedAddresses: funded, config: { realProofs: true, p2pEnabled: false, ...bbConfig(manifest) } as any });
  try {
    const net: Network = {
      node: network.node,
      warp: (s) => (network.node as any).warpL2TimeAtLeastBy(s),
      record: join(OUT, 'testnet-local.json'),
      publish: false,
    };
    await operate(net);
    await exit(net);
  } finally {
    await network.stop();
  }
}

const commands: Record<string, () => Promise<void>> = {
  operate: async () => operate(await testnet()),
  exit: async () => exit(await testnet()),
  l1: async () => l1(await testnet()),
  local,
};
const command = process.argv[2];
if (!commands[command]) {
  console.error(`usage: node src/exchange/testnet.ts ${Object.keys(commands).join(' | ')}`);
  process.exit(2);
}
commands[command]().then(
  () => process.exit(0),
  (err) => {
    console.error(err);
    process.exit(1);
  },
);
