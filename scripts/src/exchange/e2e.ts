// End to end on an in-process Aztec 6.0.0 local network, with client proving and node
// transaction-proof verification on (SPEC.md §15, the P1 exit criterion, extended through C1
// custody, SPEC.md §10.3–10.5):
//
//  1. Deploy the confidential collateral token (D7) and the Bridge, whose genesis holds the
//     operator's insurance and fee accounts. Alice and Bob register (their encryption keys reach
//     the operator as constrained private events), shield public balances into credits, and
//     deposit: each deposit moves a hidden amount into a credit the Bridge holds, under the
//     depositor's authorization of that token call, and delivers the opening to the operator. Bob
//     also deposits to an account that does not exist.
//  2. The operator reads the delivered openings, and its custody transaction sweeps the three
//     deposits into the vault and queues them with their amounts committed; only the net is
//     public. It executes everything in its engine, proves the batch (a block with 2-of-3 signed
//     indices for three markets, priority segments, merged, root) and settles it.
//  3. Batch 2: Alice rests a bid in market 0 and Bob sells into it; Alice offers in market 1 and
//     Bob buys; Alice cancels her rest and Bob withdraws. A custody transaction pays Bob's refund
//     from batch 1 as a credit, delivered to him; custody never pays the withdrawal, so after
//     t_payout Bob claims it from the vault with the DA and his key alone.
//     The operator posts a bond. Bob challenges the receipt of his withdrawal and the operator
//     answers with its path in batch 2's receipts root; a receipt for an action the operator
//     dropped goes unanswered and the bond pays Bob.
//     Bob then forces a withdrawal of his free collateral through the Bridge, paying the request
//     fee, and rekeys his account to a new master key and encryption key. Batch 3, an hour of L2
//     time later: new indices, so funding is applied; the forced withdrawal and the rekey are
//     processed; fees are swept and the accounts refreshed. A custody transaction
//     pays the forced withdrawal and sweeps a new deposit of Alice's, netting the two.
//  4. The operator stops: Alice's swept deposit is queued but never processed, and a second one is
//     never swept. After t_force anyone can activate desert mode.
//  5. For each user, a fresh exit client, given only the node, the Bridge address and the user's
//     seed (Bob's new one: his old seed no longer opens his account), rebuilds the frozen accounts
//     tree from the deployment event and the DA logs and opens the user's leaf. Each registers a claim valued at the frozen indices with funding accrued to
//     the freeze. Alice's queued deposit is refunded from the vault and her unswept one returns to
//     her as a credit; after the claim window both users withdraw.
//     The operator then claims the fee account from the DA in the same way; it is paid only from
//     the residual and only t_late after the window, which leaves the vault with funding rounding.
//
// Writes scripts/out/e2e.json.
import { homedir } from 'node:os';
import { join } from 'node:path';
import { getInitialTestAccountsData } from '@aztec-labs/accounts/testing';
import { TEST_FEE_PADDING, setupLocalNetwork } from '@aztec-labs/aztec/testing';
import { Contract } from '@aztec-labs/aztec.js/contracts';
import { Fr } from '@aztec-labs/aztec.js/fields';
import { computeSiloedPrivateLogFirstField } from '@aztec-labs/stdlib/hash';
import { TxStatus } from '@aztec-labs/aztec.js/tx';
import { EmbeddedWallet } from '@aztec-labs/wallets/embedded';
import { OUT, SHAPE, hex, randomField, readJson, timed, writeJson } from '../lib.ts';
import { type Credit, PARTIES_LOG_TAG, creditId } from './ctoken.ts';
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
// Custody (SPEC.md §10.3): deposits are reclaimable a day after they are made; custody has ten
// minutes to pay a settled record before its recipient may claim it from the vault.
const T_DEP = 86_400n;
const T_PAYOUT = 600n;
const MIN_DEPOSIT = 100n;
// Receipts (SPEC.md §11): the operator's receipt key, the challenge rules and its bond.
const RECEIPT_SEED = 0x6c33782e72637074n; // "l3x.rcpt"
const T_SETTLE = 60n;
const T_RESP = 600n;
const SLASH = 4000n;
const BOND = 10_000n;
const ALICE_SEED = 0xa11cen;
const BOB_SEED = 0xb0bn;
/** Bob's keys after his rekey (SPEC.md §7.3). */
const BOB_SEED2 = 0xb0b2n;

async function main() {
  const manifest = readJson(join(OUT, 'manifest.json'));
  const report: Record<string, any> = { startedAt: new Date().toISOString(), aztecVersion: manifest.aztecVersion };
  const accounts = await getInitialTestAccountsData();
  const platform = `${process.arch === 'x64' ? 'amd64' : process.arch}-${process.platform === 'darwin' ? 'macos' : 'linux'}`;
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

    // 1. Deploy, register, shield, deposit.
    const tokenArtifact = artifact('ctoken-ConfidentialToken');
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
      { t_dep: T_DEP, t_payout: T_PAYOUT, min_deposit: MIN_DEPOSIT },
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
    /** Public token balance; the Bridge's is the vault plus the bond. */
    const balance = async (who: any) => big((await tokenAt.methods.balance_of_public(who).simulate({ from: operator })).result);
    for (const who of [alice, bob]) {
      await token.methods.mint(who, 5_000_000n).send({ from: operator, wait });
      // The allowance covers request and challenge fees, paid from public balances.
      await tokenAt.methods.approve(bridge.address, 5_000_000n).send({ from: who, wait });
    }
    const rawToken = rawArtifact('ctoken-ConfidentialToken');
    const empty: Credit = { amount: 0n, blind: 0n };

    /** Moves `amount` of `who`'s public balance into a new credit (SPEC.md §10.5). */
    async function shield(who: any, amount: bigint): Promise<Credit> {
      const blind = randomField();
      await tokenAt.methods.shield(amount, blind).send({ from: who, wait });
      return { amount, blind };
    }
    /** Credits the token delivered to `who` from `from`, oldest first. */
    async function creditsFrom(who: any, from: any): Promise<Credit[]> {
      const evs = await (wallet as any).getPrivateEvents(await eventMeta(rawToken, 'CreditReceived'), { contractAddress: token.address, scopes: [who] });
      return evs.filter((e: any) => big(e.event.from) === big(from)).map((e: any) => ({ amount: big(e.event.amount), blind: big(e.event.blind) }));
    }
    /**
     * The (payer, payee) pairs a transaction's confidential payments published in plaintext
     * (SPEC.md §10.5): amounts are hidden, parties are not.
     */
    const partiesTag = (await computeSiloedPrivateLogFirstField(token.address, new Fr(PARTIES_LOG_TAG))).toBigInt();
    async function partiesOf(sent: any): Promise<string[]> {
      // A mined send resolves to { receipt, ... }.
      const eff: any = await node.getTxEffect(sent.receipt.txHash);
      return eff.data.privateLogs
        .filter((l: any) => l.fields[0].toBigInt() === partiesTag)
        .map((l: any) => `${hex(l.fields[1].toBigInt())}->${hex(l.fields[2].toBigInt())}`);
    }
    const pair = (from: any, to: any) => `${hex(big(from))}->${hex(big(to))}`;
    /** Spends `who`'s credit into its public balance, so the test can see it (the amount becomes public). */
    async function cash(who: any, c: Credit) {
      await tokenAt.methods.unshield(who, c.amount, [c, empty], 0n).send({ from: who, wait });
    }
    /**
     * Deposits `amount` from `credit` into `account` (SPEC.md §10.3): the depositor authorizes the
     * Bridge's call to the token, which moves the amount into a credit the Bridge holds; the change
     * returns as a credit. Returns the change and the time the deposit took.
     */
    async function deposit(who: any, account: bigint, amount: bigint, credit: Credit) {
      const salt = randomField();
      const changeBlind = randomField();
      const nonce = randomField();
      const credits = [credit, empty];
      const blind = await M.depositBlind(h, account, big(who), big(who), salt);
      const action = tokenAt.methods.transfer(who, bridge.address, amount, credits, blind, changeBlind, nonce);
      const witness = await (wallet as any).createAuthWit(who, { caller: bridge.address, call: await action.getFunctionCall() });
      const [receipt, ms] = await timed(() =>
        bridgeAt.methods.deposit(account, amount, who, salt, credits, changeBlind, nonce).with({ authWitnesses: [witness] }).send({ from: who, wait }),
      );
      const parties = await partiesOf(receipt);
      assert(parties.length === 1 && parties[0] === pair(who, bridge.address), `deposit's public parties: ${parties}`);
      const credited = await creditId(h, bridge.address, amount, blind);
      return { change: { amount: credit.amount - amount, blind: changeBlind } as Credit, credit: credited, salt, ms: Math.round(ms) };
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
    const [, shieldMs] = await timed(() => shield(alice, 1_000_000n));
    const aliceCredit = (await creditsFrom(alice, alice)).find((c) => c.amount === 1_000_000n)!;
    const bobCredit = await shield(bob, 2_000_777n);
    const dA = await deposit(alice, A, 1_000_000n, aliceCredit);
    const dB = await deposit(bob, B, 2_000_000n, bobCredit);
    const dR = await deposit(bob, 42n, 777n, dB.change); // no account 42: refund; spends dB's change
    assert(dB.change.amount === 777n, 'change credit');
    const vault0 = await balance(bridge.address);
    assert(vault0 === 0n, 'a deposit reached the vault before custody');
    log(`shield ${Math.round(shieldMs)} ms; deposits held by the Bridge in ${dA.ms}, ${dB.ms}, ${dR.ms} ms; the vault holds ${vault0}; each deposit published its parties, not its amount`);
    report.shieldMs = Math.round(shieldMs);
    report.depositMs = [dA.ms, dB.ms, dR.ms];

    // 2. The operator reads its delivered keys and deposit openings from the chain.
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

    /** The pending deposits' openings the operator holds, by credit id, and by amount commitment. */
    const openings = new Map<bigint, any>();
    const byCommitment = new Map<bigint, M.DepositOpening>();
    async function readOpenings() {
      const evs = await (wallet as any).getPrivateEvents(await eventMeta(raw, 'DepositDelivered'), { contractAddress: bridge.address, scopes: [operator] });
      for (const { event: e } of evs) {
        const o = { account_index: big(e.account_index), amount: big(e.amount), refund_to: big(e.refund_to), depositor: big(e.depositor), salt: big(e.salt) };
        const blind = await M.depositBlind(h, o.account_index, o.refund_to, o.depositor, o.salt);
        openings.set(await creditId(h, bridge.address, o.amount, blind), o);
        byCommitment.set(await M.depositCommitment(h, o.amount, o.salt), { amount: o.amount, salt: o.salt });
      }
    }
    await readOpenings();
    const pending = (await allPublicEvents(node, await eventMeta(raw, 'DepositPending'), bridge.address)) as any[];
    assert(pending.length === 3 && pending.every((p) => openings.has(big(p.credit))), 'the operator cannot open every pending deposit');
    log(`operator received ${openings.size} deposit openings by constrained delivery; the public sees ${pending.length} pending deposits, no amounts`);

    const noDeposit = { account_index: 0n, amount: 0n, refund_to: 0n, depositor: 0n, salt: 0n };
    const noPayout = { batch: 0n, index: 0, recipient: 0n, amount: 0n, salt: 0n, path: Array(M.WD_HEIGHT).fill(0n), blind: 0n };
    /**
     * The operator's custody transaction (SPEC.md §10.3): sweeps `credits`, pays `payouts`. The only
     * public amount is the vault's net change, which the token's public-transfer event shows.
     */
    async function custody(label: string, credits: bigint[], payouts: any[]) {
      const ds = credits.map((c) => openings.get(c)!);
      const pad = <T,>(xs: T[], z: T) => [...xs, ...Array(4 - xs.length).fill(z)];
      const before = await balance(bridge.address);
      const [receipt, ms] = await timed(() =>
        asOf(operator).methods.custody(pad(ds, noDeposit), ds.length, pad(payouts, noPayout), payouts.length).send({ from: operator, wait }),
      );
      const after = await balance(bridge.address);
      // Each payout names the Bridge and its recipient in public; no amount appears.
      const parties = await partiesOf(receipt);
      const want = payouts.map((p) => pair(bridge.address, p.recipient));
      assert(JSON.stringify(parties) === JSON.stringify(want), `custody's public parties: ${parties}`);
      const net = { net_in: after > before ? after - before : 0n, net_out: before > after ? before - after : 0n };
      log(`${label}: custody swept ${ds.length} deposits and paid ${payouts.length} records in ${Math.round(ms)} ms; public net in ${net.net_in}, out ${net.net_out}`);
      (report.custody ??= []).push({ label, deposits: ds.length, payouts: payouts.length, netIn: net.net_in, netOut: net.net_out, ms: Math.round(ms) });
      return net;
    }
    const pq = await eventMeta(raw, 'PriorityRequested');
    /** Priority requests queued after the first `from`, with the operator's deposit openings. */
    async function queuedFrom(from: number) {
      const out: M.Request[] = [];
      for (const ev of ((await allPublicEvents(node, pq, bridge.address)) as any[]).slice(from)) {
        const r: M.Request = { kind: big(ev.kind), a: big(ev.a), b: big(ev.b), c: big(ev.c), sender: big(ev.sender), time: big(ev.time) };
        assert((await M.requestEntry(h, r)) === big(ev.entry), `request ${ev.index} does not match its entry`);
        if (r.kind === M.KIND.DEPOSIT) r.deposit = byCommitment.get(r.b);
        out.push(r);
      }
      return out;
    }

    // Custody sweeps the three deposits into the vault and queues them; only the sum is public.
    const c1 = await custody('custody 1', [dA.credit, dB.credit, dR.credit], []);
    assert(big(c1.net_in) === 3_000_777n && (await balance(bridge.address)) === 3_000_777n, 'custody 1 net');
    const requests = await queuedFrom(0);
    const deposits = requests.filter((r) => r.kind === M.KIND.DEPOSIT);
    assert(deposits.length === 3 && deposits.every((r) => r.deposit && r.b !== r.deposit.amount), 'queued deposits carry commitments, not amounts');
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

    // Bob's refund record is in the DA, salted with his deposit's secret salt.
    const refund = requests[4];
    assert(refund.a === 42n && refund.c === big(bob), 'refund request');
    const refundRecord = await M.withdrawalRecord(h, refund.c!, 777n, refund.deposit!.salt, 1n, 0);
    const logs1 = await daLogs(node, bridge.address);
    const rp = await withdrawalPath(h, logs1[0].payload, 1n, refundRecord);

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
    // Custody pays Bob's refund as a credit delivered to him; the vault's change is public, the
    // payment's amount is not.
    const vaultBefore = await balance(bridge.address);
    const refundBlind = randomField();
    await custody('custody 2', [], [{ batch: 1n, index: rp.index, recipient: bob, amount: 777n, salt: refund.deposit!.salt, path: rp.path, blind: refundBlind }]);
    assert((await balance(bridge.address)) === vaultBefore - 777n, 'custody 2 net');
    const bobPayouts = await creditsFrom(bob, bridge.address);
    assert(bobPayouts.length === 1 && bobPayouts[0].amount === 777n && bobPayouts[0].blind === refundBlind, 'bob did not receive his refund credit');
    let bobBefore = await balance(bob);
    await cash(bob, bobPayouts[0]);
    assert((await balance(bob)) === bobBefore + 777n, 'refund credit not spendable');
    log('bob received his 777 refund as a credit by constrained delivery, and spent it');

    // Custody does not pay Bob's withdrawal; after t_payout he claims it from the vault with the
    // DA and his key alone, and its amount becomes public.
    const wdSalt = await h([M.DS.WDSALT, users.bob.keys.kEnc, 2n, 0n]);
    const wdRecord = await M.withdrawalRecord(h, big(bob), 1000n, wdSalt, 2n, 0);
    const logs2 = await daLogs(node, bridge.address);
    const wp = await withdrawalPath(h, logs2[1].payload, 2n, wdRecord);
    await (node as any).warpL2TimeAtLeastBy(Number(T_PAYOUT + 10n));
    bobBefore = await balance(bob);
    await asOf(bob).methods.claim_withdrawal(2n, wp.index, bob, 1000n, wdSalt, wp.path).send({ from: bob, wait });
    assert((await balance(bob)) === bobBefore + 1000n, 'withdrawal not paid');
    log('after t_payout bob claimed his 1000 withdrawal from the vault using the DA and his key alone');

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
    // Bob also rotates his keys through the Bridge (SPEC.md §7.3): a new master key and encryption
    // key, the latter delivered to the operator, as at registration. From batch 3 on, his old keys
    // neither sign for his account nor open it.
    const bob2 = await keysFromSeed(h, BOB_SEED2);
    const bob2Enc = await M.encCommitment(h, bob2.kEnc);
    await asOf(bob).methods.rekey(B, await M.masterAuthOf(h, bob2.pk!.x, bob2.pk!.y), bob2Enc, bob2.kEnc).send({ from: bob, wait });
    for (const ev of await (wallet as any).getPrivateEvents(await eventMeta(raw, 'KeyDelivered'), { contractAddress: bridge.address, scopes: [operator] })) {
      engine.keyring.set(big(ev.event.enc_commitment), big(ev.event.k_enc));
    }
    assert(engine.keyring.get(bob2Enc) === bob2.kEnc, "the operator did not receive bob's new key");
    const forced = await queuedFrom(requests.length);
    requests.push(...forced);
    assert(forced.map((r) => r.kind).join() === [M.KIND.FORCED_WITHDRAW, M.KIND.REKEY].join(), 'queued requests');
    log(`bob queued a forced withdrawal and a rekey (fee ${REQUEST_FEE} each to the operator); his new encryption key reached the operator by constrained delivery`);

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
    // The forced withdrawal's record is the batch's first. Alice deposits again, and one custody
    // transaction sweeps her deposit and pays Bob's forced withdrawal: the public sees their net.
    const forcedAmount = bobCollateral - engine.accts.get(B)!.priv.collateral;
    assert(forcedAmount > 0n, 'forced withdrawal moved nothing');
    const fwSalt = await h([M.DS.WDSALT, users.bob.keys.kEnc, 3n, 0n]);
    const fwRecord = await M.withdrawalRecord(h, big(bob), forcedAmount, fwSalt, 3n, 0);
    const fp = await withdrawalPath(h, (await daLogs(node, bridge.address))[2].payload, 3n, fwRecord);
    const dX = await deposit(alice, A, 5_000n, await shield(alice, 5_000n));
    await readOpenings();
    const fwBlind = randomField();
    const vaultBefore3 = await balance(bridge.address);
    const c3 = await custody('custody 3', [dX.credit], [{ batch: 3n, index: fp.index, recipient: bob, amount: forcedAmount, salt: fwSalt, path: fp.path, blind: fwBlind }]);
    assert(big(c3.net_out) === forcedAmount - 5_000n && (await balance(bridge.address)) === vaultBefore3 + 5_000n - forcedAmount, 'custody 3 net');
    const fwCredit = (await creditsFrom(bob, bridge.address)).find((c) => c.blind === fwBlind);
    assert(fwCredit?.amount === forcedAmount, 'bob did not receive his forced withdrawal as a credit');
    bobBefore = await balance(bob);
    await cash(bob, fwCredit);
    assert((await balance(bob)) === bobBefore + forcedAmount, 'forced withdrawal credit not spendable');
    log(`bob's forced withdrawal of ${forcedAmount} was processed and paid by custody as a credit`);
    report.forcedWithdrawal = forcedAmount;
    const queuedX = await queuedFrom(requests.length);
    assert(queuedX.length === 1 && queuedX[0].kind === M.KIND.DEPOSIT, 'custody 3 queued alice\'s deposit');
    const pendingIndex = BigInt(requests.length);

    // 4. The operator stops: Alice's swept deposit stays queued, and her next deposit is never swept.
    const dY = await deposit(alice, A, 3_000n, await shield(alice, 3_000n));
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
    const oldKeysOpen = await exitFromDa(h, node, bridge.address, BOB_SEED, frozen).then(
      () => true,
      () => false,
    );
    assert(!oldKeysOpen, "bob's keys from before his rekey still open his account");
    for (const [name, seed, addr] of [['alice', ALICE_SEED, alice], ['bob', BOB_SEED2, bob]] as const) {
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
    // Alice's queued deposit is refunded from the vault (its amount becomes public); her unswept one
    // returns to her as a credit, which anyone holding the opening may trigger in desert mode.
    const xTime = big(((await sim('get_priority', [pendingIndex])) as any[])[2]);
    await asOf(alice).methods.desert_refund(pendingIndex, A, 5_000n, dX.salt, alice, alice, xTime).send({ from: alice, wait });
    await readOpenings();
    const yOpening = openings.get(dY.credit);
    assert(!!yOpening, 'the operator holds the unswept deposit\'s opening');
    const yBlind = randomField();
    await asOf(bob).methods.reclaim_deposit(yOpening, yBlind).send({ from: bob, wait });
    const yCredit = (await creditsFrom(alice, bridge.address)).find((c) => c.blind === yBlind);
    assert(yCredit?.amount === 3_000n, 'alice did not receive her unswept deposit back as a credit');
    log('desert mode: alice\'s queued deposit refunded from the vault; her unswept deposit returned to her as a credit');
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
