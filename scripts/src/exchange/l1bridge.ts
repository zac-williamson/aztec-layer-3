// The collateral token's L1 bridge end to end (SPEC.md §10.6), on an in-process Aztec 6.0.0 local
// network with its anvil L1, real client proofs and node proof verification:
//
//  1. On L1, deploy a test ERC-20 and Aztec's standard TokenPortal. On L2, deploy the bridge, then
//     the confidential token with the bridge as its minter, and bind the two; the portal is then
//     initialized with the L2 bridge.
//  2. Alice deposits 1,000 from L1 to her L2 public balance and claims it.
//  3. She deposits 600 without naming a recipient, and claims it on L2 as a credit of her own.
//  4. She exits 400 of her public balance and 250 of her credit to her L1 address; each exit's
//     message is proved into the Outbox and the portal releases the ERC-20. Her credit's 350 of
//     change stays on L2.
//
// Writes scripts/out/l1bridge.json.
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { getInitialTestAccountsData } from '@aztec-labs/accounts/testing';
import { TEST_FEE_PADDING, setupLocalNetwork } from '@aztec-labs/aztec/testing';
import { EthAddress } from '@aztec-labs/aztec.js/addresses';
import { Contract } from '@aztec-labs/aztec.js/contracts';
import { Fr } from '@aztec-labs/aztec.js/fields';
import { isL1ToL2MessageReady } from '@aztec-labs/aztec.js/messaging';
import { TxStatus } from '@aztec-labs/aztec.js/tx';
import { OutboxContract } from '@aztec-labs/ethereum/contracts';
import { TestERC20Abi } from '@aztec-foundation/l1-artifacts/TestERC20Abi';
import { TestERC20Bytecode } from '@aztec-foundation/l1-artifacts/TestERC20Bytecode';
import { TokenPortalAbi } from '@aztec-foundation/l1-artifacts/TokenPortalAbi';
import { TokenPortalBytecode } from '@aztec-foundation/l1-artifacts/TokenPortalBytecode';
import { computeL2ToL1MembershipWitness } from '@aztec-labs/stdlib/messaging';
import { computeL2ToL1MessageHash, computeSecretHash } from '@aztec-labs/stdlib/hash';
import { EmbeddedWallet } from '@aztec-labs/wallets/embedded';
import { type Hex, createPublicClient, createWalletClient, decodeEventLog, encodeFunctionData, http, parseAbi, toHex, zeroAddress } from 'viem';
import { mnemonicToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { OUT, readJson, timed, writeJson } from '../lib.ts';
import { assert } from '../pipeline.ts';
import { artifact, big, eventMeta, rawArtifact } from './chain.ts';

const log = (m: string) => console.log(`[l1bridge] ${m}`);
/** Anvil's default mnemonic; account 7 is not used by the local network's own L1 actors. */
const ANVIL_MNEMONIC = 'test test test test test test test test test test test junk';

/** Aztec's Hash.sha256ToField: a zero byte, then the first 31 bytes of the SHA-256. */
const sha256ToField = (data: Hex) => BigInt(`0x${createHash('sha256').update(Buffer.from(data.slice(2), 'hex')).digest().subarray(0, 31).toString('hex')}`);
const withdrawAbi = parseAbi(['function withdraw(address,uint256,address)']);

async function main() {
  const manifest = readJson(join(OUT, 'manifest.json'));
  const report: Record<string, any> = { startedAt: new Date().toISOString(), aztecVersion: manifest.aztecVersion };
  const accounts = await getInitialTestAccountsData();
  const platform = `${process.arch}-${process.platform === 'darwin' ? 'macos' : 'linux'}`;
  const bbConfig = {
    bbWorkingDirectory: join(OUT, 'bb-work'),
    bbBinaryPath: join(homedir(), '.aztec', 'versions', manifest.aztecVersion, 'node_modules', '@aztec-foundation', 'bb.js', 'build', platform, 'bb'),
  };
  log('starting in-process local network (realProofs: true) with its anvil L1');
  const network = await setupLocalNetwork({
    fundedAddresses: accounts.map((a: any) => a.address),
    config: { realProofs: true, p2pEnabled: false, ...bbConfig } as any,
  });
  try {
    const node = network.node;
    const info: any = await node.getNodeInfo();
    const l1Addresses: any = info.l1ContractAddresses;
    const wallet = await EmbeddedWallet.create(node as any, {
      ephemeral: true,
      pxe: { proverEnabled: true, syncChainTip: 'checkpointed', ...bbConfig } as any,
    });
    wallet.setMinFeePadding(TEST_FEE_PADDING);
    const [deployer, alice] = await Promise.all(
      accounts.slice(0, 2).map(async (d: any) => (await wallet.createSchnorrInitializerlessAccount(d.secret, d.salt, d.signingKey)).address),
    );
    const wait = { waitForStatus: TxStatus.CHECKPOINTED, timeout: 1800, interval: 0.5 };

    // L1 clients.
    const chain = { ...foundry, id: network.l1ChainId };
    const l1Account = mnemonicToAccount(ANVIL_MNEMONIC, { addressIndex: 7 });
    const l1 = createPublicClient({ chain, transport: http(network.l1RpcUrl) });
    const l1w = createWalletClient({ account: l1Account, chain, transport: http(network.l1RpcUrl) });
    const l1Tx = async (hash: Hex) => {
      const r = await l1.waitForTransactionReceipt({ hash });
      assert(r.status === 'success', `L1 transaction ${hash} reverted`);
      return r;
    };
    const write = async (address: Hex, abi: any, functionName: string, args: unknown[]) =>
      l1Tx(await l1w.writeContract({ address, abi, functionName, args } as any));
    const erc20Balance = async (who: Hex) => (await l1.readContract({ address: erc20, abi: TestERC20Abi, functionName: 'balanceOf', args: [who] })) as bigint;

    // 1. Deploy: the ERC-20 and the portal on L1, then the bridge and the token on L2.
    const erc20 = (await l1Tx(await l1w.deployContract({ abi: TestERC20Abi, bytecode: TestERC20Bytecode, args: ['Test USD', 'TUSD', l1Account.address] })))
      .contractAddress! as Hex;
    const portal = (await l1Tx(await l1w.deployContract({ abi: TokenPortalAbi, bytecode: TokenPortalBytecode, args: [] }))).contractAddress! as Hex;
    const bridgeArtifact = artifact('ctbridge-ConfidentialTokenBridge');
    const tokenArtifact = artifact('ctoken-ConfidentialToken');
    const bridge = (await Contract.deploy(wallet as any, bridgeArtifact, [EthAddress.fromString(portal)]).send({ from: deployer, wait } as any) as any).contract;
    const token = (await Contract.deploy(wallet as any, tokenArtifact, [bridge.address]).send({ from: deployer, wait } as any) as any).contract;
    await bridge.methods.set_token(token.address).send({ from: deployer, wait });
    await write(portal, TokenPortalAbi, 'initialize', [l1Addresses.registryAddress.toString(), erc20, bridge.address.toString()]);
    await write(erc20, TestERC20Abi, 'addMinter', [l1Account.address]);
    await write(erc20, TestERC20Abi, 'mint', [l1Account.address, 10_000n]);
    log(`L1: ERC-20 ${erc20}, portal ${portal}; L2: bridge ${bridge.address}, token ${token.address}`);
    report.l1 = { erc20, portal };
    report.l2 = { bridge: bridge.address.toString(), token: token.address.toString() };

    const tokenAt: any = await Contract.at(token.address, tokenArtifact, wallet as any);
    const bridgeAt: any = await Contract.at(bridge.address, bridgeArtifact, wallet as any);
    const publicBalance = async (who: any) => big((await tokenAt.methods.balance_of_public(who).simulate({ from: alice })).result);

    /** Deposits through the portal; returns the claim's secret, message hash and leaf index. */
    async function deposit(kind: 'public' | 'private', amount: bigint) {
      const secret = Fr.random();
      const secretHash = await computeSecretHash(secret);
      await write(erc20, TestERC20Abi, 'approve', [portal, amount]);
      const receipt =
        kind === 'public'
          ? await write(portal, TokenPortalAbi, 'depositToAztecPublic', [alice.toString() as Hex, amount, secretHash.toString() as Hex])
          : await write(portal, TokenPortalAbi, 'depositToAztecPrivate', [amount, secretHash.toString() as Hex]);
      const ev: any = receipt.logs
        .filter((l) => l.address.toLowerCase() === portal.toLowerCase())
        .map((l) => decodeEventLog({ abi: TokenPortalAbi, data: l.data, topics: l.topics }))
        .find((d: any) => d.eventName.startsWith('DepositToAztec'));
      assert(!!ev, 'portal emitted no deposit event');
      return { secret, key: Fr.fromString(ev.args.key), index: BigInt(ev.args.index) };
    }
    /** L2 blocks pick up L1-to-L2 messages; on the automining local network a transaction makes a block. */
    async function untilReady(key: Fr) {
      for (let i = 0; i < 20; i++) {
        if (await isL1ToL2MessageReady(node as any, key, 'checkpointed')) return i;
        await tokenAt.methods.approve(deployer, 0n).send({ from: deployer, wait });
      }
      throw new Error('the L1-to-L2 message never reached a checkpointed block');
    }

    // 2. A public deposit, claimed to Alice's public balance.
    const d1 = await deposit('public', 1000n);
    const nudges1 = await untilReady(d1.key);
    const [, claimMs] = await timed(() => bridgeAt.methods.claim_public(alice, 1000n, d1.secret, d1.index).send({ from: alice, wait }));
    assert((await publicBalance(alice)) === 1000n, 'public claim');
    log(`alice deposited 1000 on L1 and claimed it to her public balance (${nudges1} blocks to sync the message, claim ${Math.round(claimMs)} ms)`);

    // 3. A deposit without a recipient, claimed as Alice's credit.
    const d2 = await deposit('private', 600n);
    await untilReady(d2.key);
    const blind = Fr.random().toBigInt();
    const [, claimCMs] = await timed(() => bridgeAt.methods.claim_confidential(alice, 600n, blind, d2.secret, d2.index).send({ from: alice, wait }));
    const credits = await (wallet as any).getPrivateEvents(await eventMeta(rawArtifact('ctoken-ConfidentialToken'), 'CreditReceived'), {
      contractAddress: token.address,
      scopes: [alice],
    });
    const minted = credits.map((e: any) => e.event).find((e: any) => big(e.blind) === blind);
    assert(minted && big(minted.amount) === 600n && big(minted.from) === big(bridge.address), 'alice did not receive her 600 credit');
    log(`alice deposited 600 on L1 and claimed it as a credit of her own (claim ${Math.round(claimCMs)} ms)`);

    // 4. Exits. Each burns on L2 and messages the portal; once the epoch's Outbox root covers the
    // message, the portal releases the ERC-20 to the recipient.
    const outbox = new OutboxContract(l1 as any, l1Addresses.outboxAddress.toString());
    const recipient = l1Account.address;
    async function release(label: string, amount: bigint, sent: any) {
      const content = new Fr(sha256ToField(encodeFunctionData({ abi: withdrawAbi, functionName: 'withdraw', args: [recipient, amount, zeroAddress] })));
      const message = await computeL2ToL1MessageHash({
        l2Sender: bridge.address,
        l1Recipient: EthAddress.fromString(portal),
        content,
        rollupVersion: new Fr(info.rollupVersion),
        chainId: new Fr(info.l1ChainId),
      });
      let witness: any;
      for (let i = 0; i < 20 && !witness; i++) {
        witness = await computeL2ToL1MembershipWitness(node as any, outbox as any, message, sent.receipt.txHash);
        if (!witness) await tokenAt.methods.approve(deployer, 0n).send({ from: deployer, wait });
      }
      assert(!!witness, `${label}: the exit never reached an Outbox root`);
      const before = await erc20Balance(recipient);
      await write(portal, TokenPortalAbi, 'withdraw', [
        recipient,
        amount,
        false,
        BigInt(witness.epochNumber),
        BigInt(witness.numCheckpointsInEpoch),
        witness.leafIndex,
        witness.siblingPath.toBufferArray().map((b: Buffer) => toHex(b)),
      ]);
      assert((await erc20Balance(recipient)) === before + amount, `${label}: the portal did not release ${amount}`);
      log(`${label}: the portal released ${amount} on L1 (epoch ${witness.epochNumber}, leaf ${witness.leafIndex})`);
    }
    const exit1 = await bridgeAt.methods.exit_public(EthAddress.fromString(recipient), 400n, EthAddress.ZERO).send({ from: alice, wait });
    assert((await publicBalance(alice)) === 600n, 'public exit burn');
    await release('public exit', 400n, exit1);
    const changeBlind = Fr.random().toBigInt();
    const exit2 = await bridgeAt.methods
      .exit_confidential(EthAddress.fromString(recipient), 250n, [{ amount: 600n, blind }, { amount: 0n, blind: 0n }], changeBlind, EthAddress.ZERO)
      .send({ from: alice, wait });
    await release('confidential exit', 250n, exit2);
    // The credit's change stays on L2: Alice spends it to show she holds it.
    await tokenAt.methods.unshield(alice, 350n, [{ amount: 350n, blind: changeBlind }, { amount: 0n, blind: 0n }], 0n).send({ from: alice, wait });
    assert((await publicBalance(alice)) === 950n, 'credit change');
    const portalHolds = await erc20Balance(portal);
    assert(portalHolds === 950n, `portal holds ${portalHolds}`);
    log(`the portal holds 950, exactly the token supply on L2 (alice's 950 public)`);
    report.portalHolds = portalHolds;
    report.status = 'passed';
  } catch (e) {
    report.status = 'failed';
    report.error = String((e as any)?.stack ?? e).slice(0, 4000);
    throw e;
  } finally {
    report.finishedAt = new Date().toISOString();
    writeJson(join(OUT, 'l1bridge.json'), report);
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
