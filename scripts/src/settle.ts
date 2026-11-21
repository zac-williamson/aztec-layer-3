// P0 exit test (SPEC.md §15): settle a fully proved batch on an in-process Aztec 6.0.0 local
// network, with client-side proving on (PXE proverEnabled) and transaction-proof verification on
// (node realProofs). Records measurement M5 and two negative checks, and writes
// scripts/out/settlement.json.
//
// Caveat: the local network settles epochs synthetically (no rollup proofs), so "proven" receipt
// status here does not mean an epoch proof was verified. What is real: the settlement transaction's
// Chonk proof, which includes the in-circuit verification of the root proof, and the node's check
// of that proof.
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { getInitialTestAccountsData } from '@aztec-labs/accounts/testing';
import { TEST_FEE_PADDING, setupLocalNetwork } from '@aztec-labs/aztec/testing';
import { loadContractArtifact } from '@aztec-labs/aztec.js/abi';
import { Contract } from '@aztec-labs/aztec.js/contracts';
import { TxStatus } from '@aztec-labs/aztec.js/tx';
import { EmbeddedWallet } from '@aztec-labs/wallets/embedded';
import { OUT, ROOT, SHAPE, hex, randomField, readJson, timed, writeJson } from './lib.ts';
import { assert, newApi, proveBatch } from './pipeline.ts';

const log = (m: string) => console.log(`[settle] ${m}`);

async function main() {
  const manifest = readJson(join(OUT, 'manifest.json'));
  const report: Record<string, unknown> = { startedAt: new Date().toISOString(), aztecVersion: manifest.aztecVersion };

  const accounts = await getInitialTestAccountsData();
  // realProofs makes the node verify transaction proofs natively; that verifier needs a working
  // directory and the bb binary, which the local-network defaults leave unset.
  const bbConfig = {
    bbWorkingDirectory: join(OUT, 'bb-work'),
    bbBinaryPath: join(homedir(), '.aztec', 'versions', manifest.aztecVersion, 'node_modules', '@aztec-foundation', 'bb.js', 'build', `${process.arch}-${process.platform === 'darwin' ? 'macos' : 'linux'}`, 'bb'),
  };
  log('starting in-process local network (realProofs: true)');
  const [network, startMs] = await timed(() =>
    setupLocalNetwork({
      fundedAddresses: accounts.map((a: any) => a.address),
      config: { realProofs: true, p2pEnabled: false, ...bbConfig } as any,
    }),
  );
  report.networkStartMs = Math.round(startMs);
  try {
    const node = network.node;
    const info = await node.getNodeInfo();
    report.nodeVersion = info.nodeVersion;
    report.realProofs = (info as any).realProofs;
    log(`node ${info.nodeVersion}, realProofs=${(info as any).realProofs}`);

    const wallet = await EmbeddedWallet.create(node as any, {
      ephemeral: true,
      pxe: { proverEnabled: true, syncChainTip: 'checkpointed', ...bbConfig } as any,
    });
    wallet.setMinFeePadding(TEST_FEE_PADDING);
    const d = accounts[0];
    const operator = (await wallet.createSchnorrInitializerlessAccount(d.secret, d.salt, d.signingKey)).address;
    const wait = { waitForStatus: TxStatus.CHECKPOINTED, timeout: 1800, interval: 0.5 };

    const artifact = loadContractArtifact(
      JSON.parse(readFileSync(join(ROOT, 'contracts', 'target', 'l3x_bridge-L3XBridge.json'), 'utf8')),
    );
    log('deploying L3XBridge (proved)');
    const [dep, deployMs] = await timed(() =>
      Contract.deploy(wallet as any, artifact, [operator, BigInt(manifest.hashes.ROOT_VK_HASH), BigInt(manifest.configHash)]).send({
        from: operator,
        wait,
      } as any),
    );
    const bridge = (dep as any).contract;
    report.bridge = bridge.address.toString();
    report.deployMs = Math.round(deployMs);
    const sim = async (method: string, args: unknown[] = []) =>
      (await bridge.methods[method](...args).simulate({ from: operator })).result;

    log('submitting two priority requests (proved)');
    const requestMs: number[] = [];
    for (const payload of [11n, 22n]) {
      const [, t] = await timed(() => bridge.methods.submit_request(payload).send({ from: operator, wait }));
      requestMs.push(Math.round(t));
    }
    report.submitRequestMs = requestMs;

    const tip0 = (await sim('get_tip')) as any[];
    const count = BigInt(tip0[5]);
    assert(count === 2n, `expected 2 queued requests, found ${count}`);
    const entries: bigint[] = [];
    for (let i = 0n; i < count; i++) entries.push(BigInt(((await sim('get_priority', [i])) as any[])[1]));
    const headStart = BigInt(((await sim('get_priority', [0n])) as any[])[0]);

    const latest = await node.getBlockNumber();
    const block: any = await node.getBlock(latest as any);
    const l2Time = BigInt(block.header.globalVariables.timestamp);
    log(`L2 block ${latest} at t=${l2Time}; proving batch 1 over ${entries.length} on-chain requests`);

    const api = await newApi();
    const batch = await proveBatch(
      api,
      {
        prevAccountsRoot: 0n,
        prevLastTime: 0n,
        batchNumber: 1n,
        minTime: l2Time,
        maxTime: l2Time,
        priorityStart: 0n,
        priorityHeadStart: headStart,
        priorityEntries: entries,
        daPayload: Array.from({ length: SHAPE.DA_LEN }, () => randomField()),
        configHash: BigInt(manifest.configHash),
      },
      log,
    );
    report.batch = { ms: batch.ms, sizes: batch.sizes, headerHash: hex(batch.headerHash) };

    const args = [batch.header, batch.rootProof, batch.rootVk, batch.daPayload];
    log('profiling settle (gates per circuit)');
    try {
      const prof: any = await bridge.methods.settle(...args).profile({ from: operator, profileMode: 'gates' });
      report.settleProfile = (prof.executionSteps ?? []).map((s: any) => ({ fn: s.functionName, gates: s.gateCount }));
    } catch (e) {
      report.settleProfile = `profile failed: ${String(e).slice(0, 300)}`;
    }

    log('settling batch 1 (client-proved transaction)');
    const [settled, settleMs] = await timed(() => bridge.methods.settle(...args).send({ from: operator, wait }));
    const receipt = (settled as any).receipt;
    report.settle = {
      ms: Math.round(settleMs),
      txHash: receipt.txHash.toString(),
      status: receipt.status,
      executionResult: receipt.executionResult,
      blockNumber: receipt.blockNumber,
      transactionFee: receipt.transactionFee?.toString(),
    };
    const tip1 = (await sim('get_tip')) as any[];
    assert(BigInt(tip1[0]) === batch.header[1], 'on-chain state root != header.new_state_root');
    assert(BigInt(tip1[2]) === 1n, 'batch number did not advance');
    assert(BigInt(tip1[4]) === count, 'priority cursor did not advance');
    log(`settled: state root ${hex(BigInt(tip1[0]))}, batch ${tip1[2]}, cursor ${tip1[4]}`);

    // Negative 1: replay the same settlement. The public phase must reject the stale root.
    const negatives: Record<string, string> = {};
    try {
      await bridge.methods.settle(...args).send({ from: operator, wait });
      negatives.replay = 'ACCEPTED (bug)';
    } catch (e) {
      negatives.replay = `rejected: ${String(e).split('\n')[0].slice(0, 200)}`;
    }
    // Negative 2: a batch-2 header that passes every public check in _apply (it chains from the
    // new tip, consumes nothing, respects the time bounds, and its DA hash matches the payload),
    // paired with batch 1's valid root proof. Only the in-circuit proof verification in the
    // private phase can reject it; if this is accepted, the header is not bound to the proof.
    try {
      const tip = (await sim('get_tip')) as any[];
      const cursor = BigInt(tip[4]);
      const headAtCursor = BigInt(((await sim('get_priority', [cursor])) as any[])[0]);
      const nowBlock: any = await node.getBlock((await node.getBlockNumber()) as any);
      const nowTime = BigInt(nowBlock.header.globalVariables.timestamp);
      const forged = [...batch.header];
      forged[0] = BigInt(tip[0]); // prev_state_root = current tip
      forged[1] = randomField(); // new_state_root: anything the forger wants
      forged[2] = randomField(); // new_accounts_root
      forged[3] = BigInt(tip[2]) + 1n; // batch_number
      forged[4] = BigInt(tip[3]); // min_time = last_time
      forged[5] = nowTime; // max_time
      forged[6] = cursor; // priority_start
      forged[7] = cursor; // priority_end: consume nothing
      forged[8] = headAtCursor;
      forged[9] = headAtCursor;
      // forged[13] (da_hash) already matches batch.daPayload; forged[15] is the stored config hash.
      await bridge.methods.settle(forged, batch.rootProof, batch.rootVk, batch.daPayload).send({ from: operator, wait });
      negatives.forgedHeader = 'ACCEPTED (bug)';
    } catch (e) {
      negatives.forgedHeader = `rejected: ${String(e).split('\n')[0].slice(0, 200)}`;
    }
    report.negatives = negatives;
    for (const [k, v] of Object.entries(negatives)) log(`${k}: ${v}`);
    assert(Object.values(negatives).every((v) => v.startsWith('rejected')), 'a negative check was accepted');
    report.status = 'passed';
    await api.destroy();
  } catch (e) {
    report.status = 'failed';
    report.error = String((e as any)?.stack ?? e).slice(0, 4000);
    throw e;
  } finally {
    report.finishedAt = new Date().toISOString();
    writeJson(join(OUT, 'settlement.json'), report);
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
