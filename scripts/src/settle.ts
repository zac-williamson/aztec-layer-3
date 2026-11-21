// P0 exit test (SPEC.md §15) and measurement M5: settle fully proved batches on an in-process
// Aztec 6.0.0 local network, with client-side proving on (PXE proverEnabled) and transaction-proof
// verification on (node realProofs). Writes scripts/out/settlement.json.
//
//   Batch 1: root(merge(tube, x), x). A P-segment of 10 client proofs and two X-segments that
//            consume the two queued priority requests and publish 40 DA fields.
//   Negatives: replaying batch 1, and a forged batch-2 header paired with batch 1's proof.
//   Batch 2 (M5): root(x, padding), publishing the largest DA payload this network admits in one
//            transaction. Aztec caps a transaction's DA gas at a share of one block's blob space
//            (stdlib computeNetworkTxGasLimits), which is below the 4,096-field public-log cap.
//
// Caveat: the local network settles epochs synthetically (no rollup proofs), so "proven" receipt
// status here does not mean an epoch proof was verified. What is real: each settlement
// transaction's Chonk proof, which includes the in-circuit verification of the root proof, and the
// node's check of that proof.
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
import { type ProvedBatch, Prover, assert, batchStart, newApi, proveBatch } from './pipeline.ts';

const log = (m: string) => console.log(`[settle] ${m}`);
const rand = (n: number) => Array.from({ length: n }, () => randomField());
const DA_LOG_TAG = 0x6c33782e64612e7631n;

function settleArgs(b: ProvedBatch, header = b.header) {
  const da = [...b.daPayload, ...Array<bigint>(SHAPE.DA_MAX - b.daPayload.length).fill(0n)];
  return [header, b.rootProof, b.rootVk, da, b.daPayload.length];
}

async function main() {
  const manifest = readJson(join(OUT, 'manifest.json'));
  const report: Record<string, any> = { startedAt: new Date().toISOString(), aztecVersion: manifest.aztecVersion };

  const accounts = await getInitialTestAccountsData();
  // realProofs makes the node verify transaction proofs natively; that verifier needs a working
  // directory and the bb binary, which the local-network defaults leave unset.
  const platform = `${process.arch}-${process.platform === 'darwin' ? 'macos' : 'linux'}`;
  const bbConfig = {
    bbWorkingDirectory: join(OUT, 'bb-work'),
    bbBinaryPath: join(homedir(), '.aztec', 'versions', manifest.aztecVersion, 'node_modules', '@aztec-foundation', 'bb.js', 'build', platform, 'bb'),
  };
  log('starting in-process local network (realProofs: true)');
  const [network, startMs] = await timed(() =>
    setupLocalNetwork({
      fundedAddresses: accounts.map((a: any) => a.address),
      config: { realProofs: true, p2pEnabled: false, ...bbConfig } as any,
    }),
  );
  report.networkStartMs = Math.round(startMs);
  const api = await newApi();
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
    const l2Time = async () => {
      const block: any = await node.getBlock((await node.getBlockNumber()) as any);
      return BigInt(block.header.globalVariables.timestamp);
    };

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

    const prover = await Prover.create(api, manifest);

    /** Settles a proved batch: gate profile, simulated gas, then the proved transaction. */
    async function settle(name: string, batch: ProvedBatch) {
      const args = settleArgs(batch);
      const r: Record<string, any> = { shape: batch.shape, daFields: batch.daPayload.length, proveMs: batch.ms };
      try {
        const prof: any = await bridge.methods.settle(...args).profile({ from: operator, profileMode: 'gates' });
        r.gates = Object.fromEntries((prof.executionSteps ?? []).map((s: any) => [s.functionName, s.gateCount]));
      } catch (e) {
        r.gates = `profile failed: ${String(e).slice(0, 300)}`;
      }
      try {
        const s: any = await bridge.methods.settle(...args).simulate({ from: operator, includeMetadata: true });
        const g = s.gasUsed;
        r.gasUsed = g && {
          total: { daGas: g.totalGas.daGas, l2Gas: g.totalGas.l2Gas },
          public: g.publicGas && { daGas: g.publicGas.daGas, l2Gas: g.publicGas.l2Gas },
          billed: g.billedGas && { daGas: g.billedGas.daGas, l2Gas: g.billedGas.l2Gas },
        };
      } catch (e) {
        r.gasUsed = `simulate failed: ${String(e).slice(0, 300)}`;
      }
      log(`${name}: settling ${batch.shape} with ${batch.daPayload.length} DA fields (client-proved transaction)`);
      const [settled, ms] = await timed(() => bridge.methods.settle(...args).send({ from: operator, wait }));
      const receipt = (settled as any).receipt;
      r.sendToCheckpointedMs = Math.round(ms);
      r.txHash = receipt.txHash.toString();
      r.status = receipt.status;
      r.executionResult = receipt.executionResult;
      r.blockNumber = receipt.blockNumber;
      r.transactionFee = receipt.transactionFee?.toString();

      const tip = (await sim('get_tip')) as any[];
      assert(BigInt(tip[0]) === batch.header[1], `${name}: on-chain state root != header.new_state_root`);
      assert(BigInt(tip[2]) === batch.header[3], `${name}: batch number did not advance`);
      assert(BigInt(tip[4]) === batch.header[7], `${name}: priority cursor != header.priority_end`);

      // The DA log must carry exactly the payload the proof committed to (SPEC.md §9.5).
      const effect: any = (await node.getTxEffect(receipt.txHash))?.data ?? receipt.txEffect;
      const logs: any[] = effect?.publicLogs ?? [];
      const fieldsOf = (l: any): bigint[] => (l.fields ?? l.log ?? []).map((f: any) => BigInt(f.toString()));
      const daLog = logs.map(fieldsOf).find((f) => f[0] === DA_LOG_TAG);
      assert(daLog, `${name}: no DA log in the settlement transaction`);
      assert(daLog[1] === batch.header[3], `${name}: DA log batch number`);
      const published = daLog.slice(2, 2 + batch.daPayload.length);
      assert(
        published.length === batch.daPayload.length && published.every((x, i) => x === batch.daPayload[i]),
        `${name}: published DA payload != proved payload`,
      );
      r.publicLogFields = logs.reduce((n, l) => n + fieldsOf(l).length + 2, 0);
      log(`${name}: settled in block ${r.blockNumber}; DA log verified (${published.length} fields); ${JSON.stringify(r.gasUsed?.total ?? {})}`);
      return r;
    }

    // Batch 1.
    const t1 = await l2Time();
    log(`proving batch 1 over ${entries.length} on-chain requests at L2 time ${t1}`);
    const b1 = await proveBatch(
      prover,
      {
        batchNumber: 1n,
        start: batchStart(BigInt(manifest.genesisTrees), headStart, 0n, 0n),
        accountsRoot: 0n,
        otherRoot: 0n,
        segments: [
          { kind: 'p' },
          { kind: 'x', blockTime: t1, entries: [entries[0]], daFields: rand(24) },
          { kind: 'x', blockTime: t1, entries: [entries[1]], daFields: rand(16) },
        ],
      },
      (m) => log(m),
    );
    report.batch1 = await settle('batch 1', b1);

    // Negative 1: replay batch 1. The public phase must reject the stale root.
    const negatives: Record<string, string> = {};
    try {
      await bridge.methods.settle(...settleArgs(b1)).send({ from: operator, wait });
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
      const forged = [...b1.header];
      forged[0] = BigInt(tip[0]); // prev_state_root = current tip
      forged[1] = randomField(); // new_state_root: anything the forger wants
      forged[2] = randomField(); // new_accounts_root
      forged[3] = BigInt(tip[2]) + 1n; // batch_number
      forged[4] = BigInt(tip[3]); // min_time = last_time
      forged[5] = await l2Time(); // max_time
      forged[6] = cursor; // priority_start
      forged[7] = cursor; // priority_end: consume nothing
      forged[8] = headAtCursor;
      forged[9] = headAtCursor;
      // forged[13] (da_hash) already matches b1's payload; forged[15] is the stored config hash.
      await bridge.methods.settle(...settleArgs(b1, forged)).send({ from: operator, wait });
      negatives.forgedHeader = 'ACCEPTED (bug)';
    } catch (e) {
      negatives.forgedHeader = `rejected: ${String(e).split('\n')[0].slice(0, 200)}`;
    }
    report.negatives = negatives;
    for (const [k, v] of Object.entries(negatives)) log(`${k}: ${v}`);
    assert(Object.values(negatives).every((v) => v.startsWith('rejected')), 'a negative check was accepted');

    // Batch 2 (M5): the largest Mode R payload the network admits. Batch 1's DA gas less its payload
    // is the settlement's fixed DA overhead (tx header, nullifier, storage writes, log headers).
    const daLimit = Number((info as any).txsLimits?.gas?.daGas);
    const overheadFields = report.batch1.gasUsed.total.daGas / 32 - b1.daPayload.length;
    const maxPayload = Math.min(SHAPE.DA_MAX, Math.floor(daLimit / 32) - overheadFields);
    report.m5 = {
      txDaGasAdmissionLimit: daLimit,
      settlementOverheadFields: overheadFields,
      maxPayloadFields: maxPayload,
      protocolPublicLogCapFields: SHAPE.DA_MAX,
      fullCapPayloadDaGas: (SHAPE.DA_MAX + overheadFields) * 32,
    };
    log(`M5: network admits ${daLimit} DA gas per tx; settlement overhead ${overheadFields} fields; max payload ${maxPayload} fields`);
    const t2 = await l2Time();
    log(`proving batch 2 with a ${maxPayload}-field DA payload at L2 time ${t2}`);
    const b2 = await proveBatch(
      prover,
      {
        batchNumber: 2n,
        start: batchStart(b1.end.state, b1.end.priorityHead, b1.end.priorityCursor, b1.end.time),
        accountsRoot: b1.accountsRoot,
        otherRoot: b1.otherRoot,
        segments: [{ kind: 'x', blockTime: t2, daFields: rand(maxPayload) }],
      },
      (m) => log(m),
    );
    report.batch2 = await settle('batch 2', b2);
    report.status = 'passed';
  } catch (e) {
    report.status = 'failed';
    report.error = String((e as any)?.stack ?? e).slice(0, 4000);
    throw e;
  } finally {
    report.finishedAt = new Date().toISOString();
    writeJson(join(OUT, 'settlement.json'), report);
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
