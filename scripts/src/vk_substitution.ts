// Negative tests for SPEC.md §3 G2: a proof of any circuit other than the pinned one must be
// rejected at each recursive layer. Witness generation does not check recursion constraints, so
// rejection shows up in barretenberg, as a proving error or a proof that does not verify.
//   A. rogue_app (verifies nothing, returns any output) in the IVC app slot, under init_kernel.
//   B. the padding segment's proof and VK in the root's tube slot.
import { cpus } from 'node:os';
import { gunzipSync } from 'node:zlib';
import { AztecClientBackend, Barretenberg, UltraHonkBackend } from '@aztec-foundation/bb.js';
import { Noir } from '@aztec-foundation/noir-noir_js';
import { OUT, SHAPE, bytesToFields, hex, randomField, readCircuit, readJson, readVkBinary, readVkJson } from './lib.ts';
import { join } from 'node:path';

const CircuitKind = { App: 0, Kernel: 1, HidingKernel: 2 } as const;

type Outcome = { test: string; rejected: boolean; how: string };

async function expectRejected(test: string, attempt: () => Promise<boolean>): Promise<Outcome> {
  try {
    const verified = await attempt();
    return verified
      ? { test, rejected: false, how: 'proof generated AND verified: pin not enforced' }
      : { test, rejected: true, how: 'proof generated but does not verify' };
  } catch (err: any) {
    const msg = String(err?.message ?? err).split('\n')[0].slice(0, 160);
    return { test, rejected: true, how: `prover error: ${msg}` };
  }
}

async function main() {
  const api = await Barretenberg.new({ threads: cpus().length });
  const results: Outcome[] = [];

  // A. Rogue app in the IVC. The rogue output claims 10 actions that were never authorized.
  results.push(
    await expectRejected('A: rogue app under init_kernel', async () => {
      const forged = { actions_hash: hex(randomField()), count: SHAPE.MAX_CLIENT_PROOFS };
      const rogue = readCircuit('rogue_app');
      const init = readCircuit('init_kernel');
      const tail = readCircuit('tail_kernel');
      const hiding = readCircuit('hiding_kernel');
      const w0 = await new Noir(rogue as any).execute({ actions_hash: forged.actions_hash, count: forged.count });
      const out = w0.returnValue as any;
      const w1 = await new Noir(init as any).execute({ app_output: out, app_vk: readVkJson('rogue_app').vk });
      const w2 = await new Noir(tail as any).execute({ prev: out, prev_vk: readVkJson('init_kernel').vk });
      const w3 = await new Noir(hiding as any).execute({ prev: out, prev_vk: readVkJson('tail_kernel').vk });
      const chonk = new AztecClientBackend(
        [rogue, init, tail, hiding].map((c) => new Uint8Array(gunzipSync(Buffer.from(c.bytecode, 'base64')))),
        api,
        ['rogue_app', 'init_kernel', 'tail_kernel', 'hiding_kernel'],
        [CircuitKind.App, CircuitKind.Kernel, CircuitKind.Kernel, CircuitKind.HidingKernel],
      );
      const res = await chonk.prove(
        [w0, w1, w2, w3].map((w) => new Uint8Array(gunzipSync(w.witness))),
        ['rogue_app', 'init_kernel', 'tail_kernel', 'hiding_kernel'].map(readVkBinary),
      );
      return chonk.verify(res.proof, res.vk);
    }),
  );

  // B. Padding proof in the root's tube slot (and in the padding slot).
  results.push(
    await expectRejected('B: padding proof in root tube slot', async () => {
      const manifest = readJson(join(OUT, 'manifest.json'));
      const pad = readCircuit('padding');
      const padW = await new Noir(pad as any).execute({ output: { actions_hash: hex(0n), count: 0 } });
      const padProof = await new UltraHonkBackend(pad.bytecode, api).generateProof(padW.witness, {
        verifierTarget: 'noir-rollup-no-zk',
      });
      const padFields = bytesToFields(padProof.proof).map(hex);
      const root = readCircuit('root');
      const now = Math.floor(Date.now() / 1000);
      const rootW = await new Noir(root as any).execute({
        tube_vk: readVkJson('padding').vk,
        tube_proof: padFields,
        agg: { actions_hash: hex(0n), count: 0 },
        padding_vk: readVkJson('padding').vk,
        padding_proof: padFields,
        prev_accounts_root: hex(0n),
        prev_last_time: '0',
        batch_number: '1',
        min_time: String(now - 60),
        max_time: String(now),
        priority_start: '0',
        priority_n: 0,
        priority_head_start: hex(0n),
        priority_entries: Array(SHAPE.MAX_PRIORITY).fill(hex(0n)),
        da_payload: Array(SHAPE.DA_LEN).fill(hex(0n)),
        config_hash: manifest.configHash,
      });
      const backend = new UltraHonkBackend(root.bytecode, api);
      const proof = await backend.generateProof(rootW.witness, { verifierTarget: 'noir-recursive' });
      return backend.verifyProof(proof, { verifierTarget: 'noir-recursive' });
    }),
  );

  for (const r of results) console.log(`${r.rejected ? 'PASS' : 'FAIL'}  ${r.test}  (${r.how})`);
  await api.destroy();
  process.exit(results.every((r) => r.rejected) ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
