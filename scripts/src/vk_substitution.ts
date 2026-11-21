// Negative tests for SPEC.md §3 G2 and §9.3: no proof of a circuit outside its allowed role may be
// accepted, and the merge tree must chain. Witness generation checks the circuits' own assertions
// (VK tree membership, roles, chaining, configuration) but not recursion constraints, so a forged
// VK hash is caught by barretenberg, as a proving error or a proof that does not verify.
//   A. rogue_app (verifies nothing, returns any output) in the IVC app slot, under init_kernel.
//   B. rogue_segment (claims any transition) as a root child, borrowing x_segment's VK tree slot.
//   C. rogue_segment as a root child with its VK hash replaced by x_segment's.
//   D. rogue_segment listed in the VK tree, but in the client subtree.
//   E. rogue_segment as a merge child, borrowing x_segment's slot.
//   F. two valid segments that do not chain.
//   G. a valid segment proved under another configuration.
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { AztecClientBackend } from '@aztec-foundation/bb.js';
import { Noir } from '@aztec-foundation/noir-noir_js';
import {
  OUT,
  ROLE,
  SHAPE,
  configHashOf,
  hex,
  randomField,
  readCircuit,
  trees,
  readJson,
  readVkBinary,
  readVkJson,
  vkPath,
  vkTree,
} from './lib.ts';
import { type NodeOutput, type Running, Prover, batchStart, newApi, nodeToNoir } from './pipeline.ts';

const CircuitKind = { App: 0, Kernel: 1, HidingKernel: 2 } as const;

type Outcome = { test: string; rejected: boolean; how: string };

/**
 * Runs an attempt that should fail. `expect` is the circuit assertion message for rejections at
 * witness generation. Without it the rejection must come from barretenberg (a proving error or a
 * proof that does not verify), not from a circuit assertion, which would mean the attempt never
 * reached the check it was meant to exercise.
 */
async function expectRejected(test: string, attempt: () => Promise<boolean>, expect?: string): Promise<Outcome> {
  try {
    const verified = await attempt();
    return verified
      ? { test, rejected: false, how: 'proof generated AND verified: not enforced' }
      : { test, rejected: true, how: 'proof generated but does not verify' };
  } catch (err: any) {
    const msg = String(err?.message ?? err).split('\n')[0].slice(0, 200);
    if (expect ? !msg.includes(expect) : msg.includes('Circuit execution failed')) {
      return { test, rejected: false, how: `failed for another reason: ${msg}` };
    }
    return { test, rejected: true, how: msg };
  }
}

async function main() {
  const manifest = readJson(join(OUT, 'manifest.json'));
  const api = await newApi();
  const prover = await Prover.create(api, manifest);
  const config = prover.configHash;
  const results: Outcome[] = [];
  const genesis = batchStart(BigInt(manifest.genesisTrees), 0n, 0n, 0n);
  const now = BigInt(Math.floor(Date.now() / 1000));

  // A. Rogue app in the IVC. The rogue output claims 10 actions that were never authorized.
  results.push(
    await expectRejected('A: rogue app under init_kernel', async () => {
      const forged = { actions_hash: hex(randomField()), count: SHAPE.MAX_CLIENT_PROOFS };
      const pkgs = ['rogue_app', 'init_kernel', 'tail_kernel', 'hiding_kernel'];
      const [rogue, init, tail, hiding] = pkgs.map(readCircuit);
      const w0 = await new Noir(rogue as any).execute({ actions_hash: forged.actions_hash, count: forged.count });
      const out = w0.returnValue as any;
      const w1 = await new Noir(init as any).execute({ app_output: out, app_vk: readVkJson('rogue_app').vk });
      const w2 = await new Noir(tail as any).execute({ prev: out, prev_vk: readVkJson('init_kernel').vk });
      const w3 = await new Noir(hiding as any).execute({ prev: out, prev_vk: readVkJson('tail_kernel').vk });
      const chonk = new AztecClientBackend(
        [rogue, init, tail, hiding].map((c) => new Uint8Array(gunzipSync(Buffer.from(c.bytecode, 'base64')))),
        api,
        pkgs,
        [CircuitKind.App, CircuitKind.Kernel, CircuitKind.Kernel, CircuitKind.HidingKernel],
      );
      const res = await chonk.prove([w0, w1, w2, w3].map((w) => new Uint8Array(gunzipSync(w.witness))), pkgs.map(readVkBinary));
      return chonk.verify(res.proof, res.vk);
    }),
  );

  // A rogue segment claiming a transition from genesis to accounts of the attacker's choosing.
  const forgedAccounts = randomField();
  const forgedEnd: Running = { ...genesis, state: await trees(api, forgedAccounts, 0n), time: now };
  const rogueOut = (configHash: bigint): NodeOutput => ({ configHash, start: genesis, end: forgedEnd });
  const rogue = await prover.proveNode('rogue_segment', { out: nodeToNoir(rogueOut(config)) });
  const pad = await prover.padding(forgedEnd);
  const borrowed = prover.membership('x_segment');

  results.push(
    await expectRejected(
      'B: rogue segment in a borrowed VK tree slot (root)',
      async () => {
        const inputs = prover.rootInputs(rogue, pad, forgedAccounts, 0n, 1n, { membership: borrowed });
        return (await prover.proveRoot(inputs)).verified;
      },
      'child VK not in VK tree',
    ),
  );

  results.push(
    await expectRejected('C: rogue segment with a forged VK hash (root)', async () => {
      const inputs = prover.rootInputs(rogue, pad, forgedAccounts, 0n, 1n, {
        membership: borrowed,
        vk_hash: manifest.vkHashByPkg.x_segment,
      });
      return (await prover.proveRoot(inputs)).verified;
    }),
  );

  results.push(
    await expectRejected(
      'D: rogue segment listed in the client subtree (root)',
      async () => {
        const leaves = manifest.vkTree.leaves.map((x: string) => BigInt(x));
        const slot = ROLE.CLIENT * SHAPE.VK_ROLE_SLOTS + 1;
        leaves[slot] = BigInt(manifest.vkHashByPkg.rogue_segment);
        const layers = await vkTree(api, leaves);
        const altRoot = layers[layers.length - 1][0];
        const altConfig = await configHashOf(api, altRoot, prover.paramsHash);
        const r = await prover.proveNode('rogue_segment', { out: nodeToNoir(rogueOut(altConfig)) });
        const p = await prover.padding(forgedEnd, altConfig);
        const padSlot = manifest.vkTree.slots.padding;
        const inputs = {
          ...prover.rootInputs(r, p, forgedAccounts, 0n, 1n, { membership: { index: slot, path: vkPath(layers, slot).map(hex) } }, {
            membership: { index: padSlot, path: vkPath(layers, padSlot).map(hex) },
          }),
          vk_tree_root: hex(altRoot),
        };
        return (await prover.proveRoot(inputs)).verified;
      },
      'child VK role not allowed',
    ),
  );

  results.push(
    await expectRejected(
      'E: rogue segment in a borrowed VK tree slot (merge)',
      async () => {
        const merge = readCircuit('merge');
        await new Noir(merge as any).execute(prover.mergeInputs(rogue, pad, { membership: borrowed }) as any);
        return true;
      },
      'child VK not in VK tree',
    ),
  );

  const x = await prover.xSegment(genesis, 0n, 0n, now, [], [1n, 2n, 3n]);
  results.push(
    await expectRejected(
      'F: segments that do not chain (root)',
      async () => {
        const gap = await prover.padding({ ...x.node.out.end, time: x.node.out.end.time + 1n });
        return (await prover.proveRoot(prover.rootInputs(x.node, gap, x.accountsRoot, 0n, 1n))).verified;
      },
      'children do not chain',
    ),
  );

  results.push(
    await expectRejected(
      'G: segment proved under another configuration (root)',
      async () => {
        const other = await prover.xSegment(genesis, 0n, 0n, now, [], [1n, 2n, 3n], config + 1n);
        const p = await prover.padding(other.node.out.end);
        return (await prover.proveRoot(prover.rootInputs(other.node, p, other.accountsRoot, 0n, 1n))).verified;
      },
      'left child config mismatch',
    ),
  );

  for (const r of results) console.log(`${r.rejected ? 'PASS' : 'FAIL'}  ${r.test}  (${r.how})`);
  await api.destroy();
  process.exit(results.every((r) => r.rejected) ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
