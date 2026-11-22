// Negative tests for SPEC.md §3 G2 and §9.3: no proof of a circuit outside its allowed role may be
// accepted, and the merge tree must chain. Witness generation checks the circuits' own assertions
// (VK tree membership, roles, chaining, configuration) but not recursion constraints, so a forged
// VK hash is caught by barretenberg, as a proving error or a proof that does not verify.
//   A. rogue_app (verifies nothing, returns any output) in the IVC app slot, under init_kernel.
//   B. rogue_segment (claims any transition) as a root child, borrowing seg_block's VK tree slot.
//   C. rogue_segment as a root child with its VK hash replaced by seg_block's.
//   D. rogue_segment listed in the VK tree, but in the client subtree.
//   E. rogue_segment as a merge child, borrowing seg_block's slot.
//   F. two valid segments that do not chain.
//   G. a valid segment proved under other exchange parameters.
//   H. rogue_client (authorizes anything) in agg_app, borrowing client_auth's VK tree slot.
//   I. rogue_client in agg_app with its VK hash replaced by client_auth's.
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
  readJson,
  readVkBinary,
  readVkJson,
  vkPath,
  vkTree,
} from './lib.ts';
import { Engine } from './exchange/engine.ts';
import * as M from './exchange/model.ts';
import { genesisState, protocolAccounts, testParams } from './exchange/params.ts';
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
  const h = M.hasher(api);
  const { params } = await testParams(h);
  const prover = await Prover.create(api, manifest, await M.paramsHash(h, params));
  const config = prover.configHash;
  const results: Outcome[] = [];
  const genesis = batchStart(BigInt(manifest.genesisTrees), 0n, 0n, 0n, 1n);
  const now = BigInt(Math.floor(Date.now() / 1000));

  // A. Rogue app in the IVC. The rogue output claims 10 actions that were never authorized.
  results.push(
    await expectRejected('A: rogue app under init_kernel', async () => {
      const forged = { actions_hash: hex(randomField()), count: SHAPE.MAX_CLIENT_PROOFS, vk_tree_root: hex(prover.vkTreeRoot) };
      const pkgs = ['rogue_app', 'init_kernel', 'tail_kernel', 'hiding_kernel'];
      const [rogue, init, tail, hiding] = pkgs.map(readCircuit);
      const w0 = await new Noir(rogue as any).execute(forged);
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
  const g = await genesisState(api);
  const forgedState: M.State = { ...g.state, accountsRoot: randomField() };
  const forgedEnd: Running = { ...genesis, state: await M.treesOf(h, forgedState), time: now };
  const forgedOpening = M.stateToNoir(forgedState);
  const rogueOut = (configHash: bigint): NodeOutput => ({ configHash, start: genesis, end: forgedEnd, receiptsRoot: 0n });
  const rogue = await prover.proveNode('rogue_segment', { out: nodeToNoir(rogueOut(config)) });
  const pad = await prover.padding(forgedEnd);
  const borrowed = prover.membership('seg_block');

  results.push(
    await expectRejected(
      'B: rogue segment in a borrowed VK tree slot (root)',
      async () => (await prover.proveRoot(prover.rootInputs(rogue, pad, forgedOpening, [], 1n, { membership: borrowed }))).verified,
      'child VK not in VK tree',
    ),
  );

  results.push(
    await expectRejected('C: rogue segment with a forged VK hash (root)', async () => {
      const inputs = prover.rootInputs(rogue, pad, forgedOpening, [], 1n, {
        membership: borrowed,
        vk_hash: manifest.vkHashByPkg.seg_block,
      });
      return (await prover.proveRoot(inputs)).verified;
    }),
  );

  results.push(
    await expectRejected(
      'D: rogue segment listed in the client subtree (root)',
      async () => {
        const leaves = manifest.vkTree.leaves.map((x: string) => BigInt(x));
        const slot = ROLE.CLIENT * SHAPE.VK_ROLE_SLOTS + SHAPE.VK_ROLE_SLOTS - 1; // an empty client slot
        leaves[slot] = BigInt(manifest.vkHashByPkg.rogue_segment);
        const layers = await vkTree(api, leaves);
        const altRoot = layers[layers.length - 1][0];
        const altConfig = await configHashOf(api, altRoot, prover.paramsHash);
        const r = await prover.proveNode('rogue_segment', { out: nodeToNoir(rogueOut(altConfig)) });
        const p = await prover.padding(forgedEnd, altConfig);
        const padSlot = manifest.vkTree.slots.padding;
        const inputs = {
          ...prover.rootInputs(r, p, forgedOpening, [], 1n, { membership: { index: slot, path: vkPath(layers, slot).map(hex) } }, {
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
        await new Noir(readCircuit('merge') as any).execute(prover.mergeInputs(rogue, pad, { membership: borrowed }) as any);
        return true;
      },
      'child VK not in VK tree',
    ),
  );

  // An honest block segment from genesis, built by the engine.
  const honest = async (p: M.Params) => {
    const engine = await Engine.create(api, p, prover.vkTreeRoot, await protocolAccounts(h));
    await engine.beginBatch(1n, 0n, 0n, 0n);
    await engine.block(now);
    const w = await engine.endBatch();
    return { node: await prover.proveNode('seg_block', w.segments[0].inputs), w };
  };
  const x = await honest(params);
  results.push(
    await expectRejected(
      'F: segments that do not chain (root)',
      async () => {
        const gap = await prover.padding({ ...x.node.out.end, time: x.node.out.end.time + 1n });
        return (await prover.proveRoot(prover.rootInputs(x.node, gap, x.w.endState, [], 1n))).verified;
      },
      'children do not chain',
    ),
  );

  results.push(
    await expectRejected(
      'G: segment proved under other parameters (root)',
      async () => {
        const other = await honest({ ...params, maxAge: params.maxAge + 1n });
        const p = await prover.padding(other.node.out.end);
        return (await prover.proveRoot(prover.rootInputs(other.node, p, other.w.endState, [], 1n))).verified;
      },
      'left child config mismatch',
    ),
  );

  // A rogue client proof authorizing an action on an account it does not control, in slot 0 of an
  // aggregation whose other slots carry honest dummies.
  const rogueClient = await prover.proveClient('rogue_client', { msg: hex(randomField()), account_index: hex(2n), auth_binding: hex(randomField()) });
  const dummy = await prover.dummyClientProof();
  const rogueAgg = (vkHash: string) => {
    const inputs = prover.aggInputs(Array(SHAPE.MAX_CLIENT_PROOFS).fill(dummy), 1);
    inputs.client_vks[0] = readVkJson('rogue_client').vk;
    inputs.vk_hashes[0] = vkHash;
    inputs.memberships[0] = prover.membership('client_auth');
    inputs.proofs[0] = rogueClient.proof;
    inputs.public_inputs[0] = rogueClient.publicInputs;
    return inputs;
  };

  results.push(
    await expectRejected(
      'H: rogue client in a borrowed VK tree slot (agg_app)',
      async () => {
        await new Noir(readCircuit('agg_app') as any).execute(rogueAgg(manifest.vkHashByPkg.rogue_client) as any);
        return true;
      },
      'client VK not in VK tree',
    ),
  );

  results.push(
    await expectRejected('I: rogue client with a forged VK hash (agg_app)', async () => {
      const pkgs = ['agg_app', 'init_kernel', 'tail_kernel', 'hiding_kernel'];
      const [app, init, tail, hiding] = pkgs.map(readCircuit);
      const w0 = await new Noir(app as any).execute(rogueAgg(manifest.vkHashByPkg.client_auth) as any);
      const out = w0.returnValue as any;
      const w1 = await new Noir(init as any).execute({ app_output: out, app_vk: readVkJson('agg_app').vk });
      const w2 = await new Noir(tail as any).execute({ prev: out, prev_vk: readVkJson('init_kernel').vk });
      const w3 = await new Noir(hiding as any).execute({ prev: out, prev_vk: readVkJson('tail_kernel').vk });
      const chonk = new AztecClientBackend(
        [app, init, tail, hiding].map((c) => new Uint8Array(gunzipSync(Buffer.from(c.bytecode, 'base64')))),
        api,
        pkgs,
        [CircuitKind.App, CircuitKind.Kernel, CircuitKind.Kernel, CircuitKind.HidingKernel],
      );
      const res = await chonk.prove([w0, w1, w2, w3].map((w) => new Uint8Array(gunzipSync(w.witness))), pkgs.map(readVkBinary));
      return chonk.verify(res.proof, res.vk);
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
