// The exit client (SPEC.md §12): with nothing but an Aztec node, the Bridge's address and the
// user's seed, rebuild the frozen accounts tree from the published data, open the user's leaf, and
// produce the arguments of Bridge.exit_register.
import { assert } from '../pipeline.ts';
import { allPublicEvents, big, daLogs, eventMeta, rawArtifact } from './chain.ts';
import { decodeBatch, openAccount, rebuildAccounts } from './da.ts';
import { keysFromSeed } from './grumpkin.ts';
import * as M from './model.ts';
import * as X from './rules.ts';

export type Frozen = { accountsRoot: bigint; marketDataHash: bigint };

/** The genesis leaves of the protocol accounts, from the Bridge's deployment event. */
export async function genesisLeaves(h: M.H, node: any, bridge: any) {
  const raw = rawArtifact('l3x_bridge-L3XBridge');
  const [ev]: any[] = await allPublicEvents(node, await eventMeta(raw, 'ProtocolAccounts'), bridge);
  assert(!!ev, 'no ProtocolAccounts event');
  const classes = [M.CLASS.INSURANCE, M.CLASS.FEE];
  return Promise.all(
    classes.map(async (cls, i) => {
      const pub: M.AccountPub = { owner: big(ev.owners[i]), masterAuth: big(ev.master_auths[i]), encCommitment: big(ev.enc_commitments[i]), class: cls };
      return { index: BigInt(i), leaf: await M.accountLeaf(h, pub, M.emptyPriv(0n)), pub };
    }),
  );
}

export async function exitFromDa(h: M.H, node: any, bridge: any, seed: bigint, frozen: Frozen) {
  const logs = await daLogs(node, bridge);
  const entries = logs.flatMap((l) => decodeBatch(l.batch, l.payload).accounts);
  const rebuilt = await rebuildAccounts(h, entries, await genesisLeaves(h, node, bridge));
  assert(rebuilt.tree.root === frozen.accountsRoot, 'DA does not rebuild the frozen accounts root');

  const keys = await keysFromSeed(h, seed);
  const opened = await openAccount(h, rebuilt, keys.kEnc, await M.masterAuthOf(h, keys.pk!.x, keys.pk!.y));

  // The frozen market data is the last settled batch's, published at the head of its DA log.
  const marketData: bigint[] = logs[logs.length - 1].marketData;
  assert((await M.marketDataHash(h, marketData)) === frozen.marketDataHash, 'published market data != frozen market data');
  const md = M.decodeMarketData(marketData);
  const equity = X.equityAt(opened.priv, md.map((m) => m.indexPrice), md.map((m) => m.cumFunding));

  return {
    batches: logs.length,
    index: opened.index,
    pub: opened.pub,
    priv: opened.priv,
    plaintext: M.plaintext(opened.priv),
    path: rebuilt.tree.path(opened.index),
    marketData,
    equity,
  };
}

/** Path of a withdrawal record in its batch's tree, from the batch's DA alone. */
export async function withdrawalPath(h: M.H, payload: bigint[], batch: bigint, record: bigint) {
  const records = decodeBatch(batch, payload).withdrawals.map((w) => w.record);
  const index = records.indexOf(record);
  assert(index >= 0, 'record not in this batch');
  let layer = [...records, ...Array<bigint>(M.MAX_WD_BATCH - records.length).fill(0n)];
  const path: bigint[] = [];
  let idx = index;
  while (layer.length > 1) {
    path.push(layer[idx ^ 1]);
    const next: bigint[] = [];
    for (let i = 0; i < layer.length; i += 2) next.push(await h([M.DS.WD_NODE, layer[i], layer[i + 1]]));
    layer = next;
    idx >>= 1;
  }
  return { index, path };
}
