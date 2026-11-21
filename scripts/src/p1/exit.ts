// The exit client (SPEC.md §12, P1 exit criterion): with nothing but an Aztec node, the Bridge's
// address and the user's seed, rebuild the frozen accounts tree from the DA logs, open the
// user's leaf, and produce the arguments of Bridge.exit_register.
import { assert } from '../pipeline.ts';
import { allPublicEvents, big, daLogs, eventMeta, rawArtifact } from './chain.ts';
import { decodeBatch, openAccount, rebuildAccounts } from './da.ts';
import { keysFromSeed } from './grumpkin.ts';
import * as M from './model.ts';

export type Frozen = { accountsRoot: bigint; marketDataHash: bigint };

export async function exitFromDa(h: M.H, node: any, bridge: any, seed: bigint, frozen: Frozen) {
  const logs = await daLogs(node, bridge);
  const entries = logs.flatMap((l) => decodeBatch(l.batch, l.payload).accounts);
  const { tree, latest } = await rebuildAccounts(h, entries);
  assert(tree.root === frozen.accountsRoot, 'DA does not rebuild the frozen accounts root');

  const keys = await keysFromSeed(h, seed);
  const { entry, priv } = await openAccount(h, latest, keys.kEnc, await M.masterAuthOf(h, keys.pk!.x, keys.pk!.y));

  // The frozen market data is the last settled batch's, published in its BatchSettled event.
  const settled = await allPublicEvents(node, await eventMeta(rawArtifact('l3x_bridge-L3XBridge'), 'BatchSettled'), bridge);
  const last: any = settled[settled.length - 1];
  const indexPrice = big(last.index_price);
  const indexTime = big(last.index_time);
  assert((await M.marketDataHash(h, indexPrice, indexTime)) === frozen.marketDataHash, 'published market data != frozen market data');

  return {
    batches: logs.length,
    index: entry.index,
    pub: entry.pub,
    priv,
    path: tree.path(entry.index),
    indexPrice,
    indexTime,
    equity: priv.collateral + priv.size * indexPrice - priv.entry,
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
