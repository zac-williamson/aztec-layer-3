// Mode R DA decoding (SPEC.md §9.5): parse a batch's payload, rebuild the accounts tree from the
// published leaves, and decrypt an account's opening with its encryption key. Exit uses only this.
import { R } from '../lib.ts';
import * as M from './model.ts';
import { MerkleTree } from './tree.ts';

/** An account entry. Change entries omit the public part, which an earlier full entry carries. */
export type AccountEntry = {
  tag: bigint;
  batch: bigint;
  pos: number;
  daNonce: bigint;
  index: bigint;
  leaf: bigint;
  pub?: M.AccountPub;
  ct: bigint[];
};
export type WithdrawalEntry = { batch: bigint; pos: number; record: bigint };

export function decodeBatch(batch: bigint, payload: bigint[]) {
  const accounts: AccountEntry[] = [];
  const withdrawals: WithdrawalEntry[] = [];
  let daNonce: bigint | undefined;
  let pos = 0;
  while (pos < payload.length) {
    const tag = payload[pos];
    if (tag === M.TAG.SEG) {
      daNonce = payload[pos + 1];
      pos += 2;
    } else if (tag === M.TAG.CHANGE || tag === M.TAG.REFRESH || tag === M.TAG.FULL) {
      if (daNonce === undefined) throw new Error(`account entry before any segment header at ${pos}`);
      const full = tag !== M.TAG.CHANGE;
      const len = full ? M.FULL_ENTRY_LEN : M.CHANGE_ENTRY_LEN;
      const f = payload.slice(pos, pos + len);
      if (f.length !== len) throw new Error(`truncated account entry at ${pos}`);
      accounts.push({
        tag,
        batch,
        pos,
        daNonce,
        index: f[1],
        leaf: f[2],
        pub: full ? { owner: f[3], masterAuth: f[4], encCommitment: f[5], class: f[6] } : undefined,
        ct: f.slice(len - M.PLAINTEXT_LEN),
      });
      pos += len;
    } else if (tag === M.TAG.WD) {
      withdrawals.push({ batch, pos, record: payload[pos + 1] });
      pos += 2;
    } else {
      throw new Error(`unknown DA tag ${tag} at ${pos}`);
    }
  }
  return { accounts, withdrawals };
}

export async function decrypt(h: M.H, kEnc: bigint, e: AccountEntry): Promise<M.AccountPriv> {
  const pt: bigint[] = [];
  for (let i = 0; i < M.PLAINTEXT_LEN; i++) {
    const ks = await M.keystream(h, kEnc, e.index, e.daNonce, e.pos, i);
    pt.push((((e.ct[i] - ks) % R) + R) % R);
  }
  return M.fromPlaintext(pt);
}

/**
 * Replays published account entries, in order, into a fresh accounts tree. Returns the latest
 * entry and the latest public part of every account.
 */
export async function rebuildAccounts(h: M.H, entries: AccountEntry[], genesis: { index: bigint; leaf: bigint; pub: M.AccountPub }[] = []) {
  const tree = await new MerkleTree(h, M.ACCOUNTS_HEIGHT, M.DS.ACCT_NODE).init();
  const latest = new Map<bigint, AccountEntry>();
  const pubs = new Map<bigint, M.AccountPub>();
  for (const g of genesis) {
    await tree.set(g.index, g.leaf);
    pubs.set(g.index, g.pub);
  }
  for (const e of entries) {
    await tree.set(e.index, e.leaf);
    latest.set(e.index, e);
    if (e.pub) pubs.set(e.index, e.pub);
  }
  return { tree, latest, pubs };
}

/**
 * Finds an account by its public part and opens its latest entry: the decrypted private part must
 * hash, with the public part, to the published leaf.
 */
export async function openAccount(h: M.H, rebuilt: { latest: Map<bigint, AccountEntry>; pubs: Map<bigint, M.AccountPub> }, kEnc: bigint, masterAuth: bigint) {
  const encCommitment = await M.encCommitment(h, kEnc);
  for (const [index, pub] of rebuilt.pubs) {
    if (pub.masterAuth !== masterAuth || pub.encCommitment !== encCommitment) continue;
    const entry = rebuilt.latest.get(index);
    if (!entry) throw new Error(`account ${index} has no entry in the DA`);
    const priv = await decrypt(h, kEnc, entry);
    if ((await M.accountLeaf(h, pub, priv)) !== entry.leaf) throw new Error(`entry for account ${index} does not open its leaf`);
    return { index, pub, entry, priv };
  }
  throw new Error('account not found in DA');
}
