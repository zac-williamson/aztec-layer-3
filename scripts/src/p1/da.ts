// Mode R DA decoding (SPEC.md §9.5): parse a batch's payload, rebuild the accounts tree from the
// published leaves, and decrypt an account's opening with its encryption key. Exit uses only this.
import { R } from '../lib.ts';
import * as M from './model.ts';
import { MerkleTree } from './tree.ts';

export type AccountEntry = {
  tag: bigint;
  batch: bigint;
  pos: number;
  daNonce: bigint;
  index: bigint;
  leaf: bigint;
  pub: M.AccountPub;
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
    } else if (tag === M.TAG.CHANGE || tag === M.TAG.REFRESH) {
      if (daNonce === undefined) throw new Error(`account entry before any segment header at ${pos}`);
      const f = payload.slice(pos, pos + M.ACCOUNT_ENTRY_LEN);
      if (f.length !== M.ACCOUNT_ENTRY_LEN) throw new Error(`truncated account entry at ${pos}`);
      accounts.push({
        tag,
        batch,
        pos,
        daNonce,
        index: f[1],
        leaf: f[2],
        pub: { owner: f[3], masterAuth: f[4], encCommitment: f[5], class: f[6] },
        ct: f.slice(7, 11),
      });
      pos += M.ACCOUNT_ENTRY_LEN;
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
  for (let i = 0; i < 4; i++) {
    const ks = await M.keystream(h, kEnc, e.index, e.daNonce, e.pos, i);
    pt.push((((e.ct[i] - ks) % R) + R) % R);
  }
  return { collateral: M.dec(pt[0]), size: M.dec(pt[1]), entry: M.dec(pt[2]), blind: pt[3] };
}

/** Replays published account entries, in order, into a fresh accounts tree. */
export async function rebuildAccounts(h: M.H, entries: AccountEntry[]) {
  const tree = await new MerkleTree(h, M.ACCOUNTS_HEIGHT, M.DS.ACCT_NODE).init();
  const latest = new Map<bigint, AccountEntry>();
  for (const e of entries) {
    await tree.set(e.index, e.leaf);
    latest.set(e.index, e);
  }
  return { tree, latest };
}

/**
 * Finds an account's latest entry by its public part and opens it: the decrypted private part
 * must hash, with the public part, to the published leaf.
 */
export async function openAccount(h: M.H, latest: Map<bigint, AccountEntry>, kEnc: bigint, masterAuth: bigint) {
  const encCommitment = await M.encCommitment(h, kEnc);
  for (const e of latest.values()) {
    if (e.pub.masterAuth !== masterAuth || e.pub.encCommitment !== encCommitment) continue;
    const priv = await decrypt(h, kEnc, e);
    if ((await M.accountLeaf(h, e.pub, priv)) !== e.leaf) throw new Error(`entry for account ${e.index} does not open its leaf`);
    return { entry: e, priv };
  }
  throw new Error('account not found in DA');
}
