// Exchange parameters and genesis state for P1 deployments and tests.
import type { Barretenberg } from '@aztec-foundation/bb.js';
import { stateRoot } from '../lib.ts';
import { keysFromSeed } from './grumpkin.ts';
import * as M from './model.ts';
import { BookTree, MerkleTree } from './tree.ts';

/** Seed of the test oracle publisher's key. Test deployments only. */
export const TEST_ORACLE_SEED = 0x6c33782e6f7261636c65n; // "l3x.oracle"

/**
 * Test parameters: 10% initial margin (10x), limit prices within 5% of the index, index moves of
 * at most 10% per update, index at most an hour old for risk-increasing orders.
 */
export async function testParams(h: M.H, chainId = 31337n, instance = 1n) {
  const oracle = await keysFromSeed(h, TEST_ORACLE_SEED);
  const params: M.Params = {
    chainId,
    instance,
    oraclePkX: oracle.pk!.x,
    oraclePkY: oracle.pk!.y,
    imrPpm: 100_000n,
    priceBandPpm: 50_000n,
    maxJumpPpm: 100_000n,
    maxAge: 3600n,
  };
  return { params, oracleSk: oracle.sk };
}

/** Genesis exchange state: empty trees, an empty book, no index (SPEC.md §6). */
export async function genesisState(api: Barretenberg) {
  const h = M.hasher(api);
  const accounts = await new MerkleTree(h, M.ACCOUNTS_HEIGHT, M.DS.ACCT_NODE).init();
  const activity = await new MerkleTree(h, M.ACCOUNTS_HEIGHT, M.DS.ACTV_NODE).init();
  const book = await new BookTree(api, M.BOOK_HEIGHT).init();
  const state: M.State = {
    accountsRoot: accounts.root,
    activityRoot: activity.root,
    market: { bookRoot: book.root, indexPrice: 0n, indexTime: 0n, nextSeq: 0n, oiLong: 0n, oiShort: 0n },
    refreshCursor: 0n,
    numAccounts: 0n,
  };
  const trees = await M.treesOf(h, state);
  return { state, trees, stateRoot: await stateRoot(api, trees, 0n, 0n, 0n) };
}
