// Exchange parameters, protocol accounts and genesis state for deployments and tests.
import type { Barretenberg } from '@aztec-foundation/bb.js';
import { stateRoot } from '../lib.ts';
import { keysFromSeed } from './grumpkin.ts';
import * as M from './model.ts';
import { BookTree, MerkleTree } from './tree.ts';

/** Seeds of the test oracle publishers' keys and the protocol accounts' keys. Test deployments only. */
export const TEST_ORACLE_SEED = 0x6c33782e6f7261636c65n; // "l3x.oracle"
export const TEST_INSURANCE_SEED = 0x6c33782e696e73n; // "l3x.ins"
export const TEST_FEE_SEED = 0x6c33782e666565n; // "l3x.fee"

const market = (imr: bigint, mmr: bigint, cmr: bigint, band: bigint, jump: bigint, markBand: bigint, maker: bigint, taker: bigint, liq: bigint): M.MarketParams => ({
  imrPpm: imr,
  mmrPpm: mmr,
  cmrPpm: cmr,
  priceBandPpm: band,
  maxJumpPpm: jump,
  markBandPpm: markBand,
  makerFeePpm: maker,
  takerFeePpm: taker,
  liqFeePpm: liq,
});
export const UNLISTED: M.MarketParams = market(0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n);

/**
 * Test parameters: three oracle publishers with a 2-of-3 threshold, indices at most an hour old
 * for risk-increasing actions, hourly funding, and three listed markets (market 3 is unlisted):
 * - market 0: 10× (IM 10%, MM 6%, CM 4%), maker 2 bp, taker 5 bp;
 * - market 1: 20× (IM 5%, MM 3%, CM 2%), maker 1 bp, taker 4 bp;
 * - market 2: 5× (IM 20%, MM 12%, CM 8%), no maker fee, taker 6 bp, wider bands.
 * Close-out margins follow SPEC.md §8.3: MM = 0.6·IM, CM = 0.4·IM.
 * Limit prices within 5% of the mark (10% in market 2), index moves of at most 10% per update
 * (20%), marks within 2% of the index (3%), liquidation fees of 1% (1.5%).
 */
export async function testParams(h: M.H, chainId = 31337n, instance = 1n) {
  const oracles = await Promise.all([0n, 1n, 2n].map((i) => keysFromSeed(h, TEST_ORACLE_SEED + i)));
  const params: M.Params = {
    chainId,
    instance,
    oraclePkX: oracles.map((k) => k.pk!.x),
    oraclePkY: oracles.map((k) => k.pk!.y),
    oracleK: 2n,
    maxAge: 3600n,
    fundingInterval: 3600n,
    markets: [
      market(100_000n, 60_000n, 40_000n, 50_000n, 100_000n, 20_000n, 200n, 500n, 10_000n),
      market(50_000n, 30_000n, 20_000n, 50_000n, 100_000n, 20_000n, 100n, 400n, 10_000n),
      market(200_000n, 120_000n, 80_000n, 100_000n, 200_000n, 30_000n, 0n, 600n, 15_000n),
      UNLISTED,
    ],
  };
  return { params, oracleSks: oracles.map((k) => k.sk), oracleSk: oracles[0].sk };
}

export type ProtocolAccount = { pub: M.AccountPub; kEnc: bigint; sk: bigint };

/**
 * The insurance (index 0) and fee (index 1) accounts that exist from genesis (SPEC.md §6.3),
 * owned by the given Aztec addresses and controlled by keys derived from their seeds.
 */
export async function protocolAccounts(h: M.H, owners: [bigint, bigint] = [0x1n, 0x2n], seeds: [bigint, bigint] = [TEST_INSURANCE_SEED, TEST_FEE_SEED]): Promise<ProtocolAccount[]> {
  const classes = [M.CLASS.INSURANCE, M.CLASS.FEE];
  return Promise.all(
    seeds.map(async (seed, i) => {
      const k = await keysFromSeed(h, seed);
      const pub: M.AccountPub = { owner: owners[i], masterAuth: await M.masterAuthOf(h, k.pk.x, k.pk.y), encCommitment: await M.encCommitment(h, k.kEnc), class: classes[i] };
      return { pub, kEnc: k.kEnc, sk: k.sk };
    }),
  );
}

/** Genesis exchange state (SPEC.md §6): the protocol accounts, empty books, no indices. */
export async function genesisState(api: Barretenberg, protocol?: ProtocolAccount[]) {
  const h = M.hasher(api);
  await M.initModel(h);
  const accts = protocol ?? (await protocolAccounts(h));
  const accounts = await new MerkleTree(h, M.ACCOUNTS_HEIGHT, M.DS.ACCT_NODE).init();
  const activity = await new MerkleTree(h, M.ACCOUNTS_HEIGHT, M.DS.ACTV_NODE).init();
  for (const [i, a] of accts.entries()) {
    await accounts.set(BigInt(i), await M.accountLeaf(h, a.pub, M.emptyPriv(0n)));
    await activity.set(BigInt(i), await M.activityHash(h, M.newActivity()));
  }
  const book = await new BookTree(api, M.BOOK_HEIGHT).init();
  const state: M.State = {
    accountsRoot: accounts.root,
    activityRoot: activity.root,
    markets: Array.from({ length: M.MARKETS }, () => M.genesisMarket(book.root)),
    refreshCursor: 0n,
    numAccounts: BigInt(accts.length),
    feesPending: 0n,
    insurancePending: 0n,
    insuranceMicro: 0n,
  };
  const trees = await M.treesOf(h, state);
  return { state, trees, stateRoot: await stateRoot(api, trees, 0n, 0n, 0n), protocol: accts };
}
