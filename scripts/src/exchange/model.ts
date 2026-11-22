// TypeScript mirror of circuits/l3x_exchange: domain separators, structures, hashes and their
// Noir input encodings. Every function here must agree with the circuit it names; the engine's
// differential checks compare the circuits' outputs with these values on every segment.
import type { Barretenberg } from '@aztec-foundation/bb.js';
import { DS as DS0, R, hex, l3xHash, permute } from '../lib.ts';

export const DS = {
  ...DS0,
  ACCT: 20n,
  ACCT_PUB: 21n,
  ACCT_PRIV: 22n,
  MAUTH: 23n,
  ENC: 24n,
  BLIND: 25n,
  ACTV: 26n,
  ACCT_NODE: 27n,
  ACTV_NODE: 28n,
  BOOK: 29n,
  ORDER: 30n,
  MKT: 31n,
  OTHER: 32n,
  ACTION: 33n,
  KS: 34n,
  DANONCE: 35n,
  WD: 36n,
  WDSALT: 37n,
  REQ: 38n,
  MARKET_DATA: 39n,
  WD_NODE: 40n,
  PARAMS: 41n,
  ORACLE: 42n,
  WD_CHAIN: 43n,
  BLOCK: 44n,
  DOMAIN: 45n,
  MKTS: 46n,
  MKT_PARAMS: 47n,
  LIQ: 48n,
  KEY: 49n,
  KEY_NODE: 50n,
} as const;

export const ACCOUNTS_HEIGHT = 32;
export const BOOK_HEIGHT = 80;
export const WD_HEIGHT = 4;
export const MAX_WD_BATCH = 16;
export const MARKETS = 4;
export const N_ORACLES = 3;
export const KEYS_HEIGHT = 8;
export const KEY_SLOTS = 256;
/** The key id of actions the master key signs. */
export const MASTER_KEY = 256n;
export const KIND = { REGISTER: 1n, DEPOSIT: 2n, FORCED_WITHDRAW: 3n, FORCED_CLOSE: 4n, FORCED_CANCEL_ALL: 5n } as const;
export const LOG = { PRIORITY: 1n, BLOCK: 2n, ORACLE: 3n, SIGNED: 4n, LIQUIDATE: 5n } as const;
export const TAG = { SEG: 1n, CHANGE: 2n, REFRESH: 3n, WD: 4n, FULL: 5n } as const;
export const PLAINTEXT_LEN = 2 + MARKETS;
export const CHANGE_ENTRY_LEN = 3 + PLAINTEXT_LEN;
export const FULL_ENTRY_LEN = 7 + PLAINTEXT_LEN;
export const CLASS = { USER: 0n, INSURANCE: 1n, FEE: 2n } as const;
export const INSURANCE_INDEX = 0n;
export const FEE_INDEX = 1n;
export const PROTOCOL_ACCOUNTS = 2;
export const MAX_DEPOSIT = 1n << 62n;
export const SIDE = { BID: 0n, ASK: 1n } as const;
export const MARKET_DATA_FIELDS = 7;
export const MARKET_DATA_LEN = MARKET_DATA_FIELDS * MARKETS;

export type H = (inputs: bigint[]) => Promise<bigint>;
export const hasher = (api: Barretenberg): H => (inputs) => l3xHash(api, inputs);

/** Two's complement in 64 bits, as the circuits store signed values. */
export const enc = (x: bigint): bigint => BigInt.asUintN(64, x);
export const dec = (x: bigint): bigint => BigInt.asIntN(64, x);
const TWO_64 = 1n << 64n;
const TWO_128 = 1n << 128n;

export type AccountPub = { owner: bigint; masterAuth: bigint; encCommitment: bigint; class: bigint };
export type Position = { size: bigint; entry: bigint; funding: bigint };
export type AccountPriv = { collateral: bigint; positions: Position[]; blind: bigint };
export type Activity = { nonce: bigint; keysRoot: bigint; openOrders: bigint; openBid: bigint[]; openAsk: bigint[] };
/** A session key (SPEC.md §7.2). */
export type Key = { pkX: bigint; pkY: bigint; marketMask: bigint; maxNotional: bigint; expiry: bigint; nonce: bigint };
export type Market = {
  bookRoot: bigint;
  nextSeq: bigint;
  indexPrice: bigint;
  indexTime: bigint;
  markPrice: bigint;
  premium: bigint;
  premiumAcc: bigint;
  lastTick: bigint;
  cumFunding: bigint;
  fundingRate: bigint;
  windowStart: bigint;
  nextFunding: bigint;
  oiLong: bigint;
  oiShort: bigint;
  bestBid: bigint;
  bestAsk: bigint;
};
export type State = {
  accountsRoot: bigint;
  activityRoot: bigint;
  markets: Market[];
  refreshCursor: bigint;
  cycleStart: bigint;
  lastSeq: bigint;
  numAccounts: bigint;
  feesPending: bigint;
  insurancePending: bigint;
  insuranceMicro: bigint;
};
export type MarketParams = {
  imrPpm: bigint;
  mmrPpm: bigint;
  cmrPpm: bigint;
  priceBandPpm: bigint;
  maxJumpPpm: bigint;
  markBandPpm: bigint;
  makerFeePpm: bigint;
  takerFeePpm: bigint;
  liqFeePpm: bigint;
};
export type Params = {
  chainId: bigint;
  instance: bigint;
  oraclePkX: bigint[];
  oraclePkY: bigint[];
  oracleK: bigint;
  maxAge: bigint;
  fundingInterval: bigint;
  markets: MarketParams[];
};
export type Request = { kind: bigint; a: bigint; b: bigint; c?: bigint; sender: bigint; time: bigint };

export const emptyPosition = (): Position => ({ size: 0n, entry: 0n, funding: 0n });
export const emptyPriv = (blind = 0n): AccountPriv => ({ collateral: 0n, positions: Array.from({ length: MARKETS }, emptyPosition), blind });
/** Root of an empty keys tree; set once by `initModel` (every activity leaf starts with it). */
export let EMPTY_KEYS_ROOT = 0n;
export async function initModel(h: H) {
  let e = 0n;
  for (let i = 0; i < KEYS_HEIGHT; i++) e = await h([DS.KEY_NODE, e, e]);
  EMPTY_KEYS_ROOT = e;
}
export const newActivity = (): Activity => {
  if (EMPTY_KEYS_ROOT === 0n) throw new Error('initModel was not called');
  return { nonce: 0n, keysRoot: EMPTY_KEYS_ROOT, openOrders: 0n, openBid: Array(MARKETS).fill(0n), openAsk: Array(MARKETS).fill(0n) };
};
export const emptyKey = (): Key => ({ pkX: 0n, pkY: 0n, marketMask: 0n, maxNotional: 0n, expiry: 0n, nonce: 0n });
export const keyLeaf = (h: H, k: Key) =>
  k.pkX === 0n && k.pkY === 0n && k.nonce === 0n ? Promise.resolve(0n) : h([DS.KEY, k.pkX, k.pkY, k.marketMask, k.maxNotional, k.expiry, k.nonce]);
export const copyPriv = (q: AccountPriv): AccountPriv => ({ ...q, positions: q.positions.map((p) => ({ ...p })) });
export const copyActivity = (a: Activity): Activity => ({ ...a, openBid: [...a.openBid], openAsk: [...a.openAsk] });
export const genesisMarket = (bookRoot: bigint): Market => ({
  bookRoot,
  nextSeq: 0n,
  indexPrice: 0n,
  indexTime: 0n,
  markPrice: 0n,
  premium: 0n,
  premiumAcc: 0n,
  lastTick: 0n,
  cumFunding: 0n,
  fundingRate: 0n,
  windowStart: 0n,
  nextFunding: 0n,
  oiLong: 0n,
  oiShort: 0n,
  bestBid: 0n,
  bestAsk: 0n,
});

export const packPosition = (p: Position) => enc(p.size) + enc(p.entry) * TWO_64 + enc(p.funding) * TWO_128;
export function unpackPosition(x: bigint): Position {
  if (x >= 1n << 192n) throw new Error('packed position out of range');
  return { size: dec(x & (TWO_64 - 1n)), entry: dec((x >> 64n) & (TWO_64 - 1n)), funding: dec(x >> 128n) };
}
export const plaintext = (q: AccountPriv): bigint[] => [enc(q.collateral), ...q.positions.map(packPosition), q.blind];
export function fromPlaintext(pt: bigint[]): AccountPriv {
  return { collateral: dec(pt[0]), positions: pt.slice(1, 1 + MARKETS).map(unpackPosition), blind: pt[PLAINTEXT_LEN - 1] };
}

export const pubHash = (h: H, p: AccountPub) => h([DS.ACCT_PUB, p.owner, p.masterAuth, p.encCommitment, p.class]);
export const privHash = (h: H, q: AccountPriv) => h([DS.ACCT_PRIV, ...plaintext(q)]);
export const accountLeaf = async (h: H, p: AccountPub, q: AccountPriv) => h([DS.ACCT, await pubHash(h, p), await privHash(h, q)]);
export const masterAuthOf = (h: H, x: bigint, y: bigint) => h([DS.MAUTH, x, y]);
export const encCommitment = (h: H, k: bigint) => h([DS.ENC, k]);
export const blindOf = (h: H, k: bigint, idx: bigint, nonce: bigint, pos: number) => h([DS.BLIND, k, idx, nonce, BigInt(pos)]);
export const keystream = (h: H, k: bigint, idx: bigint, nonce: bigint, pos: number, i: number) =>
  h([DS.KS, k, idx, nonce, BigInt(pos + i)]);
export const activityHash = (h: H, a: Activity) =>
  h([DS.ACTV, a.nonce, a.keysRoot, a.openOrders, ...a.openBid.map((b, m) => b + a.openAsk[m] * TWO_64)]);

export const marketHash = (h: H, m: Market) =>
  h([
    DS.MKT,
    m.bookRoot,
    m.nextSeq,
    m.indexPrice,
    m.indexTime,
    m.markPrice,
    enc(m.premium),
    enc(m.premiumAcc),
    m.lastTick,
    enc(m.cumFunding),
    enc(m.fundingRate),
    m.windowStart,
    m.nextFunding,
    m.oiLong,
    m.oiShort,
    m.bestBid,
    m.bestAsk,
  ]);
export const marketDataOf = (m: Market): bigint[] => [m.indexPrice, m.indexTime, m.markPrice, enc(m.cumFunding), enc(m.fundingRate), m.bestBid, m.bestAsk];
export const marketData = (ms: Market[]): bigint[] => ms.flatMap(marketDataOf);
export const marketDataHash = (h: H, data: bigint[]) => h([DS.MARKET_DATA, ...data]);
/** Decodes a batch's published market data into per-market fields. */
export function decodeMarketData(data: bigint[]) {
  return Array.from({ length: MARKETS }, (_, m) => {
    const d = data.slice(m * MARKET_DATA_FIELDS, (m + 1) * MARKET_DATA_FIELDS);
    return { indexPrice: d[0], indexTime: d[1], markPrice: d[2], cumFunding: dec(d[3]), fundingRate: dec(d[4]), bestBid: d[5], bestAsk: d[6] };
  });
}
export const marketsHash = async (h: H, ms: Market[]) => h([DS.MKTS, ...(await Promise.all(ms.map((m) => marketHash(h, m))))]);
export const otherRoot = async (h: H, s: State) =>
  h([DS.OTHER, s.activityRoot, await marketsHash(h, s.markets), s.refreshCursor, s.cycleStart, s.lastSeq, s.numAccounts, s.feesPending, s.insurancePending, s.insuranceMicro]);
export const treesOf = async (h: H, s: State) => h([DS.TREES, s.accountsRoot, await otherRoot(h, s)]);

export const marketParamsHash = (h: H, p: MarketParams) =>
  h([DS.MKT_PARAMS, p.imrPpm, p.mmrPpm, p.cmrPpm, p.priceBandPpm, p.maxJumpPpm, p.markBandPpm, p.makerFeePpm, p.takerFeePpm, p.liqFeePpm]);
export async function paramsHash(h: H, p: Params) {
  const oracles = p.oraclePkX.flatMap((x, i) => [x, p.oraclePkY[i]]);
  const markets = await Promise.all(p.markets.map((m) => marketParamsHash(h, m)));
  return h([DS.PARAMS, p.chainId, p.instance, ...oracles, p.oracleK, p.maxAge, p.fundingInterval, ...markets]);
}
export const domainOf = (h: H, p: Params) => h([DS.DOMAIN, p.chainId, p.instance]);

export const payloadHash = (h: H, kind: bigint, a: bigint, b: bigint, c = 0n) => h([DS.REQ, kind, a, b, c]);
export const requestEntry = async (h: H, r: Request) => h([DS.PRIORITY_ENTRY, await payloadHash(h, r.kind, r.a, r.b, r.c ?? 0n), r.sender, r.time]);
export const nextHead = (h: H, head: bigint, entry: bigint) => h([DS.PRIORITY, head, entry]);
export const logAppend = (h: H, log: bigint, x: bigint, kind: bigint) => h([DS.ACTION_LOG, log, x, kind]);
export const segmentNonce = (h: H, batch: bigint, actionLogEnd: bigint, startDaLen: number) =>
  h([DS.DANONCE, batch, actionLogEnd, BigInt(startDaLen)]);
export const withdrawalRecord = (h: H, recipient: bigint, amount: bigint, salt: bigint, batch: bigint, index: number) =>
  h([DS.WD, recipient, amount, salt, batch, BigInt(index)]);
export const oracleMessage = (h: H, domain: bigint, market: bigint, price: bigint, external: bigint, time: bigint) =>
  h([DS.ORACLE, domain, market, price, external, time]);
export const blockHash = (h: H, time: bigint) => h([DS.BLOCK, time]);

/** Book node: one Poseidon2 permutation over (left, right, ask + bid · 2^64, DS_BOOK). */
export async function bookNode(api: Barretenberg, l: bigint, r: bigint, ask: bigint, bid: bigint): Promise<bigint> {
  return (await permute(api, [l, r, (ask + bid * TWO_64) % R, DS.BOOK]))[0];
}

// Noir input encodings.
export const pubToNoir = (p: AccountPub) => ({
  owner: hex(p.owner),
  master_auth: hex(p.masterAuth),
  enc_commitment: hex(p.encCommitment),
  class: hex(p.class),
});
export const positionToNoir = (p: Position) => ({ size: p.size.toString(), entry: p.entry.toString(), funding: p.funding.toString() });
export const privToNoir = (q: AccountPriv) => ({
  collateral: q.collateral.toString(),
  positions: q.positions.map(positionToNoir),
  blind: hex(q.blind),
});
export const activityToNoir = (a: Activity) => ({
  nonce: a.nonce.toString(),
  keys_root: hex(a.keysRoot),
  open_orders: a.openOrders.toString(),
  open_bid: a.openBid.map(String),
  open_ask: a.openAsk.map(String),
});
export const marketToNoir = (m: Market) => ({
  book_root: hex(m.bookRoot),
  next_seq: m.nextSeq.toString(),
  index_price: m.indexPrice.toString(),
  index_time: m.indexTime.toString(),
  mark_price: m.markPrice.toString(),
  premium: m.premium.toString(),
  premium_acc: m.premiumAcc.toString(),
  last_tick: m.lastTick.toString(),
  cum_funding: m.cumFunding.toString(),
  funding_rate: m.fundingRate.toString(),
  window_start: m.windowStart.toString(),
  next_funding: m.nextFunding.toString(),
  oi_long: m.oiLong.toString(),
  oi_short: m.oiShort.toString(),
  best_bid: m.bestBid.toString(),
  best_ask: m.bestAsk.toString(),
});
export const stateToNoir = (s: State) => ({
  accounts_root: hex(s.accountsRoot),
  activity_root: hex(s.activityRoot),
  markets: s.markets.map(marketToNoir),
  refresh_cursor: s.refreshCursor.toString(),
  cycle_start: s.cycleStart.toString(),
  last_seq: s.lastSeq.toString(),
  num_accounts: s.numAccounts.toString(),
  fees_pending: s.feesPending.toString(),
  insurance_pending: s.insurancePending.toString(),
  insurance_micro: s.insuranceMicro.toString(),
});
export const marketParamsToNoir = (p: MarketParams) => ({
  imr_ppm: p.imrPpm.toString(),
  mmr_ppm: p.mmrPpm.toString(),
  cmr_ppm: p.cmrPpm.toString(),
  price_band_ppm: p.priceBandPpm.toString(),
  max_jump_ppm: p.maxJumpPpm.toString(),
  mark_band_ppm: p.markBandPpm.toString(),
  maker_fee_ppm: p.makerFeePpm.toString(),
  taker_fee_ppm: p.takerFeePpm.toString(),
  liq_fee_ppm: p.liqFeePpm.toString(),
});
export const paramsToNoir = (p: Params) => ({
  chain_id: hex(p.chainId),
  instance: hex(p.instance),
  oracle_pk_x: p.oraclePkX.map(hex),
  oracle_pk_y: p.oraclePkY.map(hex),
  oracle_k: p.oracleK.toString(),
  max_age: p.maxAge.toString(),
  funding_interval: p.fundingInterval.toString(),
  markets: p.markets.map(marketParamsToNoir),
});
export const keyToNoir = (k: Key) => ({
  pk_x: hex(k.pkX),
  pk_y: hex(k.pkY),
  market_mask: k.marketMask.toString(),
  max_notional: k.maxNotional.toString(),
  expiry: k.expiry.toString(),
  nonce: k.nonce.toString(),
});
export const requestToNoir = (r: Request) => ({
  kind: hex(r.kind),
  a: hex(r.a),
  b: hex(r.b),
  c: hex(r.c ?? 0n),
  sender: hex(r.sender),
  time: r.time.toString(),
});
export const zeroPub = (): AccountPub => ({ owner: 0n, masterAuth: 0n, encCommitment: 0n, class: 0n });
