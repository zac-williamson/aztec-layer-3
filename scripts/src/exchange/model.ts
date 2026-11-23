// TypeScript mirror of circuits/l3x_exchange: domain separators, structures, hashes and their
// Noir input encodings. Every function here must agree with the circuit it names; the engine's
// differential checks compare the circuits' outputs with these values on every segment.
import type { Barretenberg } from '@aztec-foundation/bb.js';
import { DS as DS0, R, hex, l3xHash, permute, randomField } from '../lib.ts';

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
  RECEIPT_SIG: 51n,
  MAUTH_P: 52n,
  CLEAN: 53n,
  DEPAMT: 54n,
  DEP: 55n,
  TRIGGER: 56n,
  FIRE: 57n,
  TIER: 58n,
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
export const KIND = { REGISTER: 1n, DEPOSIT: 2n, FORCED_WITHDRAW: 3n, FORCED_CLOSE: 4n, FORCED_CANCEL_ALL: 5n, REKEY: 6n } as const;
export const LOG = { PRIORITY: 1n, BLOCK: 2n, ORACLE: 3n, SIGNED: 4n, LIQUIDATE: 5n, CLEANUP: 6n, TRIGGER: 7n, TIER: 8n } as const;
export const TAG = { SEG: 1n, CHANGE: 2n, REFRESH: 3n, WD: 4n, FULL: 5n, DISPLAY: 6n } as const;
/** A display entry's key (da.nr `emit_display`): (market·2 + side)·2^80 + price·2^48 + seq. */
export const displayKey = (market: bigint, side: bigint, price: bigint, seq: bigint) => ((market * 2n + side) << 80n) + (price << 48n) + seq;
export const PLAINTEXT_LEN = 2 + MARKETS;
export const CHANGE_ENTRY_LEN = 3 + PLAINTEXT_LEN;
export const FULL_ENTRY_LEN = 7 + PLAINTEXT_LEN;
export const CLASS = { USER: 0n, INSURANCE: 1n, FEE: 2n } as const;
export const INSURANCE_INDEX = 0n;
export const FEE_INDEX = 1n;
export const PROTOCOL_ACCOUNTS = 2;
export const MAX_DEPOSIT = 1n << 62n;
export const SIDE = { BID: 0n, ASK: 1n } as const;
export const MARKET_DATA_FIELDS = 13;
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
/**
 * An account's activity leaf (SPEC.md §6.4); `epoch` is its order epoch, which CancelAll advances
 * (§6.5), and `keyEpoch` its key epoch, which a rekey advances (§7.3).
 */
export type Activity = { nonce: bigint; keysRoot: bigint; openOrders: bigint; openBid: bigint[]; openAsk: bigint[]; epoch: bigint; keyEpoch: bigint; feeTier: bigint };
/** A session key (SPEC.md §7.2). */
/** A session key; `epoch` is the account's key epoch when it was added, and it is live only while that holds. */
export type Key = { pkX: bigint; pkY: bigint; marketMask: bigint; maxNotional: bigint; expiry: bigint; nonce: bigint; epoch: bigint };
export type Market = {
  bookRoot: bigint;
  /** The market's trigger tree, and whether a trigger is due at the mark (SPEC.md §6.5). */
  triggerRoot: bigint;
  triggerPending: boolean;
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
  /** Batch `printBatch`'s print summary (SPEC.md §8.4, [D1]). */
  printBatch: bigint;
  printLast: bigint;
  printHigh: bigint;
  printLow: bigint;
  printLots: bigint;
  printQuote: bigint;
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
  /** Fee tiers (SPEC.md §8.6): factors in ppm on every market's maker and taker rates. */
  feeTiers: FeeTier[];
};
export type FeeTier = { makerPpm: bigint; takerPpm: bigint };
export const FEE_TIERS = 4;
/**
 * A priority request as queued. A Deposit's `b` commits to its amount and `c` is its refund address;
 * `deposit` is the opening the operator received by constrained delivery, never on chain.
 */
export type Request = { kind: bigint; a: bigint; b: bigint; c?: bigint; sender: bigint; time: bigint; deposit?: DepositOpening };
export type DepositOpening = { amount: bigint; salt: bigint };

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
  return { nonce: 0n, keysRoot: EMPTY_KEYS_ROOT, openOrders: 0n, openBid: Array(MARKETS).fill(0n), openAsk: Array(MARKETS).fill(0n), epoch: 0n, keyEpoch: 0n, feeTier: 0n };
};
export const emptyKey = (): Key => ({ pkX: 0n, pkY: 0n, marketMask: 0n, maxNotional: 0n, expiry: 0n, nonce: 0n, epoch: 0n });
export const keyLeaf = (h: H, k: Key) =>
  k.pkX === 0n && k.pkY === 0n && k.nonce === 0n && k.epoch === 0n
    ? Promise.resolve(0n)
    : h([DS.KEY, k.pkX, k.pkY, k.marketMask, k.maxNotional, k.expiry, k.nonce + k.epoch * TWO_64]);
export const copyPriv = (q: AccountPriv): AccountPriv => ({ ...q, positions: q.positions.map((p) => ({ ...p })) });
export const copyActivity = (a: Activity): Activity => ({ ...a, openBid: [...a.openBid], openAsk: [...a.openAsk] });
export const genesisMarket = (emptyRoot: bigint): Market => ({
  bookRoot: emptyRoot,
  triggerRoot: emptyRoot,
  triggerPending: false,
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
  printBatch: 0n,
  printLast: 0n,
  printHigh: 0n,
  printLow: 0n,
  printLots: 0n,
  printQuote: 0n,
});
/** Records a fill in batch `batch`'s print summary (l3x_exchange Market::record_print). */
export function recordPrint(m: Market, batch: bigint, price: bigint, q: bigint): Market {
  const fresh = m.printBatch !== batch;
  return {
    ...m,
    printBatch: batch,
    printLast: price,
    printHigh: fresh || price > m.printHigh ? price : m.printHigh,
    printLow: fresh || price < m.printLow ? price : m.printLow,
    printLots: (fresh ? 0n : m.printLots) + q,
    printQuote: (fresh ? 0n : m.printQuote) + q * price,
  };
}
/** The largest power of two not above x, or zero ([D1]). */
export const bucket = (x: bigint) => (x === 0n ? 0n : 1n << BigInt(x.toString(2).length - 1));

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
/** A client's auth binding: the client circuit proves knowledge of `secret` behind it (SPEC.md §7.4). */
export const authBinding = (h: H, secret: bigint) => h([DS.AUTH, secret]);
/** A P-256 key's auth binding (client_p256): the key's coordinates in 16-byte halves and the client's salt. */
export const p256Binding = (h: H, pk: { x: bigint; y: bigint }, salt: bigint) => {
  const lo = (1n << 128n) - 1n;
  return h([DS.P256, pk.x >> 128n, pk.x & lo, pk.y >> 128n, pk.y & lo, salt]);
};
/** A passkey's auth binding (client_webauthn): the key, the relying party ID hash, and the client's salt. */
export const webauthnBinding = (h: H, pk: { x: bigint; y: bigint }, rpIdHash: bigint, salt: bigint) => {
  const lo = (1n << 128n) - 1n;
  return h([DS.WEBAUTHN, pk.x >> 128n, pk.x & lo, pk.y >> 128n, pk.y & lo, rpIdHash >> 128n, rpIdHash & lo, salt]);
};
/** Lane-P master authorization (SPEC.md §7.1): the client circuit, with the account's auth binding. */
export const masterAuthP = (h: H, clientVkHash: bigint, binding: bigint) => h([DS.MAUTH_P, clientVkHash, binding]);
export const encCommitment = (h: H, k: bigint) => h([DS.ENC, k]);
export const blindOf = (h: H, k: bigint, idx: bigint, nonce: bigint, pos: number) => h([DS.BLIND, k, idx, nonce, BigInt(pos)]);
export const keystream = (h: H, k: bigint, idx: bigint, nonce: bigint, pos: number, i: number) =>
  h([DS.KS, k, idx, nonce, BigInt(pos + i)]);
export const activityHash = (h: H, a: Activity) =>
  h([DS.ACTV, a.nonce, a.keysRoot, a.openOrders, ...a.openBid.map((b, m) => b + a.openAsk[m] * TWO_64), a.epoch + a.keyEpoch * TWO_64 + a.feeTier * TWO_128]);

export const marketHash = (h: H, m: Market) =>
  h([
    DS.MKT,
    m.bookRoot,
    m.triggerRoot,
    m.triggerPending ? 1n : 0n,
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
    m.printBatch,
    m.printLast,
    m.printHigh,
    m.printLow,
    m.printLots,
    m.printQuote,
  ]);
/** The fields batch `batch` publishes for a market (Market::data). */
export function marketDataOf(m: Market, batch: bigint): bigint[] {
  const printed = m.printBatch === batch && m.printLots > 0n;
  const [last, vwap, high, low, lots] = printed ? [m.printLast, m.printQuote / m.printLots, m.printHigh, m.printLow, m.printLots] : [0n, 0n, 0n, 0n, 0n];
  return [m.indexPrice, m.indexTime, m.markPrice, enc(m.cumFunding), enc(m.fundingRate), m.bestBid, m.bestAsk, last, vwap, high, low, bucket(lots), bucket(m.oiLong)];
}
export const marketData = (ms: Market[], batch: bigint): bigint[] => ms.flatMap((m) => marketDataOf(m, batch));
export const marketDataHash = (h: H, data: bigint[]) => h([DS.MARKET_DATA, ...data]);
/** Decodes a batch's published market data into per-market fields. */
export function decodeMarketData(data: bigint[]) {
  return Array.from({ length: MARKETS }, (_, m) => {
    const d = data.slice(m * MARKET_DATA_FIELDS, (m + 1) * MARKET_DATA_FIELDS);
    return {
      indexPrice: d[0],
      indexTime: d[1],
      markPrice: d[2],
      cumFunding: dec(d[3]),
      fundingRate: dec(d[4]),
      bestBid: d[5],
      bestAsk: d[6],
      last: d[7],
      vwap: d[8],
      high: d[9],
      low: d[10],
      volumeBucket: d[11],
      oiBucket: d[12],
    };
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
  const tiers = p.feeTiers.map((t) => t.makerPpm + t.takerPpm * TWO_64);
  return h([DS.PARAMS, p.chainId, p.instance, ...oracles, p.oracleK, p.maxAge, p.fundingInterval, ...markets, ...tiers]);
}
export const domainOf = (h: H, p: Params) => h([DS.DOMAIN, p.chainId, p.instance]);

export const payloadHash = (h: H, kind: bigint, a: bigint, b: bigint, c = 0n) => h([DS.REQ, kind, a, b, c]);
export const requestEntry = async (h: H, r: Request) => h([DS.PRIORITY_ENTRY, await payloadHash(h, r.kind, r.a, r.b, r.c ?? 0n), r.sender, r.time]);
export const nextHead = (h: H, head: bigint, entry: bigint) => h([DS.PRIORITY, head, entry]);
export const logAppend = (h: H, log: bigint, x: bigint, kind: bigint) => h([DS.ACTION_LOG, log, x, kind]);
export const segmentNonce = (h: H, batch: bigint, actionLogEnd: bigint, startDaLen: number) =>
  h([DS.DANONCE, batch, actionLogEnd, BigInt(startDaLen)]);
/** A queued deposit's amount commitment (SPEC.md §10.3). */
export const depositCommitment = (h: H, amount: bigint, salt: bigint) => h([DS.DEPAMT, amount, salt]);
/** The blind of the credit a deposit moves into the Bridge (SPEC.md §10.3). */
export const depositBlind = (h: H, account: bigint, refundTo: bigint, depositor: bigint, salt: bigint) =>
  h([DS.DEP, account, refundTo, depositor, salt]);
/** A Deposit request as custody queues it, with the operator's opening. */
export async function depositRequest(
  h: H,
  account: bigint,
  amount: bigint,
  sender: bigint,
  time: bigint,
  opts: { salt?: bigint; refundTo?: bigint } = {},
): Promise<Request> {
  const salt = opts.salt ?? randomField();
  return {
    kind: KIND.DEPOSIT,
    a: account,
    b: await depositCommitment(h, amount, salt),
    c: opts.refundTo ?? sender,
    sender,
    time,
    deposit: { amount, salt },
  };
}
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
  epoch: a.epoch.toString(),
  key_epoch: a.keyEpoch.toString(),
  fee_tier: a.feeTier.toString(),
});
export const marketToNoir = (m: Market) => ({
  book_root: hex(m.bookRoot),
  trigger_root: hex(m.triggerRoot),
  trigger_pending: m.triggerPending,
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
  print_batch: m.printBatch.toString(),
  print_last: m.printLast.toString(),
  print_high: m.printHigh.toString(),
  print_low: m.printLow.toString(),
  print_lots: m.printLots.toString(),
  print_quote: m.printQuote.toString(),
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
  fee_tiers: p.feeTiers.map((t) => ({ maker_ppm: t.makerPpm.toString(), taker_ppm: t.takerPpm.toString() })),
});
export const keyToNoir = (k: Key) => ({
  pk_x: hex(k.pkX),
  pk_y: hex(k.pkY),
  market_mask: k.marketMask.toString(),
  max_notional: k.maxNotional.toString(),
  expiry: k.expiry.toString(),
  nonce: k.nonce.toString(),
  epoch: k.epoch.toString(),
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
