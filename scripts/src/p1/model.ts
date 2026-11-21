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
} as const;

export const ACCOUNTS_HEIGHT = 32;
export const BOOK_HEIGHT = 80;
export const WD_HEIGHT = 4;
export const MAX_WD_BATCH = 16;
export const KIND = { REGISTER: 1n, DEPOSIT: 2n } as const;
export const LOG = { PRIORITY: 1n, BLOCK: 2n, ORACLE: 3n, SIGNED: 4n } as const;
export const TAG = { SEG: 1n, CHANGE: 2n, REFRESH: 3n, WD: 4n } as const;
export const ACCOUNT_ENTRY_LEN = 11;
export const CLASS_USER = 0n;
export const MAX_DEPOSIT = 1n << 62n;
export const SIDE = { BID: 0n, ASK: 1n } as const;

export type H = (inputs: bigint[]) => Promise<bigint>;
export const hasher = (api: Barretenberg): H => (inputs) => l3xHash(api, inputs);

/** Two's complement in 64 bits, as the circuits store signed values. */
export const enc = (x: bigint): bigint => BigInt.asUintN(64, x);
export const dec = (x: bigint): bigint => BigInt.asIntN(64, x);

export type AccountPub = { owner: bigint; masterAuth: bigint; encCommitment: bigint; class: bigint };
export type AccountPriv = { collateral: bigint; size: bigint; entry: bigint; blind: bigint };
export type Activity = { nonce: bigint; openBid: bigint; openAsk: bigint; openOrders: bigint };
export type Market = {
  bookRoot: bigint;
  indexPrice: bigint;
  indexTime: bigint;
  nextSeq: bigint;
  oiLong: bigint;
  oiShort: bigint;
};
export type State = {
  accountsRoot: bigint;
  activityRoot: bigint;
  market: Market;
  refreshCursor: bigint;
  numAccounts: bigint;
};
export type Params = {
  chainId: bigint;
  instance: bigint;
  oraclePkX: bigint;
  oraclePkY: bigint;
  imrPpm: bigint;
  priceBandPpm: bigint;
  maxJumpPpm: bigint;
  maxAge: bigint;
};
export type Request = { kind: bigint; a: bigint; b: bigint; sender: bigint; time: bigint };

export const newActivity = (): Activity => ({ nonce: 0n, openBid: 0n, openAsk: 0n, openOrders: 0n });

export const pubHash = (h: H, p: AccountPub) => h([DS.ACCT_PUB, p.owner, p.masterAuth, p.encCommitment, p.class]);
export const privHash = (h: H, q: AccountPriv) => h([DS.ACCT_PRIV, enc(q.collateral), enc(q.size), enc(q.entry), q.blind]);
export const accountLeaf = async (h: H, p: AccountPub, q: AccountPriv) => h([DS.ACCT, await pubHash(h, p), await privHash(h, q)]);
export const masterAuthOf = (h: H, x: bigint, y: bigint) => h([DS.MAUTH, x, y]);
export const encCommitment = (h: H, k: bigint) => h([DS.ENC, k]);
export const blindOf = (h: H, k: bigint, idx: bigint, nonce: bigint, pos: number) => h([DS.BLIND, k, idx, nonce, BigInt(pos)]);
export const keystream = (h: H, k: bigint, idx: bigint, nonce: bigint, pos: number, i: number) =>
  h([DS.KS, k, idx, nonce, BigInt(pos + i)]);
export const activityHash = (h: H, a: Activity) => h([DS.ACTV, a.nonce, a.openBid, a.openAsk, a.openOrders]);
export const plaintext = (q: AccountPriv) => [enc(q.collateral), enc(q.size), enc(q.entry), q.blind];

export const marketHash = (h: H, m: Market) =>
  h([DS.MKT, m.bookRoot, m.indexPrice, m.indexTime, m.nextSeq, m.oiLong, m.oiShort]);
export const marketDataHash = (h: H, price: bigint, time: bigint) => h([DS.MARKET_DATA, price, time]);
export const otherRoot = async (h: H, s: State) =>
  h([DS.OTHER, s.activityRoot, await marketHash(h, s.market), s.refreshCursor, s.numAccounts]);
export const treesOf = async (h: H, s: State) => h([DS.TREES, s.accountsRoot, await otherRoot(h, s)]);

export const paramsHash = (h: H, p: Params) =>
  h([DS.PARAMS, p.chainId, p.instance, p.oraclePkX, p.oraclePkY, p.imrPpm, p.priceBandPpm, p.maxJumpPpm, p.maxAge]);
export const domainOf = (h: H, p: Params) => h([DS.DOMAIN, p.chainId, p.instance]);

export const payloadHash = (h: H, kind: bigint, a: bigint, b: bigint) => h([DS.REQ, kind, a, b, 0n]);
export const requestEntry = async (h: H, r: Request) => h([DS.PRIORITY_ENTRY, await payloadHash(h, r.kind, r.a, r.b), r.sender, r.time]);
export const nextHead = (h: H, head: bigint, entry: bigint) => h([DS.PRIORITY, head, entry]);
export const logAppend = (h: H, log: bigint, x: bigint, kind: bigint) => h([DS.ACTION_LOG, log, x, kind]);
export const segmentNonce = (h: H, batch: bigint, actionLogEnd: bigint, startDaLen: number) =>
  h([DS.DANONCE, batch, actionLogEnd, BigInt(startDaLen)]);
export const withdrawalRecord = (h: H, recipient: bigint, amount: bigint, salt: bigint, batch: bigint, index: number) =>
  h([DS.WD, recipient, amount, salt, batch, BigInt(index)]);
export const oracleMessage = (h: H, domain: bigint, price: bigint, time: bigint) => h([DS.ORACLE, domain, price, time]);
export const blockHash = (h: H, time: bigint) => h([DS.BLOCK, time]);

const TWO_64 = 1n << 64n;
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
export const privToNoir = (q: AccountPriv) => ({
  collateral: q.collateral.toString(),
  size: q.size.toString(),
  entry: q.entry.toString(),
  blind: hex(q.blind),
});
export const activityToNoir = (a: Activity) => ({
  nonce: a.nonce.toString(),
  open_bid: a.openBid.toString(),
  open_ask: a.openAsk.toString(),
  open_orders: a.openOrders.toString(),
});
export const marketToNoir = (m: Market) => ({
  book_root: hex(m.bookRoot),
  index_price: m.indexPrice.toString(),
  index_time: m.indexTime.toString(),
  next_seq: m.nextSeq.toString(),
  oi_long: m.oiLong.toString(),
  oi_short: m.oiShort.toString(),
});
export const stateToNoir = (s: State) => ({
  accounts_root: hex(s.accountsRoot),
  activity_root: hex(s.activityRoot),
  market: marketToNoir(s.market),
  refresh_cursor: s.refreshCursor.toString(),
  num_accounts: s.numAccounts.toString(),
});
export const paramsToNoir = (p: Params) => ({
  chain_id: hex(p.chainId),
  instance: hex(p.instance),
  oracle_pk_x: hex(p.oraclePkX),
  oracle_pk_y: hex(p.oraclePkY),
  imr_ppm: p.imrPpm.toString(),
  price_band_ppm: p.priceBandPpm.toString(),
  max_jump_ppm: p.maxJumpPpm.toString(),
  max_age: p.maxAge.toString(),
});
export const requestToNoir = (r: Request) => ({
  kind: hex(r.kind),
  a: hex(r.a),
  b: hex(r.b),
  sender: hex(r.sender),
  time: r.time.toString(),
});
export const zeroPub = (): AccountPub => ({ owner: 0n, masterAuth: 0n, encCommitment: 0n, class: 0n });
export const zeroPriv = (): AccountPriv => ({ collateral: 0n, size: 0n, entry: 0n, blind: 0n });
