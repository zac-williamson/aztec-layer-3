// Mirror of circuits/l3x_exchange/src/{trade,book}.nr: signed actions, fills, margin, book index.
import * as M from './model.ts';

export const KIND_ACT = { PLACE: 1n, CANCEL: 2n, WITHDRAW: 3n } as const;
export const TIF = { GTC: 0n, IOC: 1n } as const;
export const PPM = 1_000_000n;
export const MAX_PRICE = 1n << 24n;
export const MAX_LOTS = 1n << 24n;
export const MAX_SIZE = 1n << 32n;
export const MAX_COLLATERAL = 1n << 62n;
const TWO_48 = 1n << 48n;

export const actionMsg = (h: M.H, domain: bigint, kind: bigint, account: bigint, nonce: bigint, p: bigint[]) =>
  h([M.DS.ACTION, domain, kind, account, nonce, ...p]);

export const abs = (x: bigint) => (x < 0n ? -x : x);

/** trunc(e · num / den) for 0 ≤ num/den ≤ 1. */
function scale(e: bigint, num: bigint, den: bigint): bigint {
  const m = (abs(e) * abs(num)) / abs(den);
  return e < 0n ? -m : m;
}

/** Applies a fill of signed quantity d at price; returns [size, entry, realized PnL]. */
export function fill(size: bigint, entry: bigint, d: bigint, price: bigint): [bigint, bigint, bigint] {
  let out: [bigint, bigint, bigint];
  if (size === 0n || size > 0n === d > 0n) out = [size + d, entry + d * price, 0n];
  else if (abs(d) <= abs(size)) {
    const c = -d;
    const keep = scale(entry, size - c, size);
    out = [size - c, keep, c * price - (entry - keep)];
  } else {
    const r = size + d;
    out = [r, r * price, size * price - entry];
  }
  if (abs(out[0]) >= MAX_SIZE) throw new Error('position too large');
  return out;
}

export const equity = (collateral: bigint, size: bigint, entry: bigint, mark: bigint) => collateral + size * mark - entry;

export function worst(size: bigint, openBid: bigint, openAsk: bigint): bigint {
  const a = abs(size + openBid);
  const b = abs(size - openAsk);
  return a > b ? a : b;
}

export const meetsIm = (eq: bigint, w: bigint, mark: bigint, imrPpm: bigint) => eq >= 0n && eq * PPM >= w * mark * imrPpm;

export function orderIndex(side: bigint, price: bigint, seq: bigint): bigint {
  if (seq >= 1n << 47n) throw new Error('sequence number too large');
  return side === M.SIDE.ASK ? price * TWO_48 + seq : price * TWO_48 + (TWO_48 - 1n - seq);
}

export type Order = { side: bigint; account: bigint; lots: bigint; price: bigint; seq: bigint };
export const orderLeaf = (h: M.H, side: bigint, account: bigint, lots: bigint) =>
  lots === 0n ? Promise.resolve(0n) : h([M.DS.ORDER, side, account, lots]);
export const askLots = (o: { side: bigint; lots: bigint }) => (o.side === M.SIDE.ASK ? o.lots : 0n);
export const bidLots = (o: { side: bigint; lots: bigint }) => (o.side === M.SIDE.BID ? o.lots : 0n);
