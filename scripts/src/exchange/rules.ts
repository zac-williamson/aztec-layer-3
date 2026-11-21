// Mirror of circuits/l3x_exchange/src/{trade,mark,book}.nr: signed actions, fills, funding, fees,
// margin, mark ticks and the book index.
import * as M from './model.ts';

export const KIND_ACT = { PLACE: 1n, CANCEL: 2n, WITHDRAW: 3n } as const;
export const TIF = { GTC: 0n, IOC: 1n, FOK: 2n, POST_ONLY: 3n } as const;
export const PPM = 1_000_000n;
export const MICRO = 1_000_000n;
export const MAX_PRICE = 1n << 24n;
export const MAX_LOTS = 1n << 24n;
export const MAX_SIZE = 1n << 32n;
export const MAX_COLLATERAL = 1n << 62n;
export const MAX_CUM_FUNDING = 1n << 60n;
export const MAX_FUNDING_CREDIT = 1n << 58n;
export const MAX_OPEN_ORDERS = 1000n;
export const FUNDING = { R: 100n, R_CLAMP: 500n, CAP: 40_000n, DIV: 8n } as const;
const TWO_48 = 1n << 48n;

export const actionMsg = (h: M.H, domain: bigint, kind: bigint, account: bigint, nonce: bigint, p: bigint[]) =>
  h([M.DS.ACTION, domain, kind, account, nonce, ...p]);

export const abs = (x: bigint) => (x < 0n ? -x : x);
/** Truncating division toward zero, as the circuits compute it through magnitudes. */
export const divTrunc = (a: bigint, b: bigint) => (a < 0n ? -(abs(a) / b) : a / b);

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

/** floor(x / MICRO) and the remainder in [0, MICRO). */
export function floorMicro(x: bigint): [bigint, bigint] {
  if (abs(x) / MICRO >= MAX_FUNDING_CREDIT) throw new Error('funding amount out of range');
  const q = x >= 0n ? x / MICRO : -((-x + MICRO - 1n) / MICRO);
  return [q, x - q * MICRO];
}

/** Funding a position receives as the market's index moves from its snapshot to cum: [credit, dust]. */
export const fundingCredit = (size: bigint, snapshot: bigint, cum: bigint) => floorMicro(-size * (cum - snapshot));

/** Settles accrued funding; returns [collateral, position, dust]. */
export function settleFunding(collateral: bigint, pos: M.Position, cum: bigint): [bigint, M.Position, bigint] {
  const [credit, dust] = fundingCredit(pos.size, pos.funding, cum);
  const c = collateral + credit;
  if (abs(c) >= MAX_COLLATERAL) throw new Error('collateral out of range');
  return [c, { ...pos, funding: cum }, dust];
}

/** ceil(lots · price · rate / PPM). */
export const fee = (lots: bigint, price: bigint, ratePpm: bigint) => (lots * price * ratePpm + PPM - 1n) / PPM;

export const equity = (acct: M.AccountPriv, markets: M.Market[]) =>
  equityAt(acct, markets.map((m) => m.markPrice), markets.map((m) => m.cumFunding));

/** Equity at the given prices and cumulative funding indices (desert mode: the frozen indices). */
export function equityAt(acct: M.AccountPriv, prices: bigint[], cums: bigint[]): bigint {
  let e = acct.collateral;
  acct.positions.forEach((p, m) => {
    if (p.size !== 0n) e += p.size * prices[m] - p.entry + fundingCredit(p.size, p.funding, cums[m])[0];
  });
  return e;
}

export function worst(size: bigint, openBid: bigint, openAsk: bigint): bigint {
  const a = abs(size + openBid);
  const b = abs(size - openAsk);
  return a > b ? a : b;
}

export const initialMargin = (acct: M.AccountPriv, act: M.Activity, markets: M.Market[], params: M.Params) =>
  acct.positions.reduce((s, p, m) => s + worst(p.size, act.openBid[m], act.openAsk[m]) * markets[m].markPrice * params.markets[m].imrPpm, 0n);
export const maintenanceMargin = (acct: M.AccountPriv, markets: M.Market[], params: M.Params) =>
  acct.positions.reduce((s, p, m) => s + abs(p.size) * markets[m].markPrice * params.markets[m].mmrPpm, 0n);
export const covers = (eq: bigint, requirement: bigint) => eq >= 0n && eq * PPM >= requirement;

export function exposureFresh(acct: M.AccountPriv, act: M.Activity, markets: M.Market[], maxAge: bigint, now: bigint) {
  return acct.positions.every((p, m) => {
    const exposed = p.size !== 0n || act.openBid[m] > 0n || act.openAsk[m] > 0n;
    return !exposed || markets[m].indexTime + maxAge >= now;
  });
}

// ---- Mark and funding ticks (mark.nr) ----

export function median3(a: bigint, b: bigint, c: bigint) {
  const lo = a < b ? a : b;
  const hi = a < b ? b : a;
  return c < lo ? lo : c > hi ? hi : c;
}
const clamp = (x: bigint, bound: bigint) => (x > bound ? bound : x < -bound ? -bound : x);

export const fundingRate = (p: bigint) => divTrunc(clamp(p + clamp(FUNDING.R - p, FUNDING.R_CLAMP), FUNDING.CAP), FUNDING.DIV);

/** Applies an index update to a market at L3 time t (mark.nr `tick`). */
export function tick(m: M.Market, mp: M.MarketParams, interval: bigint, index: bigint, external: bigint, indexTime: bigint, bestBid: bigint, bestAsk: bigint, t: bigint): M.Market {
  const out = { ...m };
  const first = m.indexPrice === 0n;
  if (first) {
    out.windowStart = t;
    out.nextFunding = t + interval;
  } else {
    out.premiumAcc = m.premiumAcc + m.premium * (t - m.lastTick);
  }
  out.lastTick = t;
  out.indexPrice = index;
  out.indexTime = indexTime;
  out.bestBid = bestBid;
  out.bestAsk = bestAsk;
  const mid = bestBid > 0n && bestAsk > 0n ? (bestBid + bestAsk) / 2n : index;
  const band = (index * mp.markBandPpm) / PPM;
  const lo = band < index ? index - band : 1n;
  const hi = index + band;
  const raw = median3(index, external, mid);
  const mark = raw < lo ? lo : raw > hi ? hi : raw;
  if (mark <= 0n || mark >= MAX_PRICE) throw new Error('mark out of range');
  out.markPrice = mark;
  out.premium = divTrunc((mark - index) * PPM, index);
  if (!first && t >= m.nextFunding) {
    const elapsed = t - m.windowStart;
    const p = elapsed > 0n ? divTrunc(out.premiumAcc, elapsed) : out.premium;
    const rate = fundingRate(p);
    out.cumFunding = m.cumFunding + rate * mark;
    if (abs(out.cumFunding) >= MAX_CUM_FUNDING) throw new Error('cumulative funding out of range');
    out.fundingRate = rate;
    out.premiumAcc = 0n;
    out.windowStart = t;
    out.nextFunding = m.nextFunding + interval > t ? m.nextFunding + interval : t + interval;
  }
  return out;
}

// ---- Book ----

export function orderIndex(side: bigint, price: bigint, seq: bigint): bigint {
  if (seq >= 1n << 47n) throw new Error('sequence number too large');
  return side === M.SIDE.ASK ? price * TWO_48 + seq : price * TWO_48 + (TWO_48 - 1n - seq);
}
export const RIGHTMOST = (1n << 80n) - 1n;
export const LEFTMOST = 0n;

export type Order = { side: bigint; account: bigint; lots: bigint; price: bigint; seq: bigint };
export const orderLeaf = (h: M.H, side: bigint, account: bigint, lots: bigint) =>
  lots === 0n ? Promise.resolve(0n) : h([M.DS.ORDER, side, account, lots]);
export const askLots = (o: { side: bigint; lots: bigint }) => (o.side === M.SIDE.ASK ? o.lots : 0n);
export const bidLots = (o: { side: bigint; lots: bigint }) => (o.side === M.SIDE.BID ? o.lots : 0n);
