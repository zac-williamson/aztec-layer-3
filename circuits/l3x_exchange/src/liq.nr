//! Liquidation (SPEC.md §8.5): preconditions, prices and the insurance takeover.
use crate::{
    account::{AccountPriv, Position},
    consts::{MARKETS, MAX_COLLATERAL, MAX_PRICE, PPM},
    matching::shift_oi,
    params::Params,
    state::Market,
    trade::{abs, covers, fill, funding_credit, settle_funding},
};

pub global LIQ_CANCEL: Field = 1;
pub global LIQ_CLOSE: Field = 2;
pub global LIQ_TAKEOVER: Field = 3;
pub global LIQ_DEFICIT: Field = 4;
pub global LIQ_ADL: Field = 5;

/// Σ_m |size_m| · mark_m · cmr_m, scaled by PPM (SPEC.md §8.3).
pub fn closeout_margin(acct: AccountPriv, markets: [Market; MARKETS], params: Params) -> u128 {
    let mut cm: u128 = 0;
    for m in 0..MARKETS {
        cm += (abs(acct.positions[m].size) as u128) * (markets[m].mark_price as u128)
            * (params.markets[m].cmr_ppm as u128);
    }
    cm
}

/// equity < requirement / PPM.
pub fn below(equity: i64, requirement: u128) -> bool {
    !covers(equity, requirement)
}

/// A position's unrealized PnL at the mark, including unrealized funding.
pub fn upnl(p: Position, m: Market) -> i64 {
    if p.size == 0 {
        0
    } else {
        let (credit, _) = funding_credit(p.size, p.funding, m.cum_funding);
        p.size * (m.mark_price as i64) - p.entry + credit
    }
}

/// The limit price for closing a position against the book (SPEC.md §8.5): a close at this price
/// keeps the account's equity-to-maintenance ratio constant,
///   long:  mark − mark · mmr_m · E / MM,   short: mark + mark · mmr_m · E / MM,
/// with E clamped at zero and the offset truncated, so the limit lies on the account's side of the
/// exact value. `mm_scaled` is MM scaled by PPM.
pub fn close_limit(size: i64, mark: u64, mmr_ppm: u64, equity: i64, mm_scaled: u128) -> u64 {
    assert(mm_scaled > 0, "no maintenance requirement");
    let e = if equity > 0 { equity as u64 } else { 0 };
    let delta = ((mark as u128) * (mmr_ppm as u128) * (e as u128) / mm_scaled) as u64;
    if size > 0 {
        if delta < mark { mark - delta } else { 1 }
    } else {
        mark + delta
    }
}

/// ceil(notional · rate / PPM): the liquidation fee on a close (SPEC.md §8.5).
pub fn liq_fee(notional: u64, rate_ppm: u64) -> u64 {
    (((notional as u128) * (rate_ppm as u128) + (PPM as u128) - 1) / (PPM as u128)) as u64
}

/// The bankruptcy price of a position for an account with equity `e` (SPEC.md §8.5): closing the
/// whole position there brings the account's equity to zero, mark − e / size. Rounded so the
/// bankrupt account ends at or above zero, the mark if the account is not underwater, and kept in
/// the price range.
pub fn bankruptcy_price(size: i64, mark: u64, e: i64) -> u64 {
    if e >= 0 {
        mark
    } else {
        let s = abs(size);
        let d = (abs(e) + s - 1) / s;
        if size > 0 {
            let p = mark + d;
            if p < MAX_PRICE { p } else { MAX_PRICE - 1 }
        } else if d < mark {
            mark - d
        } else {
            1
        }
    }
}

/// The insurance account takes over an account's whole position in market `m` at the mark (SPEC.md
/// §8.5, step 2): both settle funding, the account realizes its PnL at the mark, and the insurance
/// account fills the same size at the mark. Returns both private parts, the market (open interest)
/// and the funding remainders for the insurance fund.
pub fn takeover(a: AccountPriv, ins: AccountPriv, market: Market, m: u32) -> (AccountPriv, AccountPriv, Market, u64) {
    let mark = market.mark_price as i64;
    let (ac, apos, d1) = settle_funding(a.collateral, a.positions[m], market.cum_funding);
    let (ic, ipos, d2) = settle_funding(ins.collateral, ins.positions[m], market.cum_funding);
    let s = apos.size;
    let (as_, ae, apnl) = fill(apos.size, apos.entry, 0 - s, mark);
    let (is_, ie, ipnl) = fill(ipos.size, ipos.entry, s, mark);
    let mkt = shift_oi(shift_oi(market, apos.size, as_), ipos.size, is_);
    let mut a2 = a;
    a2.positions[m] = Position { size: as_, entry: ae, funding: apos.funding };
    a2.collateral = ac + apnl;
    let mut i2 = ins;
    i2.positions[m] = Position { size: is_, entry: ie, funding: ipos.funding };
    i2.collateral = ic + ipnl;
    assert((abs(a2.collateral) < MAX_COLLATERAL) & (abs(i2.collateral) < MAX_COLLATERAL), "collateral out of range");
    (a2, i2, mkt, d1 + d2)
}

#[test]
fn prices() {
    // E = 300 of MM = 600 (scaled 600·10^6), mmr 6%: offset 2000 · 0.06 · 0.5 = 60.
    assert(close_limit(10, 2000, 60_000, 300, 600_000_000) == 1940);
    assert(close_limit(-10, 2000, 60_000, 300, 600_000_000) == 2060);
    // Underwater: the limit is the mark.
    assert(close_limit(10, 2000, 60_000, -5, 600_000_000) == 2000);
    // Long 10 with equity −95: bankruptcy at 2000 + ceil(9.5) = 2010; short at 2000 − 10.
    assert(bankruptcy_price(10, 2000, -95) == 2010);
    assert(bankruptcy_price(-10, 2000, -95) == 1990);
    assert(bankruptcy_price(10, 2000, 50) == 2000);
    assert(liq_fee(100_000, 10_000) == 1000);
    assert(liq_fee(1, 10_000) == 1);
}
