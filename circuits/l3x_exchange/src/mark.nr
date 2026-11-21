//! Mark and funding ticks (SPEC.md §8.4). Every oracle update is a mark tick for its market:
//! it accrues the premium, recomputes the mark, and applies funding once an interval is due.
use crate::{
    consts::{FUNDING_CAP, FUNDING_DIV, FUNDING_R, FUNDING_R_CLAMP, MAX_PRICE, PPM},
    params::MarketParams,
    state::Market,
    trade::{abs, assert_cum_in_range},
};

pub fn median3(a: u64, b: u64, c: u64) -> u64 {
    let lo = if a < b { a } else { b };
    let hi = if a < b { b } else { a };
    if c < lo {
        lo
    } else if c > hi {
        hi
    } else {
        c
    }
}

fn clamp(x: i64, bound: i64) -> i64 {
    if x > bound {
        bound
    } else if x < 0 - bound {
        0 - bound
    } else {
        x
    }
}

/// a / b truncated toward zero, for b > 0.
fn div_trunc(a: i64, b: u64) -> i64 {
    let q = (abs(a) / b) as i64;
    if a < 0 { 0 - q } else { q }
}

/// The funding rate for an interval from the time-weighted premium P, in ppm:
/// clamp(P + clamp(R − P, ±R_CLAMP), ±CAP) / DIV, truncated toward zero.
pub fn funding_rate(p: i64) -> i64 {
    let inner = clamp(FUNDING_R - p, FUNDING_R_CLAMP);
    div_trunc(clamp(p + inner, FUNDING_CAP), FUNDING_DIV as u64)
}

/// Applies an index update (price `index`, publisher mark `external`, published at `index_time`)
/// to market `m` at L3 time `t`, with the top of book `best_bid`, `best_ask` (zero for an empty
/// side) proved by the caller. Returns the updated market.
///
/// - The premium in force since the last tick accrues into `premium_acc` for the time elapsed.
/// - mark = median(index, external, book mid), clamped to index · (1 ± mark_band). With an empty
///   side the mid is the index.
/// - Once `next_funding` is reached, the interval's rate comes from the time-weighted premium
///   since `window_start`, and `cum_funding += rate · mark`. At most one interval applies per tick,
///   and after a gap the schedule restarts from `t`, so funding never accrues across a halt.
/// - The first update of a market only starts its schedule.
pub fn tick(
    m: Market,
    mp: MarketParams,
    interval: u64,
    index: u64,
    external: u64,
    index_time: u64,
    best_bid: u64,
    best_ask: u64,
    t: u64,
) -> Market {
    let mut out = m;
    let first = m.index_price == 0;
    if first {
        out.window_start = t;
        out.next_funding = t + interval;
    } else {
        out.premium_acc = m.premium_acc + m.premium * ((t - m.last_tick) as i64);
    }
    out.last_tick = t;
    out.index_price = index;
    out.index_time = index_time;
    out.best_bid = best_bid;
    out.best_ask = best_ask;

    let mid = if (best_bid > 0) & (best_ask > 0) {
        (best_bid + best_ask) / 2
    } else {
        index
    };
    let band = index * mp.mark_band_ppm / PPM;
    let lo = if band < index { index - band } else { 1 };
    let hi = index + band;
    let raw = median3(index, external, mid);
    let mark = if raw < lo {
        lo
    } else if raw > hi {
        hi
    } else {
        raw
    };
    assert((mark > 0) & (mark < MAX_PRICE), "mark out of range");
    out.mark_price = mark;
    out.premium = div_trunc((mark as i64 - index as i64) * (PPM as i64), index);

    if (!first) & (t >= m.next_funding) {
        let elapsed = t - m.window_start;
        let p = if elapsed > 0 {
            div_trunc(out.premium_acc, elapsed)
        } else {
            out.premium
        };
        let rate = funding_rate(p);
        out.cum_funding = m.cum_funding + rate * (mark as i64);
        assert_cum_in_range(out.cum_funding);
        out.funding_rate = rate;
        out.premium_acc = 0;
        out.window_start = t;
        out.next_funding = if m.next_funding + interval > t {
            m.next_funding + interval
        } else {
            t + interval
        };
    }
    out
}

#[test]
fn rates() {
    // Zero premium: the interest component alone, 100 / 8 = 12 ppm per hour.
    assert(funding_rate(0) == 12);
    // A large premium is capped at 4% / 8 = 5000 ppm per hour.
    assert(funding_rate(1_000_000) == 5000);
    assert(funding_rate(-1_000_000) == -5000);
    // Within ±500 ppm of R the rate is R / 8.
    assert(funding_rate(300) == 12);
    // P = 2000: 2000 + clamp(-1900, ±500) = 1500, / 8 = 187.
    assert(funding_rate(2000) == 187);
    assert(median3(3, 1, 2) == 2);
    assert(median3(5, 5, 1) == 5);
}

#[test]
fn ticks() {
    let mp = MarketParams {
        imr_ppm: 100_000,
        mmr_ppm: 60_000,
        cmr_ppm: 40_000,
        price_band_ppm: 50_000,
        max_jump_ppm: 100_000,
        mark_band_ppm: 20_000,
        maker_fee_ppm: 0,
        taker_fee_ppm: 0,
        liq_fee_ppm: 0,
    };
    let g = Market::genesis(0);
    // First update starts the schedule; mark = median(2000, 2010, 2000) = 2000.
    let a = tick(g, mp, 3600, 2000, 2010, 100, 0, 0, 100);
    assert(a.mark_price == 2000);
    assert(a.next_funding == 3700);
    assert(a.cum_funding == 0);
    // External 2100 and book mid 2050: median 2050 clamped to 2040 (2% band); premium 20,000 ppm.
    let b = tick(a, mp, 3600, 2000, 2100, 200, 2040, 2060, 200);
    assert(b.mark_price == 2040);
    assert(b.premium == 20_000);
    // At the funding time the window's premium is 20,000 · 3500 / 3600 = 19,444 ppm, so the rate is
    // (19,444 + clamp(100 − 19,444, ±500)) / 8 = 2368 ppm, and cum += 2368 · mark.
    let c = tick(b, mp, 3600, 2000, 2000, 3700, 0, 0, 3700);
    assert(c.premium_acc == 0);
    assert(c.funding_rate == 2368);
    assert(c.cum_funding == 2368 * 2000);
    assert(c.next_funding == 7300);
}
