//! Trading rules (SPEC.md §7–§8, P1 profile): signed actions, fills, margin.
use crate::consts::{DS_ACTION, MAX_SIZE, PPM};
use l3x_types::hash::hash;

pub global KIND_PLACE: Field = 1;
pub global KIND_CANCEL: Field = 2;
pub global KIND_WITHDRAW: Field = 3;
pub global TIF_GTC: Field = 0;
pub global TIF_IOC: Field = 1;

/// The message an account signs for an action (SPEC.md §7.1): the domain binds chain and
/// deployment, the nonce orders the account's actions.
///   PlaceOrder:  p = (side, price, lots, tif)
///   CancelOrder: p = (side, price, seq, 0)
///   Withdraw:    p = (amount, recipient, 0, 0)
pub fn action_msg(domain: Field, kind: Field, account_index: u32, nonce: u64, p: [Field; 4]) -> Field {
    hash([DS_ACTION, domain, kind, account_index as Field, nonce as Field, p[0], p[1], p[2], p[3]])
}

pub fn abs(x: i64) -> u64 {
    if x < 0 { (0 - x) as u64 } else { x as u64 }
}

/// trunc(e · num / den) for 0 ≤ num / den ≤ 1, through 128-bit magnitudes.
fn scale(e: i64, num: i64, den: i64) -> i64 {
    let mag = ((abs(e) as u128) * (abs(num) as u128)) / (abs(den) as u128);
    let m = (mag as u64) as i64;
    if e < 0 { 0 - m } else { m }
}

/// Applies a fill of signed quantity `d` at `price` to a position (size, entry notional) and
/// returns the new position and the realized PnL (SPEC.md §8.2). Reductions realize PnL against
/// the average entry; a flip closes the position and opens the rest at `price`. The rounding of
/// the kept entry only moves value between realized and unrealized PnL: equity is exact.
pub fn fill(size: i64, entry: i64, d: i64, price: i64) -> (i64, i64, i64) {
    let (s, e, pnl) = if (size == 0) | ((size > 0) == (d > 0)) {
        (size + d, entry + d * price, 0)
    } else if abs(d) <= abs(size) {
        let c = 0 - d;
        let keep = scale(entry, size - c, size);
        (size - c, keep, c * price - (entry - keep))
    } else {
        let r = size + d;
        (r, r * price, size * price - entry)
    };
    assert(abs(s) < MAX_SIZE, "position too large");
    (s, e, pnl)
}

pub fn equity(collateral: i64, size: i64, entry: i64, mark: u64) -> i64 {
    collateral + size * (mark as i64) - entry
}

/// Worst-case position if every open order filled (SPEC.md §8.3).
pub fn worst(size: i64, open_bid: u64, open_ask: u64) -> u64 {
    let a = abs(size + open_bid as i64);
    let b = abs(size - open_ask as i64);
    if a > b { a } else { b }
}

/// equity ≥ worst · mark · imr.
pub fn meets_im(equity: i64, worst: u64, mark: u64, imr_ppm: u64) -> bool {
    (equity >= 0)
        & ((equity as u64) as u128 * (PPM as u128) >= (worst as u128) * (mark as u128) * (imr_ppm as u128))
}

#[test]
fn fills() {
    // Long 10 at 100, sell 4 at 110: realizes 40, keeps 6 at 100.
    assert(fill(10, 1000, -4, 110) == (6, 600, 40));
    // Short 10 at 100, buy back 4 at 90: realizes 40.
    assert(fill(-10, -1000, 4, 90) == (-6, -600, 40));
    // Long 10 at 100, sell 15 at 110: realizes 100, short 5 at 110.
    assert(fill(10, 1000, -15, 110) == (-5, -550, 100));
    // Increase.
    assert(fill(10, 1000, 5, 120) == (15, 1600, 0));
    assert(fill(0, 0, -3, 50) == (-3, -150, 0));
    // Rounding: long 3 entered at notional 100, close 1 at 40: keep trunc(100·2/3) = 66.
    assert(fill(3, 100, -1, 40) == (2, 66, 6));
}

#[test]
fn margin() {
    assert(worst(10, 5, 0) == 15);
    assert(worst(10, 0, 30) == 20);
    assert(meets_im(20_000, 100, 2000, 100_000));
    assert(!meets_im(19_999, 100, 2000, 100_000));
    assert(!meets_im(-1, 0, 2000, 100_000));
}
