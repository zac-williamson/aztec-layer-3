//! Trading rules (SPEC.md §7–§8): signed actions, fills, funding settlement, fees, margin.
use crate::{
    account::{account_leaf, AccountPriv, AccountPub, Activity, blind, enc_commitment, Key, Position},
    consts::{
        DS_ACTION, DS_KEY_NODE, DS_WD_CHAIN, DS_WDSALT, KEY_SLOTS, KEYS_HEIGHT, MARKETS, MAX_COLLATERAL,
        MAX_CUM_FUNDING, MAX_FUNDING_CREDIT, MAX_SIZE, MICRO, PPM, TAG_WD,
    },
    da::{absorb, emit_change},
    params::Params,
    state::Market,
    tree::merkle_root,
    withdrawal_record,
};
use l3x_types::{hash::hash, Running};

pub global KIND_PLACE: Field = 1;
pub global KIND_CANCEL: Field = 2;
pub global KIND_WITHDRAW: Field = 3;
pub global KIND_ADD_KEY: Field = 4;
pub global KIND_REVOKE_KEY: Field = 5;
pub global TIF_GTC: Field = 0;
pub global TIF_IOC: Field = 1;
pub global TIF_FOK: Field = 2;
pub global TIF_POST_ONLY: Field = 3;
pub global TIF_GTT: Field = 4;
pub global ACTION_PAYLOAD: u32 = 8;

/// The message a key signs for an action (SPEC.md §7.1): the domain binds chain and deployment,
/// the key id binds the signing key's slot (MASTER_KEY for the master key), and the nonce orders
/// that key's actions.
///   PlaceOrder:  p = (market, side, price, lots, tif, reduce_only, expiry, 0)
///   CancelOrder: p = (market, side, price, seq, 0, 0, 0, 0)
///   Withdraw:    p = (amount, recipient, 0, …)
///   AddKey:      p = (slot, pk_x, pk_y, market_mask, max_notional, expiry, 0, 0)
///   RevokeKey:   p = (slot, 0, …)
pub fn action_msg(domain: Field, kind: Field, account_index: u32, key_id: u32, nonce: u64, p: [Field; ACTION_PAYLOAD]) -> Field {
    hash(
        [
            DS_ACTION, domain, kind, account_index as Field, key_id as Field, nonce as Field, p[0], p[1], p[2],
            p[3], p[4], p[5], p[6], p[7],
        ],
    )
}

/// AddKey (`add`) or RevokeKey on a session-key slot (SPEC.md §7.2), p = (slot, pk_x, pk_y,
/// market_mask, max_notional, expiry, …): proves the slot's current key under `keys_root` and
/// returns the new root. The slot keeps its nonce, so a replaced key's signatures never replay.
pub fn write_key_slot(keys_root: Field, old: Key, path: [Field; KEYS_HEIGHT], add: bool, p: [Field; ACTION_PAYLOAD]) -> Field {
    let slot = p[0] as u32;
    assert((slot as Field == p[0]) & (slot < KEY_SLOTS), "key slot");
    assert(merkle_root(DS_KEY_NODE, old.leaf(), slot, path) == keys_root, "key slot path");
    let new_key = if add {
        let mask = p[3] as u32;
        let max_notional = p[4] as u64;
        let expiry = p[5] as u64;
        assert(
            (mask as Field == p[3]) & (max_notional as Field == p[4]) & (expiry as Field == p[5]),
            "key parameters out of range",
        );
        assert((p[1] != 0) | (p[2] != 0), "empty key");
        Key { pk_x: p[1], pk_y: p[2], market_mask: mask, max_notional, expiry, nonce: old.nonce }
    } else {
        Key { pk_x: 0, pk_y: 0, market_mask: 0, max_notional: 0, expiry: 0, nonce: old.nonce }
    };
    merkle_root(DS_KEY_NODE, new_key.leaf(), slot, path)
}

/// Withdraw (SPEC.md §8.3, §10.4), p = (amount, recipient, …), authorized by the master key or a
/// client proof: `amount` of the account's collateral to an Aztec `recipient`. Requires the
/// collateral, fresh indices wherever the account is exposed, and IM after the withdrawal. Writes
/// the account's new private part under a fresh blind, publishes it, and appends the withdrawal
/// record to the batch's withdrawals chain and the DA. Returns the new account leaf; the caller
/// writes it, and the activity, to the trees.
pub fn withdraw(
    running: Running,
    markets: [Market; MARKETS],
    params: Params,
    idx: u32,
    acct_pub: AccountPub,
    old: AccountPriv,
    act: Activity,
    k_enc: Field,
    p: [Field; ACTION_PAYLOAD],
    da_nonce: Field,
) -> (Field, Running) {
    let mut r = running;
    let amount = p[0] as u64;
    let recipient = p[1];
    assert((amount as Field == p[0]) & (amount > 0) & (amount < MAX_COLLATERAL), "withdrawal amount out of range");
    assert(old.collateral >= amount as i64, "collateral below the amount");
    assert(exposure_fresh(old, act, markets, params.max_age, r.time), "index too old for a withdrawal");
    let after = equity(old, markets) - amount as i64;
    assert(covers(after, initial_margin(old, act, markets, params)), "insufficient margin");

    assert(enc_commitment(k_enc) == acct_pub.enc_commitment, "k_enc does not open the commitment");
    let mut np = old;
    np.collateral = old.collateral - amount as i64;
    np.blind = blind(k_enc, idx, da_nonce, r.da_len);
    let new_leaf = account_leaf(acct_pub, np);
    r = emit_change(r, idx, new_leaf, np, k_enc, da_nonce);

    // The salt makes the record unguessable from public data (SPEC.md §10.4); the owner can
    // rebuild it from its key.
    let index = r.withdrawals_count;
    let salt = hash([DS_WDSALT, k_enc, r.batch as Field, index as Field]);
    let record = withdrawal_record(recipient, amount, salt, r.batch, index);
    r.withdrawals = hash([DS_WD_CHAIN, r.withdrawals, record]);
    r.withdrawals_count = index + 1;
    r.withdrawals_amount += amount;
    r = absorb(absorb(r, TAG_WD), record);
    (new_leaf, r)
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
/// returns the new size and entry and the realized PnL (SPEC.md §8.2). Reductions realize PnL
/// against the average entry; a flip closes the position and opens the rest at `price`. The
/// rounding of the kept entry only moves value between realized and unrealized PnL: equity is
/// exact.
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

/// floor(±mag / MICRO) and the remainder r in [0, MICRO): ±mag = q · MICRO + r.
pub fn floor_micro(negative: bool, mag: u128) -> (i64, u64) {
    let q = mag / (MICRO as u128);
    let r = (mag % (MICRO as u128)) as u64;
    assert(q < (MAX_FUNDING_CREDIT as u128), "funding amount out of range");
    let q = (q as u64) as i64;
    if !negative {
        (q, r)
    } else if r == 0 {
        (0 - q, 0)
    } else {
        (0 - q - 1, MICRO - r)
    }
}

/// The funding a position receives as its market's cumulative index moves from the position's
/// snapshot to `cum` (both in micro-units per lot): floor(−size · (cum − snapshot) / MICRO)
/// collateral units, rounded against the account, and the remainder in micro-units, which belongs
/// to the insurance fund (SPEC.md §6.1, §8.4). Longs pay when the index rises.
pub fn funding_credit(size: i64, snapshot: i64, cum: i64) -> (i64, u64) {
    let d = cum - snapshot;
    let mag = (abs(size) as u128) * (abs(d) as u128);
    let negative = ((size > 0) & (d > 0)) | ((size < 0) & (d < 0));
    floor_micro(negative, mag)
}

/// Settles a position's accrued funding into collateral and moves its snapshot to `cum`.
/// Returns the new collateral and position and the remainder for the insurance fund.
pub fn settle_funding(collateral: i64, pos: Position, cum: i64) -> (i64, Position, u64) {
    let (credit, dust) = funding_credit(pos.size, pos.funding, cum);
    let c = collateral + credit;
    assert(abs(c) < MAX_COLLATERAL, "collateral out of range");
    (c, Position { size: pos.size, entry: pos.entry, funding: cum }, dust)
}

/// ceil(lots · price · rate / PPM): fees round against the account (SPEC.md §8.6).
pub fn fee(lots: u64, price: u64, rate_ppm: u64) -> u64 {
    let num = (lots as u128) * (price as u128) * (rate_ppm as u128);
    ((num + (PPM as u128) - 1) / (PPM as u128)) as u64
}

/// Equity at the markets' marks, including unrealized funding (SPEC.md §8.3):
/// collateral + Σ_m [size_m · mark_m − entry_m + funding_credit_m].
pub fn equity(acct: AccountPriv, markets: [Market; MARKETS]) -> i64 {
    let mut prices: [u64; MARKETS] = [0; MARKETS];
    let mut cums: [i64; MARKETS] = [0; MARKETS];
    for m in 0..MARKETS {
        prices[m] = markets[m].mark_price;
        cums[m] = markets[m].cum_funding;
    }
    equity_at(acct, prices, cums)
}

/// Equity at the given prices and cumulative funding indices. Desert mode values accounts at the
/// frozen index prices with funding accrued to the freeze (SPEC.md §12).
pub fn equity_at(acct: AccountPriv, prices: [u64; MARKETS], cums: [i64; MARKETS]) -> i64 {
    let mut e = acct.collateral;
    for m in 0..MARKETS {
        let p = acct.positions[m];
        if p.size != 0 {
            let (credit, _) = funding_credit(p.size, p.funding, cums[m]);
            e += p.size * (prices[m] as i64) - p.entry + credit;
        }
    }
    e
}

/// Worst-case size in one market if every open order filled (SPEC.md §8.3).
pub fn worst(size: i64, open_bid: u64, open_ask: u64) -> u64 {
    let a = abs(size + open_bid as i64);
    let b = abs(size - open_ask as i64);
    if a > b { a } else { b }
}

/// Σ_m worst_m · mark_m · imr_m, scaled by PPM.
pub fn initial_margin(acct: AccountPriv, act: Activity, markets: [Market; MARKETS], params: Params) -> u128 {
    let mut im: u128 = 0;
    for m in 0..MARKETS {
        let w = worst(acct.positions[m].size, act.open_bid[m], act.open_ask[m]);
        im += (w as u128) * (markets[m].mark_price as u128) * (params.markets[m].imr_ppm as u128);
    }
    im
}

/// Σ_m |size_m| · mark_m · mmr_m, scaled by PPM.
pub fn maintenance_margin(acct: AccountPriv, markets: [Market; MARKETS], params: Params) -> u128 {
    let mut mm: u128 = 0;
    for m in 0..MARKETS {
        mm += (abs(acct.positions[m].size) as u128) * (markets[m].mark_price as u128)
            * (params.markets[m].mmr_ppm as u128);
    }
    mm
}

/// equity ≥ requirement / PPM.
pub fn covers(equity: i64, requirement: u128) -> bool {
    (equity >= 0) & (((equity as u64) as u128) * (PPM as u128) >= requirement)
}

/// Every market the account is exposed to, by a position or an open order, has an index no older
/// than `max_age`: equity and margin are only as current as the oldest mark they use.
pub fn exposure_fresh(acct: AccountPriv, act: Activity, markets: [Market; MARKETS], max_age: u64, now: u64) -> bool {
    let mut ok = true;
    for m in 0..MARKETS {
        let exposed = (acct.positions[m].size != 0) | (act.open_bid[m] > 0) | (act.open_ask[m] > 0);
        if exposed {
            ok = ok & (markets[m].index_time + max_age >= now);
        }
    }
    ok
}

/// The cumulative funding index stays in range for the positions' arithmetic.
pub fn assert_cum_in_range(cum: i64) {
    assert(abs(cum) < MAX_CUM_FUNDING, "cumulative funding out of range");
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
fn funding() {
    // Long 10 lots, index up 2,500,000 micro-units per lot: pays exactly 25.
    assert(funding_credit(10, 0, 2_500_000) == (-25, 0));
    // Short 10 lots receives 25.
    assert(funding_credit(-10, 0, 2_500_000) == (25, 0));
    // Long 3 lots, up 333,333: owes 0.999999, pays 1 (against the account), 1 micro to insurance.
    assert(funding_credit(3, 0, 333_333) == (-1, 1));
    // Short 3 lots receives 0.999999: gets 0, 999,999 micro to insurance.
    assert(funding_credit(-3, 0, 333_333) == (0, 999_999));
    // The two sides together pay exactly what they receive plus the remainders.
    assert(funding_credit(0, 5, 99) == (0, 0));
}

#[test]
fn fees() {
    assert(fee(10, 2000, 500) == 10);
    assert(fee(1, 2001, 500) == 2); // 1.0005 rounds up
    assert(fee(7, 100, 0) == 0);
}
