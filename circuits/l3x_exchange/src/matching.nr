//! Matching (SPEC.md §6.5, §8.1, §8.2): a taker order against the best resting orders of one market,
//! shared by signed orders (seg_trade) and liquidation closes (seg_liquidate).
use crate::{
    account::{account_leaf, AccountPriv, AccountPub, Activity, blind, enc_commitment, Position},
    book::{Order, order_index, Sibling, SIDE_BID, walk},
    consts::{ACCOUNTS_HEIGHT, BOOK_HEIGHT, DS_ACCT_NODE, DS_ACTV_NODE, MAX_COLLATERAL},
    da::emit_change,
    state::{Market, State},
    trade::{abs, fee, fill, settle_funding},
    tree::update,
};
use l3x_types::Running;

/// One matching step against the best resting order: a fill, or, when the resting order is the
/// taker's own, its cancellation (self-trade prevention, SPEC.md §8.1).
pub struct Fill {
    /// The resting order's leaf index, its price and sequence number, and the order before the step.
    pub index: Field,
    pub price: u32,
    pub seq: u64,
    pub order: Order,
    pub book_path: [Sibling; BOOK_HEIGHT],
    pub maker_pub: AccountPub,
    pub maker_priv: AccountPriv,
    pub maker_acct_path: [Field; ACCOUNTS_HEIGHT],
    pub maker_k_enc: Field,
    pub maker_actv: Activity,
    pub maker_actv_path: [Field; ACCOUNTS_HEIGHT],
}

/// The taker, in memory until its leaf is written: its private part and activity, and whether a
/// fill has already settled its funding in the market.
pub struct Taker {
    pub index: u32,
    pub priv: AccountPriv,
    pub act: Activity,
    pub traded: bool,
}

/// Matches up to `lots` of a taker order on `side` with limit price `limit` against the best
/// opposite orders of market `mid`, in up to F steps (`n` used). Every step proves that its order
/// is the best on its side. A step cancels the taker's own order (self-trade prevention), removes
/// a void order (its owner cancelled all since placing it) or an expired GTT order, or fills:
/// fills execute at the maker's price, settle both sides' funding first, and charge
/// `maker_fee_ppm` and `taker_fee_ppm` into `fees_pending`. Makers' leaves are
/// written and published here; the taker's is left to the caller. Returns the updated state,
/// running values, market and taker, the unfilled lots and the filled notional.
pub fn match_order<let F: u32>(
    state: State,
    running: Running,
    market: Market,
    mid: u32,
    side: Field,
    limit: u64,
    lots: u64,
    taker: Taker,
    fills: [Fill; F],
    n: u32,
    maker_fee_ppm: u64,
    taker_fee_ppm: u64,
    da_nonce: Field,
) -> (State, Running, Market, Taker, u64, u64) {
    let mut st = state;
    let mut r = running;
    let mut mkt = market;
    let mut t = taker;
    let mut remaining = lots;
    let mut notional: u64 = 0;
    assert(n <= F, "too many fills");
    for j in 0..F {
        if j < n {
            let f = fills[j];
            assert(f.order.side != side, "maker must be on the other side");
            assert(f.order.lots > 0, "empty maker order");
            assert(f.index == order_index(f.order.side, f.price, f.seq), "maker order index");
            assert(remaining > 0, "order already filled");
            let mp_price = f.price as u64;
            // Best price-time: no same-side order lies ahead of it (SPEC.md §6.5).
            let before = walk(f.order.leaf(), f.order.ask_lots(), f.order.bid_lots(), f.index, f.book_path);
            assert(before.root == mkt.book_root, "maker order path");
            if side == SIDE_BID {
                assert(before.asks_left == 0, "not the best ask");
                assert(mp_price <= limit, "best ask above the limit");
            } else {
                assert(before.bids_right == 0, "not the best bid");
                assert(mp_price >= limit, "best bid below the limit");
            }
            // The step: the taker's own order goes (self-trade prevention); a void order (its owner
            // cancelled all since placing it) or an expired GTT order goes; anything else fills.
            // Every case ends in one write of the order's leaf, and every case but the first in
            // one write of the maker's activity, which the void test needs proved anyway.
            let own = f.order.account_index == t.index;
            let is_void = !own & (f.order.epoch != f.maker_actv.epoch);
            let is_expired = !own & !is_void & f.order.expired(r.time);
            let is_fill = !own & !is_void & !is_expired;
            let q = if !is_fill {
                0
            } else if remaining < f.order.lots {
                remaining
            } else {
                f.order.lots
            };
            let left = if is_fill {
                Order {
                    side: f.order.side,
                    account_index: f.order.account_index,
                    lots: f.order.lots - q,
                    expiry: f.order.expiry,
                    epoch: f.order.epoch,
                }
            } else {
                Order::empty()
            };
            mkt.book_root = walk(left.leaf(), left.ask_lots(), left.bid_lots(), f.index, f.book_path).root;
            if own {
                // A void order of the taker's no longer counts as open; only a live one shrinks its lots.
                if f.order.epoch == t.act.epoch {
                    if f.order.side == SIDE_BID {
                        t.act.open_bid[mid] -= f.order.lots;
                    } else {
                        t.act.open_ask[mid] -= f.order.lots;
                    }
                    t.act.open_orders -= 1;
                }
            } else {
                // A void order is already gone from its owner's open lots; an expired one takes all
                // its lots out of them, and a fill the lots it fills.
                let mut mact = f.maker_actv;
                let gone = if is_expired { f.order.lots } else { q };
                if f.order.side == SIDE_BID {
                    mact.open_bid[mid] = f.maker_actv.open_bid[mid] - gone;
                } else {
                    mact.open_ask[mid] = f.maker_actv.open_ask[mid] - gone;
                }
                if is_expired | (is_fill & (left.lots == 0)) {
                    mact.open_orders = f.maker_actv.open_orders - 1;
                }
                if is_fill {
                    let (st2, r2, m2) = fill_maker(st, r, mkt, mid, maker_fee_ppm, f, q, da_nonce);
                    st = st2;
                    r = r2;
                    mkt = m2;

                    // Taker side of the fill.
                    if !t.traded {
                        let (c, pos, dust) = settle_funding(t.priv.collateral, t.priv.positions[mid], mkt.cum_funding);
                        t.priv.collateral = c;
                        t.priv.positions[mid] = pos;
                        st.insurance_micro += dust;
                        t.traded = true;
                    }
                    let dm: i64 = if f.order.side == SIDE_BID { q as i64 } else { 0 - (q as i64) };
                    let tpos = t.priv.positions[mid];
                    let (ts, te, tpnl) = fill(tpos.size, tpos.entry, 0 - dm, mp_price as i64);
                    let tfee = fee(q, mp_price, taker_fee_ppm);
                    mkt = shift_oi(mkt, tpos.size, ts);
                    t.priv.positions[mid] = Position { size: ts, entry: te, funding: tpos.funding };
                    t.priv.collateral = t.priv.collateral + tpnl - tfee as i64;
                    assert(abs(t.priv.collateral) < MAX_COLLATERAL, "collateral out of range");
                    st.fees_pending += tfee;
                    notional += q * mp_price;
                    remaining -= q;
                    // The batch's print summary (SPEC.md §8.4, [D1]).
                    mkt = mkt.record_print(r.batch, mp_price, q);
                }
                st.activity_root =
                    update(DS_ACTV_NODE, st.activity_root, f.order.account_index, f.maker_actv.hash(), mact.hash(), f.maker_actv_path);
            }
        }
    }
    assert(mkt.oi_long == mkt.oi_short, "open interest out of balance");
    (st, r, mkt, t, remaining, notional)
}

/// The maker side of a fill of `q` lots at the maker's price: settles the maker's funding, applies
/// the fill and the maker fee, and writes and publishes the maker's leaf. The caller writes the
/// maker's activity.
fn fill_maker(
    state: State,
    running: Running,
    market: Market,
    mid: u32,
    maker_fee_ppm: u64,
    f: Fill,
    q: u64,
    da_nonce: Field,
) -> (State, Running, Market) {
    let mut st = state;
    let mut r = running;
    let mut mkt = market;
    let mi = f.order.account_index;
    let mp_price = f.price as u64;
    let (mc, mpos, mdust) = settle_funding(f.maker_priv.collateral, f.maker_priv.positions[mid], mkt.cum_funding);
    st.insurance_micro += mdust;
    let dm: i64 = if f.order.side == SIDE_BID { q as i64 } else { 0 - (q as i64) };
    let (ms, me, mpnl) = fill(mpos.size, mpos.entry, dm, mp_price as i64);
    let mfee = fee(q, mp_price, maker_fee_ppm);
    mkt = shift_oi(mkt, mpos.size, ms);
    let mut mpriv = f.maker_priv;
    mpriv.positions[mid] = Position { size: ms, entry: me, funding: mpos.funding };
    mpriv.collateral = mc + mpnl - mfee as i64;
    assert(abs(mpriv.collateral) < MAX_COLLATERAL, "collateral out of range");
    st.fees_pending += mfee;
    assert(enc_commitment(f.maker_k_enc) == f.maker_pub.enc_commitment, "maker k_enc");
    mpriv.blind = blind(f.maker_k_enc, mi, da_nonce, r.da_len);
    let maker_leaf = account_leaf(f.maker_pub, mpriv);
    st.accounts_root =
        update(DS_ACCT_NODE, st.accounts_root, mi, account_leaf(f.maker_pub, f.maker_priv), maker_leaf, f.maker_acct_path);
    r = emit_change(r, mi, maker_leaf, mpriv, f.maker_k_enc, da_nonce);
    (st, r, mkt)
}

/// Proves that no opposite order crosses `price` for a taker on `side`, by a walk from the empty
/// slot (side, price, seq): for a bid no ask lies to its left (none at or below `price`), for an
/// ask no bid lies to its right (none at or above `price`). Returns the slot index.
pub fn assert_no_crossing(root: Field, side: Field, price: u64, seq: u64, path: [Sibling; BOOK_HEIGHT]) -> Field {
    let slot = order_index(side, price as u32, seq);
    let probe = walk(0, 0, 0, slot, path);
    assert(probe.root == root, "resting slot path");
    if side == SIDE_BID {
        assert(probe.asks_left == 0, "crossing asks remain");
    } else {
        assert(probe.bids_right == 0, "crossing bids remain");
    }
    slot
}

/// Moves one account's contribution to open interest from `before` to `after`.
pub fn shift_oi(m: Market, before: i64, after: i64) -> Market {
    let mut out = m;
    let long_before = if before > 0 { before as u64 } else { 0 };
    let long_after = if after > 0 { after as u64 } else { 0 };
    let short_before = if before < 0 { (0 - before) as u64 } else { 0 };
    let short_after = if after < 0 { (0 - after) as u64 } else { 0 };
    out.oi_long = m.oi_long + long_after - long_before;
    out.oi_short = m.oi_short + short_after - short_before;
    out
}
