use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, Activity, blind, enc_commitment, Position},
    book::{Order, order_index, replace, Sibling, SIDE_ASK, SIDE_BID},
    consts::{
        ACCOUNTS_HEIGHT, BOOK_HEIGHT, CLASS_INSURANCE, CLASS_USER, DS_ACCT_NODE, DS_ACTV_NODE, DS_LIQ,
        INSURANCE_INDEX, LOG_LIQUIDATE, MARKETS, MAX_COLLATERAL,
    },
    da::{emit_change, open_segment, segment_nonce},
    liq::{
        bankruptcy_price, below, close_limit, closeout_margin, LIQ_ADL, LIQ_CANCEL, LIQ_CLOSE, LIQ_DEFICIT,
        LIQ_TAKEOVER, liq_fee, takeover, upnl,
    },
    matching::{assert_no_crossing, Fill, match_order, shift_oi, Taker},
    params::Params,
    state::State,
    trade::{abs, covers, equity, exposure_fresh, fill, initial_margin, maintenance_margin, settle_funding},
    tree::{merkle_root, update},
};
use l3x_types::{DS_ACTION_LOG, hash::hash, NodeOutput, Running};

/// Liquidation steps per segment, and matching steps per close.
global LQ: u32 = 2;
global F: u32 = 2;

/// One liquidation step. Fields a step's kind does not use are ignored.
struct Step {
    kind: Field,
    /// The liquidated account, its leaf preimage, key and activity.
    account_index: u32,
    market: u32,
    acct_pub: AccountPub,
    acct_priv: AccountPriv,
    acct_k_enc: Field,
    acct_path: [Field; ACCOUNTS_HEIGHT],
    actv: Activity,
    actv_path: [Field; ACCOUNTS_HEIGHT],
    /// Cancel: the order. Close: the lots to close, the matching steps, and the no-crossing probe.
    /// `book_path` is the cancelled order's path or the probe's.
    side: Field,
    price: u32,
    seq: u64,
    cancel_lots: u64,
    cancel_expiry: u64,
    lots: u64,
    n_fills: u32,
    fills: [Fill; F],
    book_path: [Sibling; BOOK_HEIGHT],
    /// Takeover and deficit: the insurance account. ADL: the counterparty.
    other_index: u32,
    other_pub: AccountPub,
    other_priv: AccountPriv,
    other_k_enc: Field,
    other_path: [Field; ACCOUNTS_HEIGHT],
    /// Takeover, deficit, ADL: the insurance account's activity, for its margin. ADL also proves the
    /// insurance account's leaf, read only, to show that it cannot absorb the position.
    ins_actv: Activity,
    ins_actv_path: [Field; ACCOUNTS_HEIGHT],
    ins_pub: AccountPub,
    ins_priv: AccountPriv,
    ins_path: [Field; ACCOUNTS_HEIGHT],
}

/// Liquidation segment (SPEC.md §8.5): operator steps, each justified by a precondition the circuit
/// checks at current marks, with fresh indices wherever the accounts involved are exposed.
///
/// 1. Cancel: equity < MM. Removes one of the account's resting orders.
/// 2. Close: equity < MM and no open orders. The account closes up to its whole position in one
///    market against the book, no worse than the ratio-preserving limit, and pays the liquidation
///    fee (capped at its remaining equity) to the insurance fund. A close that stops short proves
///    that no liquidity is left within the limit.
/// 3. Takeover: equity < CM and no open orders. The insurance account takes over the position with
///    the lowest unrealized PnL at the mark, and must still meet its own IM.
/// 4. Deficit: no positions or orders and negative collateral. The insurance account absorbs it,
///    and must still meet its own IM.
/// 5. ADL: equity < CM and no open orders, and the insurance account could not take the position
///    over without falling below its IM. The position closes against an opposite user position,
///    chosen by the operator (ranking is phase 3), at the bankruptcy price.
fn main(
    vk_tree_root: Field,
    params: Params,
    start: Running,
    state: State,
    n: u32,
    steps: [Step; LQ],
) -> pub NodeOutput {
    assert(start.state == state.trees(), "state opening");
    assert(n <= LQ, "too many liquidation steps");
    let mut end = start;
    for i in 0..LQ {
        if i < n {
            end.action_log = hash([DS_ACTION_LOG, end.action_log, step_message(steps[i]), LOG_LIQUIDATE]);
        }
    }
    let da_nonce = segment_nonce(start, end.action_log);
    end = open_segment(end, da_nonce);
    let mut st = state;
    for i in 0..LQ {
        if i < n {
            let (st2, end2) = apply(st, end, steps[i], da_nonce, params);
            st = st2;
            end = end2;
        }
    }
    end.state = st.trees();
    NodeOutput { config_hash: params.config(vk_tree_root), start, end, receipts_root: 0 }
}

/// What the action log records for a step.
fn step_message(s: Step) -> Field {
    hash(
        [
            DS_LIQ, s.kind, s.account_index as Field, s.market as Field, s.other_index as Field,
            s.lots as Field, s.side, s.price as Field, s.seq as Field,
        ],
    )
}

fn apply(state: State, running: Running, s: Step, da_nonce: Field, params: Params) -> (State, Running) {
    let mut st = state;
    let mut r = running;
    let idx = s.account_index;
    let m = s.market;
    assert(m < MARKETS, "market");
    assert(s.acct_pub.class == CLASS_USER, "only user accounts are liquidated");
    let a0 = s.acct_priv;
    assert(exposure_fresh(a0, s.actv, st.markets, params.max_age, r.time), "index too old for a liquidation");
    let e = equity(a0, st.markets);
    let mm = maintenance_margin(a0, st.markets, params);
    let cm = closeout_margin(a0, st.markets, params);
    let mut a = a0;
    let mut act = s.actv;
    let mut write_a = false;
    let mut other = s.other_priv;
    let mut write_other = false;
    let uses_insurance = (s.kind == LIQ_TAKEOVER) | (s.kind == LIQ_DEFICIT) | (s.kind == LIQ_ADL);

    if s.kind == LIQ_CANCEL {
        assert(below(e, mm), "account is not liquidatable");
        assert(s.cancel_lots > 0, "no such order");
        let o = Order { side: s.side, account_index: idx, lots: s.cancel_lots, expiry: s.cancel_expiry };
        let index = order_index(s.side, s.price, s.seq);
        let (root, _) = replace(st.markets[m].book_root, index, o, Order::empty(), s.book_path);
        st.markets[m].book_root = root;
        if s.side == SIDE_BID {
            act.open_bid[m] = s.actv.open_bid[m] - s.cancel_lots;
        } else {
            act.open_ask[m] = s.actv.open_ask[m] - s.cancel_lots;
        }
        act.open_orders = s.actv.open_orders - 1;
    } else if s.kind == LIQ_CLOSE {
        assert(below(e, mm), "account is not liquidatable");
        assert(s.actv.open_orders == 0, "orders must be cancelled first");
        let pos = a0.positions[m];
        assert(pos.size != 0, "no position in the market");
        assert((s.lots > 0) & (s.lots <= abs(pos.size)), "close size");
        let mp = params.markets[m];
        let side = if pos.size > 0 { SIDE_ASK } else { SIDE_BID };
        let limit = close_limit(pos.size, st.markets[m].mark_price, mp.mmr_ppm, e, mm);
        let taker = Taker { index: idx, priv: a0, act: s.actv, traded: false };
        let (st2, r2, market, t, remaining, notional) =
            match_order(st, r, st.markets[m], m, side, limit, s.lots, taker, s.fills, s.n_fills, mp.maker_fee_ppm, 0, da_nonce);
        st = st2;
        r = r2;
        if remaining > 0 {
            let _ = assert_no_crossing(market.book_root, side, limit, market.next_seq, s.book_path);
        }
        st.markets[m] = market;
        a = t.priv;
        act = t.act;
        // The liquidation fee goes to the insurance fund, capped at what the account has left.
        let left = equity(a, st.markets);
        let cap = if left > 0 { left as u64 } else { 0 };
        let f = liq_fee(notional, mp.liq_fee_ppm);
        let charged = if f < cap { f } else { cap };
        a.collateral -= charged as i64;
        st.insurance_pending += charged;
        write_a = t.traded;
    } else if s.kind == LIQ_TAKEOVER {
        assert(below(e, cm), "account is above close-out margin");
        assert(s.actv.open_orders == 0, "orders must be cancelled first");
        assert(s.other_index == INSURANCE_INDEX, "takeovers go to the insurance account");
        let pos = a0.positions[m];
        assert(pos.size != 0, "no position in the market");
        let u = upnl(pos, st.markets[m]);
        for k in 0..MARKETS {
            if a0.positions[k].size != 0 {
                assert(u <= upnl(a0.positions[k], st.markets[k]), "not the lowest unrealized PnL");
            }
        }
        let (a2, i2, market, dust) = takeover(a0, s.other_priv, st.markets[m], m);
        st.markets[m] = market;
        st.insurance_micro += dust;
        a = a2;
        other = i2;
        write_a = true;
        write_other = true;
    } else if s.kind == LIQ_DEFICIT {
        assert(s.actv.open_orders == 0, "orders must be cancelled first");
        for k in 0..MARKETS {
            assert(a0.positions[k].size == 0, "positions remain");
        }
        assert(a0.collateral < 0, "no deficit");
        assert(s.other_index == INSURANCE_INDEX, "the insurance account absorbs deficits");
        other.collateral = s.other_priv.collateral + a0.collateral;
        a.collateral = 0;
        write_a = true;
        write_other = true;
    } else {
        assert(s.kind == LIQ_ADL, "unknown liquidation step");
        assert(below(e, cm), "account is above close-out margin");
        assert(s.actv.open_orders == 0, "orders must be cancelled first");
        assert(s.other_pub.class == CLASS_USER, "counterparty must be a user account");
        assert(s.other_index != idx, "counterparty is the account");
        let pos = a0.positions[m];
        let cpos = s.other_priv.positions[m];
        assert(pos.size != 0, "no position in the market");
        assert((cpos.size != 0) & ((cpos.size > 0) != (pos.size > 0)), "counterparty not opposite");
        // The backstop is exhausted: a takeover would leave the insurance account below its IM.
        assert(s.ins_pub.class == CLASS_INSURANCE, "insurance account class");
        assert(
            merkle_root(DS_ACCT_NODE, account_leaf(s.ins_pub, s.ins_priv), INSURANCE_INDEX, s.ins_path)
                == st.accounts_root,
            "insurance account path",
        );
        assert(
            exposure_fresh(s.ins_priv, s.ins_actv, st.markets, params.max_age, r.time),
            "index too old for the insurance account",
        );
        let (_, i2, _, _) = takeover(a0, s.ins_priv, st.markets[m], m);
        assert(
            !covers(equity(i2, st.markets), initial_margin(i2, s.ins_actv, st.markets, params)),
            "insurance can absorb",
        );
        // Close the smaller of the two positions at the account's bankruptcy price.
        let market = st.markets[m];
        let q = if abs(pos.size) < abs(cpos.size) { abs(pos.size) } else { abs(cpos.size) };
        let price = bankruptcy_price(pos.size, market.mark_price, e) as i64;
        let (ac, apos, d1) = settle_funding(a0.collateral, pos, market.cum_funding);
        let (cc, cpos2, d2) = settle_funding(s.other_priv.collateral, cpos, market.cum_funding);
        let da: i64 = if pos.size > 0 { 0 - (q as i64) } else { q as i64 };
        let (as_, ae, apnl) = fill(apos.size, apos.entry, da, price);
        let (cs, ce, cpnl) = fill(cpos2.size, cpos2.entry, 0 - da, price);
        st.markets[m] = shift_oi(shift_oi(market, apos.size, as_), cpos2.size, cs);
        st.insurance_micro += d1 + d2;
        a.positions[m] = Position { size: as_, entry: ae, funding: apos.funding };
        a.collateral = ac + apnl;
        other.positions[m] = Position { size: cs, entry: ce, funding: cpos2.funding };
        other.collateral = cc + cpnl;
        assert((abs(a.collateral) < MAX_COLLATERAL) & (abs(other.collateral) < MAX_COLLATERAL), "collateral out of range");
        write_a = true;
        write_other = true;
    }
    assert(st.markets[m].oi_long == st.markets[m].oi_short, "open interest out of balance");

    // The liquidated account's activity (cancel and close change it; the rest prove it).
    st.activity_root = update(DS_ACTV_NODE, st.activity_root, idx, s.actv.hash(), act.hash(), s.actv_path);
    if uses_insurance {
        assert(
            merkle_root(DS_ACTV_NODE, s.ins_actv.hash(), INSURANCE_INDEX, s.ins_actv_path) == st.activity_root,
            "insurance activity path",
        );
        if s.kind != LIQ_ADL {
            // The insurance account must still meet its IM, at fresh indices.
            assert(
                exposure_fresh(other, s.ins_actv, st.markets, params.max_age, r.time),
                "index too old for the insurance account",
            );
            assert(
                covers(equity(other, st.markets), initial_margin(other, s.ins_actv, st.markets, params)),
                "insurance below initial margin",
            );
        }
    }

    // The liquidated account's leaf is always proven; it is written, and published, if it changed.
    let old_leaf = account_leaf(s.acct_pub, a0);
    let mut new_leaf = old_leaf;
    if write_a {
        assert(enc_commitment(s.acct_k_enc) == s.acct_pub.enc_commitment, "account k_enc");
        a.blind = blind(s.acct_k_enc, idx, da_nonce, r.da_len);
        new_leaf = account_leaf(s.acct_pub, a);
    }
    st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, idx, old_leaf, new_leaf, s.acct_path);
    if write_a {
        r = emit_change(r, idx, new_leaf, a, s.acct_k_enc, da_nonce);
    }
    if write_other {
        assert(enc_commitment(s.other_k_enc) == s.other_pub.enc_commitment, "counterparty k_enc");
        other.blind = blind(s.other_k_enc, s.other_index, da_nonce, r.da_len);
        let leaf = account_leaf(s.other_pub, other);
        st.accounts_root = update(
            DS_ACCT_NODE,
            st.accounts_root,
            s.other_index,
            account_leaf(s.other_pub, s.other_priv),
            leaf,
            s.other_path,
        );
        r = emit_change(r, s.other_index, leaf, other, s.other_k_enc, da_nonce);
    }
    (st, r)
}
