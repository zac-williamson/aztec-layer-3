use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, Activity, Key, master_auth_of},
    book::{Order, order_index, replace, RIGHTMOST, Sibling, SIDE_ASK, SIDE_BID},
    consts::{
        ACCOUNTS_HEIGHT, BOOK_HEIGHT, DS_ACCT_NODE, DS_ACTV_NODE, DS_KEY_NODE, KEY_SLOTS, KEYS_HEIGHT, LOG_SIGNED,
        MARKETS, MASTER_KEY, MAX_LOTS, MAX_OPEN_ORDERS, MAX_PRICE, PPM,
    },
    da::{emit_display, open_segment, segment_nonce},
    params::Params,
    sig::{assert_signed, Signature},
    state::State,
    trade::{
        abs, ACTION_PAYLOAD, action_msg, covers, equity, exposure_fresh, initial_margin, KIND_CANCEL, KIND_CANCEL_ALL,
        KIND_MODIFY, KIND_PLACE, TIF_GTC, TIF_GTT, TIF_POST_ONLY, worst,
    },
    tree::{merkle_root, update},
};
use l3x_types::{DS_ACTION_LOG, hash::hash, NodeOutput, receipt_leaf, receipt_node, Running};

/// Signed actions per quote segment, as many as fit 2^20 gates.
global TQ: u32 = 30;
/// The receipts tree's leaves (a power of two, at least TQ) and its depth.
global RL: u32 = 32;
global RD: u32 = 5;

/// One signed action that moves resting orders and no balances. Paths are valid against the roots
/// at the moment the action executes.
struct Action {
    kind: Field,
    account_index: u32,
    /// The signing key: MASTER_KEY, or a session-key slot of the account (SPEC.md §7.2).
    key_id: u32,
    /// The sequencer's number for the action, as on its receipt (SPEC.md §11).
    seq: u64,
    nonce: u64,
    p: [Field; ACTION_PAYLOAD],
    pk_x: Field,
    pk_y: Field,
    sig: Signature,
    /// A session key's slot and its path in the activity's keys tree.
    key: Key,
    key_path: [Field; KEYS_HEIGHT],
    acct_pub: AccountPub,
    acct_priv: AccountPriv,
    acct_path: [Field; ACCOUNTS_HEIGHT],
    actv: Activity,
    actv_path: [Field; ACCOUNTS_HEIGHT],
    /// Place: the path of the resting slot. Cancel and modify: the path of the order. CancelAll:
    /// the path of market 0's rightmost slot, which is never an order.
    book_path: [Sibling; BOOK_HEIGHT],
    /// Cancel and modify: the order's lots, expiry, and display and reduce-only flags.
    order_lots: u64,
    order_expiry: u64,
    order_display: bool,
    order_reduce_only: bool,
}

/// Quote segment (P2.25, SPEC.md §9.2): up to TQ signed actions that move resting orders and no
/// balances, in order: a PlaceOrder that rests without filling (GTC, post-only or GTT), CancelOrder,
/// ModifyOrder and CancelAll, signed by the master key or a session key. They are most of a market
/// maker's traffic, and in `seg_trade` every slot also pays for fills, transfers, withdrawals,
/// triggers and key changes. Here each slot is one signature check, one proof of the account's
/// leaf, one book replace and one activity update:
/// - a placement replaces the empty slot at the market's next sequence number, and the walk from
///   that empty slot proves that no opposite order crosses it (book.nr's index order);
/// - a cancellation or modification replaces the order with nothing or with its reduced size;
/// - CancelAll replaces the rightmost slot of market 0, which never holds an order, by itself.
/// An order that would fill goes to `seg_trade`, which also places, cancels and modifies.
fn main(
    vk_tree_root: Field,
    params: Params,
    start: Running,
    state: State,
    n: u32,
    actions: [Action; TQ],
) -> pub NodeOutput {
    assert(start.state == state.trees(), "state opening");
    assert(n <= TQ, "too many actions");
    let domain = params.domain();
    let mut msgs: [Field; TQ] = [0; TQ];
    let mut end = start;
    for i in 0..TQ {
        if i < n {
            let a = actions[i];
            msgs[i] = action_msg(domain, a.kind, a.account_index, a.key_id, a.nonce, a.p);
            end.action_log = hash([DS_ACTION_LOG, end.action_log, msgs[i], LOG_SIGNED]);
        }
    }
    let da_nonce = segment_nonce(start, end.action_log);
    end = open_segment(end, da_nonce);
    let mut st = state;
    // Receipts (SPEC.md §11): actions execute in the order of their sequence numbers, and each gets a
    // leaf in the segment's receipts tree.
    let mut leaves: [Field; RL] = [0; RL];
    for i in 0..TQ {
        if i < n {
            let a = actions[i];
            assert(a.seq > st.last_seq, "sequence numbers must increase");
            st.last_seq = a.seq;
            leaves[i] = receipt_leaf(a.seq, msgs[i]);
            let (st2, end2) = apply(st, end, a, msgs[i], params);
            st = st2;
            end = end2;
        }
    }
    end.state = st.trees();
    // The receipts tree over RL leaves, empty slots zero.
    let mut width = RL;
    for _ in 0..RD {
        width = width / 2;
        for k in 0..RL / 2 {
            if k < width {
                leaves[k] = receipt_node(leaves[2 * k], leaves[2 * k + 1]);
            }
        }
    }
    NodeOutput { config_hash: params.config(vk_tree_root), start, end, receipts_root: leaves[0] }
}

fn apply(state: State, running: Running, a: Action, msg: Field, params: Params) -> (State, Running) {
    let mut st = state;
    let mut r = running;
    let idx = a.account_index;
    let is_place = a.kind == KIND_PLACE;
    let is_cancel = (a.kind == KIND_CANCEL) | (a.kind == KIND_MODIFY);
    let is_all = a.kind == KIND_CANCEL_ALL;
    assert(is_place | is_cancel | is_all, "not a quote action");

    // Authorization (SPEC.md §7.1, §7.2), with one signature check for either key.
    assert_signed(a.pk_x, a.pk_y, a.sig, msg);
    let mut act = a.actv;
    if a.key_id == MASTER_KEY {
        assert(master_auth_of(a.pk_x, a.pk_y) == a.acct_pub.master_auth, "signing key is not the account's");
        assert(a.actv.nonce + 1 == a.nonce, "nonce");
        act.nonce = a.nonce;
    } else {
        assert(a.key_id < KEY_SLOTS, "key slot");
        assert(merkle_root(DS_KEY_NODE, a.key.leaf(), a.key_id, a.key_path) == a.actv.keys_root, "session key path");
        assert(
            (a.key.pk_x == a.pk_x) & (a.key.pk_y == a.pk_y) & ((a.pk_x != 0) | (a.pk_y != 0)),
            "signing key is not the slot's",
        );
        assert(a.key.nonce + 1 == a.nonce, "nonce");
        assert(r.time <= a.key.expiry, "session key expired");
        assert(a.key.epoch == a.actv.key_epoch, "session key revoked by a rekey");
        if !is_all {
            let m = a.p[0] as u32;
            assert((m as Field == a.p[0]) & (m < MARKETS), "market");
            assert(a.key.allows_market(m), "market not allowed for the session key");
        }
        if is_place {
            let notional = ((a.p[2] as u64) as u128) * ((a.p[3] as u64) as u128);
            assert(notional <= a.key.max_notional as u128, "order above the session key's notional limit");
        }
        let mut k = a.key;
        k.nonce = a.nonce;
        act.keys_root = merkle_root(DS_KEY_NODE, k.leaf(), a.key_id, a.key_path);
    }
    // The account's leaf, which binds the master key and holds the collateral and positions that
    // margin reads; a quote never changes it.
    assert(
        merkle_root(DS_ACCT_NODE, account_leaf(a.acct_pub, a.acct_priv), idx, a.acct_path) == st.accounts_root,
        "account path",
    );

    let mid = a.p[0] as u32;
    assert((mid as Field == a.p[0]) & (mid < MARKETS), "market");
    let mut market = st.markets[mid];
    let side = a.p[1];
    let price = a.p[2] as u64;
    let next_seq = market.next_seq;
    // Placement fields; the asserts hold only for a placement.
    let lots = a.p[3] as u64;
    let tif = a.p[4];
    let reduce_only = a.p[5] == 1;
    let expiry = a.p[6] as u64;
    if is_place {
        let mp = params.markets[mid];
        assert(mp.listed(), "market not listed");
        assert((side == SIDE_BID) | (side == SIDE_ASK), "side");
        assert((price as Field == a.p[2]) & (price > 0) & (price < MAX_PRICE), "price out of range");
        assert((lots as Field == a.p[3]) & (lots > 0) & (lots < MAX_LOTS), "lots out of range");
        assert((tif == TIF_GTC) | (tif == TIF_POST_ONLY) | (tif == TIF_GTT), "a quote rests");
        assert((a.p[5] == 0) | (a.p[5] == 1), "reduce-only flag");
        assert(expiry as Field == a.p[6], "expiry");
        assert((a.p[7] == 0) | (a.p[7] == 1), "display flag");
        assert((tif == TIF_GTT) == (expiry != 0), "only GTT orders expire");
        assert((expiry == 0) | (expiry > r.time), "order already expired");
        if reduce_only {
            let size = a.acct_priv.positions[mid].size;
            assert((size != 0) & ((size > 0) == (side == SIDE_ASK)), "reduce-only order must reduce");
            assert(lots <= abs(size), "reduce-only order larger than the position");
        }
        assert(!market.trigger_pending, "triggers are due in this market");
        let mark = market.mark_price;
        assert(mark > 0, "no mark price");
        let diff = if price > mark { price - mark } else { mark - price };
        assert(diff * PPM <= mark * mp.price_band_ppm, "limit price outside the band");
    }
    // Cancel and modify fields; again the asserts hold only for them.
    let seq = a.p[3] as u64;
    let modify = a.kind == KIND_MODIFY;
    let kept_lots = if modify { a.p[4] as u64 } else { 0 };
    if is_cancel {
        assert((side == SIDE_BID) | (side == SIDE_ASK), "side");
        assert((price as Field == a.p[2]) & (seq as Field == a.p[3]), "order reference");
        assert(a.order_lots > 0, "no such order");
        if modify {
            assert((kept_lots as Field == a.p[4]) & (kept_lots > 0) & (kept_lots < a.order_lots), "a modification only reduces an order");
        }
    }

    // The one book replace.
    let epoch = a.actv.epoch;
    let placed = Order { side, account_index: idx, lots, expiry, epoch, display: a.p[7] == 1, reduce_only };
    let existing = Order {
        side,
        account_index: idx,
        lots: a.order_lots,
        expiry: a.order_expiry,
        epoch,
        display: a.order_display,
        reduce_only: a.order_reduce_only,
    };
    let reduced = Order { side, account_index: idx, lots: kept_lots, expiry: a.order_expiry, epoch, display: a.order_display, reduce_only: a.order_reduce_only };
    let (index, old, new) = if is_place {
        (order_index(side, price as u32, next_seq), Order::empty(), placed)
    } else if is_cancel {
        (order_index(side, price as u32, seq), existing, if modify { reduced } else { Order::empty() })
    } else {
        (RIGHTMOST, Order::empty(), Order::empty())
    };
    let (root, before) = replace(market.book_root, index, old, new, a.book_path);
    market.book_root = root;
    if is_place {
        // Nothing crosses the new order: no ask lies left of a bid's slot, no bid right of an ask's.
        if side == SIDE_BID {
            assert(before.asks_left == 0, "the order would fill");
        } else {
            assert(before.bids_right == 0, "the order would fill");
        }
        market.next_seq = next_seq + 1;
    }
    let display = (is_place & (a.p[7] == 1)) | (is_cancel & a.order_display);
    if display {
        let (dseq, dlots) = if is_place { (next_seq, lots) } else { (seq, kept_lots) };
        r = emit_display(r, mid, side, price as u32, dseq, dlots);
    }
    st.markets[mid] = market;

    // The activity: open lots and orders, or a new order epoch.
    if is_all {
        act = act.cancel_all();
    } else {
        let held = if is_place { if reduce_only { 0 } else { lots } } else if a.order_reduce_only {
            0
        } else {
            a.order_lots - kept_lots
        };
        if is_place {
            if side == SIDE_BID {
                act.open_bid[mid] += held;
            } else {
                act.open_ask[mid] += held;
            }
            act.open_orders += 1;
            assert(act.open_orders <= MAX_OPEN_ORDERS, "too many open orders");
        } else {
            if side == SIDE_BID {
                act.open_bid[mid] -= held;
            } else {
                act.open_ask[mid] -= held;
            }
            if !modify {
                act.open_orders -= 1;
            }
        }
    }
    st.activity_root = update(DS_ACTV_NODE, st.activity_root, idx, a.actv.hash(), act.hash(), a.actv_path);

    // Margin (SPEC.md §8.3): a placement that raises the worst-case size in its market needs fresh
    // indices wherever the account is exposed and equity ≥ IM with the order's lots held open.
    if is_place {
        let size = a.acct_priv.positions[mid].size;
        let worst_before = worst(size, a.actv.open_bid[mid], a.actv.open_ask[mid]);
        let worst_after = worst(size, act.open_bid[mid], act.open_ask[mid]);
        if worst_after > worst_before {
            assert(
                exposure_fresh(a.acct_priv, act, st.markets, params.max_age, r.time),
                "index too old for a risk-increasing order",
            );
            assert(covers(equity(a.acct_priv, st.markets), initial_margin(a.acct_priv, act, st.markets, params)), "insufficient margin");
        }
    }
    (st, r)
}
