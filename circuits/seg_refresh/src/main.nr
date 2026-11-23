use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, Activity, blind, enc_commitment},
    book::{Order, order_index, replace, Sibling, SIDE_BID},
    consts::{
        ACCOUNTS_HEIGHT, BOOK_HEIGHT, CLASS_FEE, CLASS_INSURANCE, CLASS_USER, DS_ACCT_NODE, DS_ACTV_NODE, DS_CLEAN,
        DS_TIER, FEE_INDEX, FEE_TIERS, INSURANCE_INDEX, LOG_CLEANUP, LOG_TIER, MARKETS, MAX_COLLATERAL, MICRO,
        PROTOCOL_ACCOUNTS, TAG_REFRESH,
    },
    da::{emit_change, emit_display, emit_full, open_segment, segment_nonce},
    liq::below,
    params::Params,
    state::State,
    trade::{abs, equity, exposure_fresh, maintenance_margin},
    tree::{merkle_root, update},
};
use l3x_types::{DS_ACTION_LOG, hash::hash, NodeOutput, Running};

global RF: u32 = 4;
/// Order removals per maintenance segment.
global CL: u32 = 4;
/// Fee-tier changes per maintenance segment.
global TC: u32 = 2;

/// The operator sets an account's fee tier (SPEC.md §8.6).
struct TierChange {
    account_index: u32,
    tier: u32,
    actv: Activity,
    actv_path: [Field; ACCOUNTS_HEIGHT],
}

/// A resting order that is void or expired, and its owner's activity, which says which.
struct Removal {
    market: u32,
    price: u32,
    seq: u64,
    order: Order,
    path: [Sibling; BOOK_HEIGHT],
    owner_actv: Activity,
    owner_actv_path: [Field; ACCOUNTS_HEIGHT],
}

struct Item {
    pub_part: AccountPub,
    priv_part: AccountPriv,
    path: [Field; ACCOUNTS_HEIGHT],
    k_enc: Field,
    /// Refresh: the account's activity, for the risk check.
    actv: Activity,
    actv_path: [Field; ACCOUNTS_HEIGHT],
}

/// Maintenance segment (SPEC.md §6.5, §8.6, §9.5).
///
/// It first removes up to CL orders that can never fill: void orders, whose owner has cancelled all
/// since placing them, and expired GTT orders, whose lots leave the owner's open lots. Each removal
/// is an operator action in the action log. A tick may use only a live order as its top of book
/// (seg_block), so the operator removes dead orders from the top of a book before ticking it.
///
/// It then sets up to TC accounts' fee tiers, each an operator action in the action log. The tier
/// is the operator's choice (SPEC.md §8.6, not proven); the circuit checks only that it exists.
///
/// With `sweep`, it first credits the fees collected so far to the fee account, and the liquidation
/// fees and whole units of funding remainders to the insurance account, which keeps those balances
/// out of every trade's witness (SPEC.md §8.8).
///
/// It then republishes the next `n` accounts after refresh_cursor, in index order and wrapping
/// around, each as its unchanged leaf with the full opening encrypted under a fresh keystream, and
/// records the L3 time whenever the cursor wraps. The Bridge requires every batch to end within the
/// refresh window W of the last wrap, so the DA of the last W rebuilds every account, active or not.
///
/// The refresh is also the risk sweep (SPEC.md §8.7): a user account whose exposure has fresh
/// indices is refreshed only if it is not due for liquidation, so the operator must liquidate it
/// first, and every due liquidation happens within W. A stale index exempts the account, so an
/// oracle outage cannot halt the refresh.
fn main(
    vk_tree_root: Field,
    params: Params,
    start: Running,
    state: State,
    n_clean: u32,
    removals: [Removal; CL],
    n_tiers: u32,
    tiers: [TierChange; TC],
    sweep: bool,
    protocol: [Item; PROTOCOL_ACCOUNTS],
    n: u32,
    items: [Item; RF],
) -> pub NodeOutput {
    assert(start.state == state.trees(), "state opening");
    assert(n <= RF, "too many refresh entries");
    assert(n <= state.num_accounts, "more refresh entries than accounts");
    assert(n_clean <= CL, "too many removals");
    let mut st = state;
    let mut end = start;
    for i in 0..CL {
        if i < n_clean {
            let c = removals[i];
            assert(c.market < MARKETS, "market");
            assert(c.order.lots > 0, "no such order");
            let owner = c.order.account_index;
            let is_void = c.order.epoch != c.owner_actv.epoch;
            let is_expired = !is_void & c.order.expired(end.time);
            assert(is_void | is_expired, "order is live");
            let index = order_index(c.order.side, c.price, c.seq);
            let (root, _) = replace(st.markets[c.market].book_root, index, c.order, Order::empty(), c.path);
            st.markets[c.market].book_root = root;
            let mut act = c.owner_actv;
            if is_expired {
                // A reduce-only order holds no open lots, only its place in the count (P2.21).
                if !c.order.reduce_only {
                    if c.order.side == SIDE_BID {
                        act.open_bid[c.market] = c.owner_actv.open_bid[c.market] - c.order.lots;
                    } else {
                        act.open_ask[c.market] = c.owner_actv.open_ask[c.market] - c.order.lots;
                    }
                }
                act.open_orders = c.owner_actv.open_orders - 1;
            }
            st.activity_root = update(DS_ACTV_NODE, st.activity_root, owner, c.owner_actv.hash(), act.hash(), c.owner_actv_path);
            let msg = hash([DS_CLEAN, c.market as Field, c.order.side, c.price as Field, c.seq as Field]);
            end.action_log = hash([DS_ACTION_LOG, end.action_log, msg, LOG_CLEANUP]);
        }
    }
    assert(n_tiers <= TC, "too many tier changes");
    for i in 0..TC {
        if i < n_tiers {
            let c = tiers[i];
            assert(c.tier < FEE_TIERS, "fee tier");
            let mut act = c.actv;
            act.fee_tier = c.tier;
            // Only an account has a non-empty activity leaf, so the account exists.
            st.activity_root =
                update(DS_ACTV_NODE, st.activity_root, c.account_index, c.actv.hash(), act.hash(), c.actv_path);
            let msg = hash([DS_TIER, c.account_index as Field, c.tier as Field]);
            end.action_log = hash([DS_ACTION_LOG, end.action_log, msg, LOG_TIER]);
        }
    }
    let da_nonce = segment_nonce(start, end.action_log);
    end = open_segment(end, da_nonce);
    // A removed displayed order leaves the displayed book (SPEC.md §8.4, [D1]).
    for i in 0..CL {
        if (i < n_clean) & removals[i].order.display {
            let c = removals[i];
            end = emit_display(end, c.market, c.order.side, c.price, c.seq, 0);
        }
    }
    if sweep {
        for k in 0..PROTOCOL_ACCOUNTS {
            let w = protocol[k];
            let (idx, class, credit) = if k == INSURANCE_INDEX {
                (INSURANCE_INDEX, CLASS_INSURANCE, st.insurance_pending + st.insurance_micro / MICRO)
            } else {
                (FEE_INDEX, CLASS_FEE, st.fees_pending)
            };
            assert(w.pub_part.class == class, "protocol account class");
            assert(enc_commitment(w.k_enc) == w.pub_part.enc_commitment, "k_enc does not open the commitment");
            let mut p = w.priv_part;
            p.collateral = w.priv_part.collateral + credit as i64;
            assert(abs(p.collateral) < MAX_COLLATERAL, "collateral out of range");
            p.blind = blind(w.k_enc, idx, da_nonce, end.da_len);
            let leaf = account_leaf(w.pub_part, p);
            st.accounts_root =
                update(DS_ACCT_NODE, st.accounts_root, idx, account_leaf(w.pub_part, w.priv_part), leaf, w.path);
            end = emit_change(end, idx, leaf, p, w.k_enc, da_nonce);
        }
        st.insurance_micro = st.insurance_micro % MICRO;
        st.insurance_pending = 0;
        st.fees_pending = 0;
    }
    let mut cursor = st.refresh_cursor;
    for i in 0..RF {
        if i < n {
            let w = items[i];
            let leaf = account_leaf(w.pub_part, w.priv_part);
            assert(merkle_root(DS_ACCT_NODE, leaf, cursor, w.path) == st.accounts_root, "account path");
            if w.pub_part.class == CLASS_USER {
                assert(merkle_root(DS_ACTV_NODE, w.actv.hash(), cursor, w.actv_path) == st.activity_root, "activity path");
                if exposure_fresh(w.priv_part, w.actv, st.markets, params.max_age, end.time) {
                    let due = below(equity(w.priv_part, st.markets), maintenance_margin(w.priv_part, st.markets, params));
                    assert(!due, "account is due for liquidation");
                }
            }
            assert(enc_commitment(w.k_enc) == w.pub_part.enc_commitment, "k_enc does not open the commitment");
            end = emit_full(end, TAG_REFRESH, cursor, leaf, w.pub_part, w.priv_part, w.k_enc, da_nonce);
            if cursor + 1 == st.num_accounts {
                // The cycle is complete: every account has a refresh entry since the last wrap, and
                // the next cycle starts now.
                cursor = 0;
                st.cycle_start = end.time;
            } else {
                cursor += 1;
            }
        }
    }
    st.refresh_cursor = cursor;
    end.state = st.trees();
    NodeOutput { config_hash: params.config(vk_tree_root), start, end, receipts_root: 0 }
}
