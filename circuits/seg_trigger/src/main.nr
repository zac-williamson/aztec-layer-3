use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, Activity, blind, enc_commitment},
    book::{Sibling, SIDE_ASK, SIDE_BID},
    consts::{ACCOUNTS_HEIGHT, BOOK_HEIGHT, DS_ACCT_NODE, DS_ACTV_NODE, DS_FIRE, LOG_TRIGGER, MARKETS, MAX_FEES},
    da::{emit_change, open_segment, segment_nonce},
    matching::{assert_no_crossing, Fill, match_order, Taker},
    params::Params,
    state::State,
    tree::update,
    trigger::{DIR_UP, due, highest_down, lowest_up, Trigger, trigger_index, trigger_walk, TriggerTop},
};
use l3x_types::{DS_ACTION_LOG, hash::hash, NodeOutput, Running};

/// Matching steps per firing.
global F: u32 = 2;

/// Trigger segment (SPEC.md §6.5): the operator fires one trigger due at the market's mark. The
/// trigger must be the next due in its direction (the lowest UP trigger at or below the mark, or
/// the highest DOWN trigger at or above it), so due triggers fire in price-time order.
///
/// A live trigger executes as a reduce-only IOC order at its limit price, paying the taker fee: it
/// fills at most the owner's position on its other side, so it reserves no margin and never
/// increases risk. It stops early only when its matching steps run out, in which case the rest
/// stays in the tree to fire again, or when no liquidity is left within its limit, in which case
/// the rest is dropped. A void trigger (its owner cancelled all since placing it), or one whose
/// owner has nothing left to reduce, is removed without effect. The segment then proves the next
/// trigger due in each direction and clears the market's trigger_pending flag once none is.
fn main(
    vk_tree_root: Field,
    params: Params,
    start: Running,
    state: State,
    market: u32,
    dir: Field,
    price: u32,
    seq: u64,
    trigger: Trigger,
    trigger_path: [Sibling; BOOK_HEIGHT],
    acct_pub: AccountPub,
    acct_priv: AccountPriv,
    k_enc: Field,
    acct_path: [Field; ACCOUNTS_HEIGHT],
    actv: Activity,
    actv_path: [Field; ACCOUNTS_HEIGHT],
    n_fills: u32,
    fills: [Fill; F],
    probe_path: [Sibling; BOOK_HEIGHT],
    up: TriggerTop,
    down: TriggerTop,
) -> pub NodeOutput {
    assert(start.state == state.trees(), "state opening");
    assert(market < MARKETS, "market");
    let mp = params.markets[market];
    assert(mp.listed(), "market not listed");
    let index = trigger_index(dir, price, seq);
    let mut end = start;
    end.action_log = hash([DS_ACTION_LOG, start.action_log, hash([DS_FIRE, market as Field, index]), LOG_TRIGGER]);
    let da_nonce = segment_nonce(start, end.action_log);
    end = open_segment(end, da_nonce);
    let mut st = state;
    let mut mk = st.markets[market];
    let mark = mk.mark_price;

    // The trigger is in the tree, due at the mark, and the next due in its direction.
    assert((trigger.lots > 0) & (trigger.dir == dir), "no such trigger");
    let w = trigger_walk(trigger, index, trigger_path);
    assert(w.root == mk.trigger_root, "trigger path");
    if dir == DIR_UP {
        assert(price as u64 <= mark, "trigger not due");
        assert(w.asks_left == 0, "an earlier trigger is due first");
    } else {
        assert(price as u64 >= mark, "trigger not due");
        assert(w.bids_right == 0, "an earlier trigger is due first");
    }

    // The owner reduces its position on the trigger's other side, by at most the trigger's lots.
    let idx = trigger.account_index;
    let live = trigger.epoch == actv.epoch;
    let pos = acct_priv.positions[market].size;
    let held = if (trigger.side == SIDE_ASK) & (pos > 0) {
        pos as u64
    } else if (trigger.side == SIDE_BID) & (pos < 0) {
        (0 - pos) as u64
    } else {
        0
    };
    let q = if !live {
        0
    } else if trigger.lots < held {
        trigger.lots
    } else {
        held
    };
    let mut a = acct_priv;
    let mut act = actv;
    let mut traded = false;
    let mut left: u64 = 0;
    if q > 0 {
        let taker = Taker { index: idx, priv: a, act, traded: false };
        let (st2, r2, m2, t, remaining, _) = match_order(
            st,
            end,
            mk,
            market,
            trigger.side,
            trigger.limit,
            q,
            taker,
            fills,
            n_fills,
            mp.maker_fee_ppm,
            mp.taker_fee_ppm,
            da_nonce,
        );
        st = st2;
        end = r2;
        mk = m2;
        a = t.priv;
        act = t.act;
        traded = t.traded;
        if remaining > 0 {
            if n_fills < F {
                let _ = assert_no_crossing(mk.book_root, trigger.side, trigger.limit, mk.next_seq, probe_path);
            } else {
                left = remaining;
            }
        }
        assert(st.fees_pending < MAX_FEES, "fees out of range");
    } else {
        assert(n_fills == 0, "nothing to fill");
    }

    // The trigger leaves the tree, or keeps the lots its steps did not reach.
    let mut kept = trigger;
    kept.lots = left;
    mk.trigger_root = trigger_walk(kept, index, trigger_path).root;
    mk.trigger_pending = due(lowest_up(mk.trigger_root, up), highest_down(mk.trigger_root, down), mark);
    st.markets[market] = mk;

    // The owner's activity and account; its leaf is always proven, and written only if it traded.
    st.activity_root = update(DS_ACTV_NODE, st.activity_root, idx, actv.hash(), act.hash(), actv_path);
    let old_leaf = account_leaf(acct_pub, acct_priv);
    let mut new_leaf = old_leaf;
    if traded {
        assert(enc_commitment(k_enc) == acct_pub.enc_commitment, "k_enc does not open the commitment");
        a.blind = blind(k_enc, idx, da_nonce, end.da_len);
        new_leaf = account_leaf(acct_pub, a);
    }
    st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, idx, old_leaf, new_leaf, acct_path);
    if traded {
        end = emit_change(end, idx, new_leaf, a, k_enc, da_nonce);
    }
    end.state = st.trees();
    NodeOutput { config_hash: params.config(vk_tree_root), start, end, receipts_root: 0 }
}
