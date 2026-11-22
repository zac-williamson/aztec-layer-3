use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, Activity, blind, enc_commitment, Key, master_auth_of},
    book::{Order, order_index, replace, Sibling, SIDE_ASK, SIDE_BID, walk},
    consts::{
        ACCOUNTS_HEIGHT, BOOK_HEIGHT, CLASS_USER, DS_ACCT_NODE, DS_ACTV_NODE, DS_KEY_NODE, KEY_SLOTS,
        KEYS_HEIGHT, LOG_SIGNED, MARKETS, MASTER_KEY, MAX_COLLATERAL, MAX_FEES, MAX_LOTS, MAX_OPEN_ORDERS,
        MAX_PRICE, PPM,
    },
    da::{emit_change, open_segment, segment_nonce},
    matching::{assert_no_crossing, Fill, match_order, Taker},
    params::Params,
    sig::{assert_signed, Signature},
    state::State,
    trade::{
        abs, ACTION_PAYLOAD, action_msg, covers, credit, debit, equity, exposure_fresh, initial_margin,
        KIND_ADD_KEY, KIND_CANCEL, KIND_CANCEL_ALL, KIND_MODIFY, KIND_PLACE, KIND_REVOKE_KEY, KIND_TRANSFER,
        KIND_WITHDRAW,
        TIF_FOK, TIF_GTC, TIF_GTT, TIF_IOC, TIF_POST_ONLY, withdraw as withdraw_collateral, worst,
        write_key_slot,
    },
    tree::{merkle_root, update},
};
use l3x_types::{DS_ACTION_LOG, hash::hash, NodeOutput, receipt_leaf, receipt_node, Running};

/// Signed actions per segment, and matching steps per order.
global TA: u32 = 2;
global F: u32 = 2;

/// One signed action. Paths are valid against the roots at the moment each leaf is written.
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
    /// A session key's slot and its path in the activity's keys tree; for AddKey and RevokeKey,
    /// the target slot's current key.
    key: Key,
    key_path: [Field; KEYS_HEIGHT],
    taker_pub: AccountPub,
    taker_priv: AccountPriv,
    taker_k_enc: Field,
    taker_acct_path: [Field; ACCOUNTS_HEIGHT],
    taker_actv: Activity,
    taker_actv_path: [Field; ACCOUNTS_HEIGHT],
    n_fills: u32,
    fills: [Fill; F],
    /// Place: the path of the resting slot (GTC, post-only) or of the no-crossing probe (IOC
    /// remainder). Cancel and modify: the path of the order.
    rest_path: [Sibling; BOOK_HEIGHT],
    /// Cancel and modify: the order's remaining lots and expiry.
    cancel_lots: u64,
    cancel_expiry: u64,
    /// Transfer: the destination account, its key and its path after the source's debit.
    dest_pub: AccountPub,
    dest_priv: AccountPriv,
    dest_k_enc: Field,
    dest_acct_path: [Field; ACCOUNTS_HEIGHT],
}

/// Trade segment (SPEC.md §6.5, §7.2, §8.1–§8.6, §10.4): executes up to TA signed PlaceOrder,
/// CancelOrder, ModifyOrder, CancelAll, Withdraw, Transfer, AddKey and RevokeKey actions in order,
/// in any listed market. The master key may sign anything; a session key only places, cancels,
/// modifies and cancels all, within its markets, notional and expiry. An order matches the best
/// opposite orders, up to F steps, at the makers' prices, settling both sides' funding and
/// charging maker and taker fees; then its remainder rests (GTC, post-only) or cancels (IOC) once
/// no crossing liquidity is left. Only accounts whose balances change get DA entries: quoting and
/// cancelling change the unpublished activity tree and the book, never a published leaf (§4).
fn main(
    vk_tree_root: Field,
    params: Params,
    start: Running,
    state: State,
    n: u32,
    actions: [Action; TA],
) -> pub NodeOutput {
    assert(start.state == state.trees(), "state opening");
    assert(n <= TA, "too many actions");
    let domain = params.domain();
    let mut end = start;
    for i in 0..TA {
        if i < n {
            let a = actions[i];
            let msg = action_msg(domain, a.kind, a.account_index, a.key_id, a.nonce, a.p);
            end.action_log = hash([DS_ACTION_LOG, end.action_log, msg, LOG_SIGNED]);
        }
    }
    let da_nonce = segment_nonce(start, end.action_log);
    end = open_segment(end, da_nonce);
    let mut st = state;
    // Receipts (SPEC.md §11): actions execute in the order of their sequence numbers, and each
    // gets a leaf in the segment's receipts root, so a receipted action that was dropped or
    // reordered has no leaf the operator can show.
    let mut leaves: [Field; TA] = [0; TA];
    for i in 0..TA {
        if i < n {
            let a = actions[i];
            assert(a.seq > st.last_seq, "sequence numbers must increase");
            st.last_seq = a.seq;
            leaves[i] = receipt_leaf(a.seq, action_msg(domain, a.kind, a.account_index, a.key_id, a.nonce, a.p));
            let (st2, end2) = apply(st, end, a, da_nonce, params, domain);
            st = st2;
            end = end2;
        }
    }
    end.state = st.trees();
    NodeOutput { config_hash: params.config(vk_tree_root), start, end, receipts_root: receipt_node(leaves[0], leaves[1]) }
}

fn apply(state: State, running: Running, a: Action, da_nonce: Field, params: Params, domain: Field) -> (State, Running) {
    // Authorization (SPEC.md §7.1, §7.2). The master key is bound to the account by its leaf, which
    // every action proves against the accounts root; a session key by its slot in the activity's
    // keys tree. Either way the signing key's nonce advances by one.
    let msg = action_msg(domain, a.kind, a.account_index, a.key_id, a.nonce, a.p);
    let mut act = a.taker_actv;
    if a.key_id == MASTER_KEY {
        assert(master_auth_of(a.pk_x, a.pk_y) == a.taker_pub.master_auth, "signing key is not the account's");
        assert_signed(a.pk_x, a.pk_y, a.sig, msg);
        assert(a.taker_actv.nonce + 1 == a.nonce, "nonce");
        act.nonce = a.nonce;
    } else {
        assert(a.key_id < KEY_SLOTS, "key slot");
        assert(
            merkle_root(DS_KEY_NODE, a.key.leaf(), a.key_id, a.key_path) == a.taker_actv.keys_root,
            "session key path",
        );
        assert(
            (a.key.pk_x == a.pk_x) & (a.key.pk_y == a.pk_y) & ((a.pk_x != 0) | (a.pk_y != 0)),
            "signing key is not the slot's",
        );
        assert_signed(a.pk_x, a.pk_y, a.sig, msg);
        assert(a.key.nonce + 1 == a.nonce, "nonce");
        assert(running.time <= a.key.expiry, "session key expired");
        assert(
            (a.kind == KIND_PLACE) | (a.kind == KIND_CANCEL) | (a.kind == KIND_MODIFY) | (a.kind == KIND_CANCEL_ALL),
            "session keys only place, cancel, modify and cancel all",
        );
        // CancelAll only reduces risk, so any session key may send it; the others name a market.
        if a.kind != KIND_CANCEL_ALL {
            let m = a.p[0] as u32;
            assert((m as Field == a.p[0]) & (m < MARKETS), "market");
            assert(a.key.allows_market(m), "market not allowed for the session key");
        }
        if a.kind == KIND_PLACE {
            let notional = ((a.p[2] as u64) as u128) * ((a.p[3] as u64) as u128);
            assert(notional <= a.key.max_notional as u128, "order above the session key's notional limit");
        }
        let mut k = a.key;
        k.nonce = a.nonce;
        act.keys_root = merkle_root(DS_KEY_NODE, k.leaf(), a.key_id, a.key_path);
    }
    if a.kind == KIND_PLACE {
        place(state, running, a, act, da_nonce, params)
    } else if (a.kind == KIND_CANCEL) | (a.kind == KIND_MODIFY) {
        (cancel(state, a, act), running)
    } else if a.kind == KIND_WITHDRAW {
        withdraw(state, running, a, act, da_nonce, params)
    } else if a.kind == KIND_TRANSFER {
        transfer(state, running, a, act, da_nonce, params)
    } else if a.kind == KIND_CANCEL_ALL {
        (cancel_all(state, a, act), running)
    } else {
        assert((a.kind == KIND_ADD_KEY) | (a.kind == KIND_REVOKE_KEY), "unknown action kind");
        (set_key(state, a, act), running)
    }
}

/// AddKey and RevokeKey (SPEC.md §7.2), master key only: writes a session-key slot, keeping the
/// slot's nonce so a replaced key's signatures can never be replayed.
fn set_key(state: State, a: Action, act_auth: Activity) -> State {
    let mut st = state;
    let idx = a.account_index;
    let leaf = account_leaf(a.taker_pub, a.taker_priv);
    st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, idx, leaf, leaf, a.taker_acct_path);
    let mut act = act_auth;
    act.keys_root = write_key_slot(act_auth.keys_root, a.key, a.key_path, a.kind == KIND_ADD_KEY, a.p);
    st.activity_root = update(DS_ACTV_NODE, st.activity_root, idx, a.taker_actv.hash(), act.hash(), a.taker_actv_path);
    st
}

/// Withdraw (SPEC.md §8.3, §10.4): debits collateral, keeps equity − amount ≥ IM, and appends a
/// record the vault pays to `recipient` once the batch settles.
fn withdraw(state: State, running: Running, a: Action, act: Activity, da_nonce: Field, params: Params) -> (State, Running) {
    let mut st = state;
    let idx = a.account_index;
    let (new_leaf, r) = withdraw_collateral(
        running,
        st.markets,
        params,
        idx,
        a.taker_pub,
        a.taker_priv,
        a.taker_actv,
        a.taker_k_enc,
        a.p,
        da_nonce,
    );
    st.accounts_root = update(
        DS_ACCT_NODE,
        st.accounts_root,
        idx,
        account_leaf(a.taker_pub, a.taker_priv),
        new_leaf,
        a.taker_acct_path,
    );
    st.activity_root = update(DS_ACTV_NODE, st.activity_root, idx, a.taker_actv.hash(), act.hash(), a.taker_actv_path);
    (st, r)
}

/// Transfer (SPEC.md §7.3), p = (amount, destination, …), master key only: debits `amount` under
/// the withdrawal rules and credits it to another user account. Both accounts are republished;
/// the amount stays hidden (§4).
fn transfer(state: State, running: Running, a: Action, act: Activity, da_nonce: Field, params: Params) -> (State, Running) {
    let mut st = state;
    let idx = a.account_index;
    let amount = a.p[0] as u64;
    assert((amount as Field == a.p[0]) & (amount > 0) & (amount < MAX_COLLATERAL), "transfer amount out of range");
    let dest = a.p[1] as u32;
    assert((dest as Field == a.p[1]) & (dest < st.num_accounts), "no such account");
    assert(dest != idx, "transfer to the same account");
    // Protocol accounts change only through the sweep and liquidation, never through a trade.
    assert(a.dest_pub.class == CLASS_USER, "transfers go to user accounts");
    let (leaf, r1) = debit(running, st.markets, params, idx, a.taker_pub, a.taker_priv, a.taker_actv, a.taker_k_enc, amount, da_nonce);
    st.accounts_root =
        update(DS_ACCT_NODE, st.accounts_root, idx, account_leaf(a.taker_pub, a.taker_priv), leaf, a.taker_acct_path);
    let (dest_leaf, r2) = credit(r1, dest, a.dest_pub, a.dest_priv, a.dest_k_enc, amount, da_nonce);
    st.accounts_root =
        update(DS_ACCT_NODE, st.accounts_root, dest, account_leaf(a.dest_pub, a.dest_priv), dest_leaf, a.dest_acct_path);
    st.activity_root = update(DS_ACTV_NODE, st.activity_root, idx, a.taker_actv.hash(), act.hash(), a.taker_actv_path);
    (st, r2)
}

fn place(state: State, running: Running, a: Action, act_auth: Activity, da_nonce: Field, params: Params) -> (State, Running) {
    let mut st = state;
    let mut r = running;
    let idx = a.account_index;
    let mid = a.p[0] as u32;
    let side = a.p[1];
    let price = a.p[2] as u64;
    let lots = a.p[3] as u64;
    let tif = a.p[4];
    let reduce_only = a.p[5];
    assert((mid as Field == a.p[0]) & (mid < MARKETS), "market");
    let mp = params.markets[mid];
    assert(mp.listed(), "market not listed");
    assert((side == SIDE_BID) | (side == SIDE_ASK), "side");
    assert((price as Field == a.p[2]) & (price > 0) & (price < MAX_PRICE), "price out of range");
    assert((lots as Field == a.p[3]) & (lots > 0) & (lots < MAX_LOTS), "lots out of range");
    assert(
        (tif == TIF_GTC) | (tif == TIF_IOC) | (tif == TIF_FOK) | (tif == TIF_POST_ONLY) | (tif == TIF_GTT),
        "time in force",
    );
    assert((reduce_only == 0) | (reduce_only == 1), "reduce-only flag");
    let rests = (tif == TIF_GTC) | (tif == TIF_POST_ONLY) | (tif == TIF_GTT);
    // GTT (SPEC.md §6.5): a resting order with an expiry in the future; other orders have none.
    let expiry = a.p[6] as u64;
    assert((expiry as Field == a.p[6]) & (a.p[7] == 0), "expiry");
    assert((tif == TIF_GTT) == (expiry != 0), "only GTT orders expire");
    assert((expiry == 0) | (expiry > r.time), "order already expired");
    // P2: reduce-only orders do not rest, so a later position change never has to trim them.
    assert((reduce_only == 0) | !rests, "reduce-only orders cannot rest");
    if tif == TIF_POST_ONLY {
        assert(a.n_fills == 0, "post-only order would take liquidity");
    }
    let mut market = st.markets[mid];
    let mark = market.mark_price;
    assert(mark > 0, "no mark price");
    let diff = if price > mark { price - mark } else { mark - price };
    assert(diff * PPM <= mark * mp.price_band_ppm, "limit price outside the band");

    // The taker's account and activity, in memory until the end of the action. Funding in this
    // market is settled before its position changes.
    let size_before = a.taker_priv.positions[mid].size;
    let taker = Taker { index: idx, priv: a.taker_priv, act: act_auth, traded: false };
    let (st2, r2, m2, t, remaining, _) = match_order(
        st,
        r,
        market,
        mid,
        side,
        price,
        lots,
        taker,
        a.fills,
        a.n_fills,
        mp.maker_fee_ppm,
        mp.taker_fee_ppm,
        da_nonce,
    );
    st = st2;
    r = r2;
    market = m2;
    let mut taker = t.priv;
    let mut act = t.act;
    let traded = t.traded;
    assert(st.fees_pending < MAX_FEES, "fees out of range");
    if tif == TIF_FOK {
        assert(remaining == 0, "fill-or-kill order not filled");
    }
    if reduce_only == 1 {
        let filled = lots - remaining;
        assert((size_before != 0) & ((size_before > 0) == (side == SIDE_ASK)), "reduce-only order must reduce");
        assert(filled <= abs(size_before), "reduce-only order would flip the position");
    }

    // The remainder rests (GTC, post-only) or cancels (IOC), and either way no crossing liquidity
    // is left.
    if remaining > 0 {
        let seq = market.next_seq;
        let slot = assert_no_crossing(market.book_root, side, price, seq, a.rest_path);
        if rests {
            let o = Order { side, account_index: idx, lots: remaining, expiry, epoch: act.epoch };
            market.book_root = walk(o.leaf(), o.ask_lots(), o.bid_lots(), slot, a.rest_path).root;
            market.next_seq = seq + 1;
            if side == SIDE_BID {
                act.open_bid[mid] += remaining;
            } else {
                act.open_ask[mid] += remaining;
            }
            act.open_orders += 1;
            assert(act.open_orders <= MAX_OPEN_ORDERS, "too many open orders");
        }
    }
    st.markets[mid] = market;

    // Taker account. Its leaf is always proven, which authenticates the signing key above; it is
    // written, and published, only if a fill changed it.
    let old_leaf = account_leaf(a.taker_pub, a.taker_priv);
    let mut new_leaf = old_leaf;
    if traded {
        assert(enc_commitment(a.taker_k_enc) == a.taker_pub.enc_commitment, "taker k_enc");
        taker.blind = blind(a.taker_k_enc, idx, da_nonce, r.da_len);
        new_leaf = account_leaf(a.taker_pub, taker);
    }
    st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, idx, old_leaf, new_leaf, a.taker_acct_path);
    if traded {
        r = emit_change(r, idx, new_leaf, taker, a.taker_k_enc, da_nonce);
    }
    st.activity_root = update(DS_ACTV_NODE, st.activity_root, idx, a.taker_actv.hash(), act.hash(), a.taker_actv_path);

    // Margin (SPEC.md §8.3): an action that increases the worst-case size in its market needs
    // fresh indices wherever the account is exposed and equity ≥ IM afterwards.
    let worst_before = worst(size_before, a.taker_actv.open_bid[mid], a.taker_actv.open_ask[mid]);
    let worst_after = worst(taker.positions[mid].size, act.open_bid[mid], act.open_ask[mid]);
    if worst_after > worst_before {
        assert(
            exposure_fresh(taker, act, st.markets, params.max_age, r.time),
            "index too old for a risk-increasing order",
        );
        assert(covers(equity(taker, st.markets), initial_margin(taker, act, st.markets, params)), "insufficient margin");
    }
    (st, r)
}

/// CancelAll (SPEC.md §6.5, §7.3): advances the account's order epoch, which voids every resting
/// order it placed before, in every market, at once. Its open lots and order count drop to zero;
/// matching removes the void orders when it meets them, as it removes expired GTT orders.
fn cancel_all(state: State, a: Action, act_auth: Activity) -> State {
    let mut st = state;
    let leaf = account_leaf(a.taker_pub, a.taker_priv);
    st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, a.account_index, leaf, leaf, a.taker_acct_path);
    let mut act = act_auth;
    act.epoch = act_auth.epoch + 1;
    act.open_orders = 0;
    act.open_bid = [0; MARKETS];
    act.open_ask = [0; MARKETS];
    st.activity_root =
        update(DS_ACTV_NODE, st.activity_root, a.account_index, a.taker_actv.hash(), act.hash(), a.taker_actv_path);
    st
}

/// CancelOrder, p = (market, side, price, seq), and ModifyOrder, p = (market, side, price, seq,
/// lots): removes the account's resting order, or reduces it in place to `lots`, which keeps its
/// place in the queue (SPEC.md §7.3). A modification that would add lots or move the price is a
/// cancellation and a new order.
fn cancel(state: State, a: Action, act_auth: Activity) -> State {
    let mut st = state;
    // The account's leaf authenticates the signing key.
    let leaf = account_leaf(a.taker_pub, a.taker_priv);
    st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, a.account_index, leaf, leaf, a.taker_acct_path);
    let mid = a.p[0] as u32;
    let side = a.p[1];
    let price = a.p[2] as u32;
    let seq = a.p[3] as u64;
    assert((mid as Field == a.p[0]) & (mid < MARKETS), "market");
    assert((side == SIDE_BID) | (side == SIDE_ASK), "side");
    assert((price as Field == a.p[2]) & (seq as Field == a.p[3]), "order reference");
    assert(a.cancel_lots > 0, "no such order");
    let modify = a.kind == KIND_MODIFY;
    let lots = if modify { a.p[4] as u64 } else { 0 };
    if modify {
        assert((lots as Field == a.p[4]) & (lots > 0) & (lots < a.cancel_lots), "a modification only reduces an order");
    }
    let index = order_index(side, price, seq);
    // Only a live order can be cancelled or modified: a void one is already gone from the account's
    // open lots, and its leaf records an earlier epoch.
    let epoch = a.taker_actv.epoch;
    let o = Order { side, account_index: a.account_index, lots: a.cancel_lots, expiry: a.cancel_expiry, epoch };
    let kept = if modify {
        Order { side, account_index: a.account_index, lots, expiry: a.cancel_expiry, epoch }
    } else {
        Order::empty()
    };
    let (root, _) = replace(st.markets[mid].book_root, index, o, kept, a.rest_path);
    st.markets[mid].book_root = root;
    let mut act = act_auth;
    let removed = a.cancel_lots - lots;
    if side == SIDE_BID {
        act.open_bid[mid] = a.taker_actv.open_bid[mid] - removed;
    } else {
        act.open_ask[mid] = a.taker_actv.open_ask[mid] - removed;
    }
    if !modify {
        act.open_orders = a.taker_actv.open_orders - 1;
    }
    st.activity_root =
        update(DS_ACTV_NODE, st.activity_root, a.account_index, a.taker_actv.hash(), act.hash(), a.taker_actv_path);
    st
}
