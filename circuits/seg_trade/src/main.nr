use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, Activity, blind, enc_commitment, master_auth_of},
    book::{Order, order_index, replace, Sibling, SIDE_ASK, SIDE_BID, walk},
    consts::{
        ACCOUNTS_HEIGHT, BOOK_HEIGHT, DS_ACCT_NODE, DS_ACTV_NODE, DS_WD_CHAIN, DS_WDSALT, LOG_SIGNED,
        MAX_LOTS, MAX_PRICE, PPM, TAG_CHANGE, TAG_WD,
    },
    da::{absorb, emit_account, open_segment, segment_nonce},
    params::Params,
    sig::{assert_signed, Signature},
    state::State,
    trade::{abs, action_msg, equity, fill, KIND_CANCEL, KIND_PLACE, KIND_WITHDRAW, meets_im, TIF_GTC, TIF_IOC, worst},
    tree::update,
    withdrawal_record,
};
use l3x_types::{DS_ACTION_LOG, hash::hash, NodeOutput, Running};

/// Signed actions per segment, and fills per order.
global TA: u32 = 2;
global F: u32 = 2;
global MAX_COLLATERAL: u64 = 0x4000000000000000; // 2^62

/// One fill against a resting maker order.
struct Fill {
    /// The maker order's leaf index, its price and sequence number, and the order before the fill.
    index: Field,
    price: u32,
    seq: u64,
    order: Order,
    book_path: [Sibling; BOOK_HEIGHT],
    maker_pub: AccountPub,
    maker_priv: AccountPriv,
    maker_acct_path: [Field; ACCOUNTS_HEIGHT],
    maker_k_enc: Field,
    maker_actv: Activity,
    maker_actv_path: [Field; ACCOUNTS_HEIGHT],
}

/// One signed action. Paths are valid against the roots at the moment each leaf is written.
struct Action {
    kind: Field,
    account_index: u32,
    nonce: u64,
    p: [Field; 4],
    pk_x: Field,
    pk_y: Field,
    sig: Signature,
    taker_pub: AccountPub,
    taker_priv: AccountPriv,
    taker_k_enc: Field,
    taker_acct_path: [Field; ACCOUNTS_HEIGHT],
    taker_actv: Activity,
    taker_actv_path: [Field; ACCOUNTS_HEIGHT],
    n_fills: u32,
    fills: [Fill; F],
    /// Place: the path of the resting slot (GTC) or of the no-crossing probe (IOC remainder).
    /// Cancel: the path of the cancelled order.
    rest_path: [Sibling; BOOK_HEIGHT],
    /// Cancel: the cancelled order's remaining lots.
    cancel_lots: u64,
}

/// Trade segment (SPEC.md §6.5, §8.1–§8.3, §10.4): executes up to TA signed PlaceOrder,
/// CancelOrder and Withdraw actions in order. An order fills against the best opposite orders, up to F of them, at the
/// makers' prices, then rests (GTC) or cancels its remainder (IOC) once no crossing liquidity is
/// left. Only accounts whose balances change get DA entries: quoting and cancelling change the
/// unpublished activity tree and the book, never a published leaf (§4).
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
            let msg = action_msg(domain, a.kind, a.account_index, a.nonce, a.p);
            end.action_log = hash([DS_ACTION_LOG, end.action_log, msg, LOG_SIGNED]);
        }
    }
    let da_nonce = segment_nonce(start, end.action_log);
    end = open_segment(end, da_nonce);
    let mut st = state;
    for i in 0..TA {
        if i < n {
            let (st2, end2) = apply(st, end, actions[i], da_nonce, params, domain);
            st = st2;
            end = end2;
        }
    }
    end.state = st.trees();
    NodeOutput { config_hash: params.config(vk_tree_root), start, end }
}

fn apply(state: State, running: Running, a: Action, da_nonce: Field, params: Params, domain: Field) -> (State, Running) {
    // Authorization: the account's master key signed this action, with the next nonce. The key
    // is bound to the account by its leaf, which place and cancel prove against the accounts root.
    let msg = action_msg(domain, a.kind, a.account_index, a.nonce, a.p);
    assert(master_auth_of(a.pk_x, a.pk_y) == a.taker_pub.master_auth, "signing key is not the account's");
    assert_signed(a.pk_x, a.pk_y, a.sig, msg);
    assert(a.taker_actv.nonce + 1 == a.nonce, "nonce");
    if a.kind == KIND_PLACE {
        place(state, running, a, da_nonce, params)
    } else if a.kind == KIND_CANCEL {
        (cancel(state, a), running)
    } else {
        assert(a.kind == KIND_WITHDRAW, "unknown action kind");
        withdraw(state, running, a, da_nonce, params)
    }
}

/// Withdraw (SPEC.md §8.3, §10.4): debits collateral, keeps equity − amount ≥ IM, and appends a
/// record the vault pays to `recipient` once the batch settles.
fn withdraw(state: State, running: Running, a: Action, da_nonce: Field, params: Params) -> (State, Running) {
    let mut st = state;
    let mut r = running;
    let idx = a.account_index;
    let amount = a.p[0] as u64;
    let recipient = a.p[1];
    assert((amount as Field == a.p[0]) & (amount > 0) & (amount < MAX_COLLATERAL), "withdrawal amount out of range");
    let old = a.taker_priv;
    assert(old.collateral >= amount as i64, "collateral below the amount");
    let mark = st.market.index_price;
    let open = worst(old.size, a.taker_actv.open_bid, a.taker_actv.open_ask);
    if open > 0 {
        assert(st.market.index_time + params.max_age >= r.time, "index too old for a withdrawal");
    }
    let after = equity(old.collateral, old.size, old.entry, mark) - amount as i64;
    assert(meets_im(after, open, mark, params.imr_ppm), "insufficient margin");

    assert(enc_commitment(a.taker_k_enc) == a.taker_pub.enc_commitment, "taker k_enc");
    let mut p = old;
    p.collateral = old.collateral - amount as i64;
    p.blind = blind(a.taker_k_enc, idx, da_nonce, r.da_len);
    let new_leaf = account_leaf(a.taker_pub, p);
    st.accounts_root =
        update(DS_ACCT_NODE, st.accounts_root, idx, account_leaf(a.taker_pub, old), new_leaf, a.taker_acct_path);
    r = emit_account(r, TAG_CHANGE, idx, new_leaf, a.taker_pub, p, a.taker_k_enc, da_nonce);

    // The salt makes the record unguessable from public data (SPEC.md §10.4); the owner can
    // rebuild it from its key.
    let index = r.withdrawals_count;
    let salt = hash([DS_WDSALT, a.taker_k_enc, r.batch as Field, index as Field]);
    let record = withdrawal_record(recipient, amount, salt, r.batch, index);
    r.withdrawals = hash([DS_WD_CHAIN, r.withdrawals, record]);
    r.withdrawals_count = index + 1;
    r.withdrawals_amount += amount;
    r = absorb(absorb(r, TAG_WD), record);

    let mut act = a.taker_actv;
    act.nonce = a.nonce;
    st.activity_root =
        update(DS_ACTV_NODE, st.activity_root, idx, a.taker_actv.hash(), act.hash(), a.taker_actv_path);
    (st, r)
}

fn place(state: State, running: Running, a: Action, da_nonce: Field, params: Params) -> (State, Running) {
    let mut st = state;
    let mut r = running;
    let idx = a.account_index;
    let side = a.p[0];
    let price = a.p[1] as u64;
    let lots = a.p[2] as u64;
    let tif = a.p[3];
    assert((side == SIDE_BID) | (side == SIDE_ASK), "side");
    assert((price as Field == a.p[1]) & (price > 0) & (price < MAX_PRICE), "price out of range");
    assert((lots as Field == a.p[2]) & (lots > 0) & (lots < MAX_LOTS), "lots out of range");
    assert((tif == TIF_GTC) | (tif == TIF_IOC), "time in force");
    let mark = st.market.index_price;
    assert(mark > 0, "no index price");
    let diff = if price > mark { price - mark } else { mark - price };
    assert(diff * PPM <= mark * params.price_band_ppm, "limit price outside the band");

    let mut remaining = lots;
    let mut size = a.taker_priv.size;
    let mut entry = a.taker_priv.entry;
    let mut collateral = a.taker_priv.collateral;
    assert(a.n_fills <= F, "too many fills");
    for j in 0..F {
        if j < a.n_fills {
            let f = a.fills[j];
            assert(f.order.side != side, "maker must be on the other side");
            assert(f.order.lots > 0, "empty maker order");
            assert(f.order.account_index != idx, "self trade");
            assert(f.index == order_index(f.order.side, f.price, f.seq), "maker order index");
            assert(remaining > 0, "order already filled");
            let mp = f.price as u64;
            // Best price-time: no same-side order of the maker lies ahead of it (SPEC.md §6.5).
            let before = walk(f.order.leaf(), f.order.ask_lots(), f.order.bid_lots(), f.index, f.book_path);
            assert(before.root == st.market.book_root, "maker order path");
            if side == SIDE_BID {
                assert(before.asks_left == 0, "not the best ask");
                assert(mp <= price, "best ask above the limit");
            } else {
                assert(before.bids_right == 0, "not the best bid");
                assert(mp >= price, "best bid below the limit");
            }
            let q = if remaining < f.order.lots { remaining } else { f.order.lots };
            let left = Order { side: f.order.side, account_index: f.order.account_index, lots: f.order.lots - q };
            st.market.book_root = walk(left.leaf(), left.ask_lots(), left.bid_lots(), f.index, f.book_path).root;

            // Maker: position, collateral, open lots.
            assert(f.maker_priv.collateral >= 0 - (MAX_COLLATERAL as i64), "collateral out of range");
            let dm: i64 = if f.order.side == SIDE_BID { q as i64 } else { 0 - (q as i64) };
            let (ms, me, mpnl) = fill(f.maker_priv.size, f.maker_priv.entry, dm, mp as i64);
            let old_maker = account_leaf(f.maker_pub, f.maker_priv);
            let mut mpriv = f.maker_priv;
            mpriv.size = ms;
            mpriv.entry = me;
            mpriv.collateral = f.maker_priv.collateral + mpnl;
            assert(abs(mpriv.collateral) < MAX_COLLATERAL, "collateral out of range");
            assert(enc_commitment(f.maker_k_enc) == f.maker_pub.enc_commitment, "maker k_enc");
            mpriv.blind = blind(f.maker_k_enc, f.order.account_index, da_nonce, r.da_len);
            let maker_leaf = account_leaf(f.maker_pub, mpriv);
            st.accounts_root =
                update(DS_ACCT_NODE, st.accounts_root, f.order.account_index, old_maker, maker_leaf, f.maker_acct_path);
            r = emit_account(r, TAG_CHANGE, f.order.account_index, maker_leaf, f.maker_pub, mpriv, f.maker_k_enc, da_nonce);
            let mut mact = f.maker_actv;
            if f.order.side == SIDE_BID {
                mact.open_bid = f.maker_actv.open_bid - q;
            } else {
                mact.open_ask = f.maker_actv.open_ask - q;
            }
            if left.lots == 0 {
                mact.open_orders = f.maker_actv.open_orders - 1;
            }
            st.activity_root = update(
                DS_ACTV_NODE,
                st.activity_root,
                f.order.account_index,
                f.maker_actv.hash(),
                mact.hash(),
                f.maker_actv_path,
            );

            // Taker, in memory until the end of the action.
            let (ts, te, tpnl) = fill(size, entry, 0 - dm, mp as i64);
            // Open interest: long and short totals move together (SPEC.md §6.6).
            st.market = shift_oi(shift_oi(st.market, f.maker_priv.size, ms), size, ts);
            size = ts;
            entry = te;
            collateral = collateral + tpnl;
            assert(abs(collateral) < MAX_COLLATERAL, "collateral out of range");
            remaining -= q;
        }
    }
    assert(st.market.oi_long == st.market.oi_short, "open interest out of balance");

    // The remainder rests (GTC) or cancels (IOC), and either way no crossing liquidity is left.
    let mut act = a.taker_actv;
    act.nonce = a.nonce;
    if remaining > 0 {
        let seq = st.market.next_seq;
        let slot = order_index(side, price as u32, seq);
        let probe = walk(0, 0, 0, slot, a.rest_path);
        assert(probe.root == st.market.book_root, "resting slot path");
        if side == SIDE_BID {
            assert(probe.asks_left == 0, "crossing asks remain");
        } else {
            assert(probe.bids_right == 0, "crossing bids remain");
        }
        if tif == TIF_GTC {
            let o = Order { side, account_index: idx, lots: remaining };
            st.market.book_root = walk(o.leaf(), o.ask_lots(), o.bid_lots(), slot, a.rest_path).root;
            st.market.next_seq = seq + 1;
            if side == SIDE_BID {
                act.open_bid = a.taker_actv.open_bid + remaining;
            } else {
                act.open_ask = a.taker_actv.open_ask + remaining;
            }
            act.open_orders = a.taker_actv.open_orders + 1;
        }
    }

    // Taker account. Its leaf is always proven, which authenticates the signing key above; it is
    // written, and published, only if a fill changed it.
    let mut tpriv = a.taker_priv;
    let old_leaf = account_leaf(a.taker_pub, a.taker_priv);
    let mut new_leaf = old_leaf;
    if a.n_fills > 0 {
        assert(enc_commitment(a.taker_k_enc) == a.taker_pub.enc_commitment, "taker k_enc");
        tpriv.size = size;
        tpriv.entry = entry;
        tpriv.collateral = collateral;
        tpriv.blind = blind(a.taker_k_enc, idx, da_nonce, r.da_len);
        new_leaf = account_leaf(a.taker_pub, tpriv);
    }
    st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, idx, old_leaf, new_leaf, a.taker_acct_path);
    if a.n_fills > 0 {
        r = emit_account(r, TAG_CHANGE, idx, new_leaf, a.taker_pub, tpriv, a.taker_k_enc, da_nonce);
    }
    st.activity_root =
        update(DS_ACTV_NODE, st.activity_root, idx, a.taker_actv.hash(), act.hash(), a.taker_actv_path);

    // Margin (SPEC.md §8.3): a risk-increasing order needs a fresh index and equity ≥ IM after it.
    let worst_before = worst(a.taker_priv.size, a.taker_actv.open_bid, a.taker_actv.open_ask);
    let worst_after = worst(tpriv.size, act.open_bid, act.open_ask);
    if worst_after > worst_before {
        assert(st.market.index_time + params.max_age >= r.time, "index too old for a risk-increasing order");
        assert(
            meets_im(equity(tpriv.collateral, tpriv.size, tpriv.entry, mark), worst_after, mark, params.imr_ppm),
            "insufficient margin",
        );
    }
    (st, r)
}

fn cancel(state: State, a: Action) -> State {
    let mut st = state;
    // The account's leaf authenticates the signing key.
    let leaf = account_leaf(a.taker_pub, a.taker_priv);
    st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, a.account_index, leaf, leaf, a.taker_acct_path);
    let side = a.p[0];
    let price = a.p[1] as u32;
    let seq = a.p[2] as u64;
    assert((side == SIDE_BID) | (side == SIDE_ASK), "side");
    assert((price as Field == a.p[1]) & (seq as Field == a.p[2]), "order reference");
    assert(a.cancel_lots > 0, "no such order");
    let index = order_index(side, price, seq);
    let o = Order { side, account_index: a.account_index, lots: a.cancel_lots };
    let (root, _) = replace(st.market.book_root, index, o, Order::empty(), a.rest_path);
    st.market.book_root = root;
    let mut act = a.taker_actv;
    act.nonce = a.nonce;
    if side == SIDE_BID {
        act.open_bid = a.taker_actv.open_bid - a.cancel_lots;
    } else {
        act.open_ask = a.taker_actv.open_ask - a.cancel_lots;
    }
    act.open_orders = a.taker_actv.open_orders - 1;
    st.activity_root =
        update(DS_ACTV_NODE, st.activity_root, a.account_index, a.taker_actv.hash(), act.hash(), a.taker_actv_path);
    st
}

/// Moves one account's contribution to open interest from `before` to `after`.
fn shift_oi(m: l3x_exchange::state::Market, before: i64, after: i64) -> l3x_exchange::state::Market {
    let mut out = m;
    let long_before = if before > 0 { before as u64 } else { 0 };
    let long_after = if after > 0 { after as u64 } else { 0 };
    let short_before = if before < 0 { (0 - before) as u64 } else { 0 };
    let short_after = if after < 0 { (0 - after) as u64 } else { 0 };
    out.oi_long = m.oi_long + long_after - long_before;
    out.oi_short = m.oi_short + short_after - short_before;
    out
}
