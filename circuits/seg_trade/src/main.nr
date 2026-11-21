use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, Activity, blind, enc_commitment, master_auth_of, Position},
    book::{Order, order_index, replace, Sibling, SIDE_ASK, SIDE_BID, walk},
    consts::{
        ACCOUNTS_HEIGHT, BOOK_HEIGHT, DS_ACCT_NODE, DS_ACTV_NODE, DS_WD_CHAIN, DS_WDSALT, LOG_SIGNED, MARKETS,
        MAX_COLLATERAL, MAX_FEES, MAX_LOTS, MAX_OPEN_ORDERS, MAX_PRICE, PPM, TAG_WD,
    },
    da::{absorb, emit_change, open_segment, segment_nonce},
    params::Params,
    sig::{assert_signed, Signature},
    state::{Market, State},
    trade::{
        abs, ACTION_PAYLOAD, action_msg, covers, equity, exposure_fresh, fee, fill, initial_margin, KIND_CANCEL,
        KIND_PLACE, KIND_WITHDRAW, settle_funding, TIF_FOK, TIF_GTC, TIF_IOC, TIF_POST_ONLY, worst,
    },
    tree::update,
    withdrawal_record,
};
use l3x_types::{DS_ACTION_LOG, hash::hash, NodeOutput, Running};

/// Signed actions per segment, and matching steps per order.
global TA: u32 = 2;
global F: u32 = 2;

/// One matching step against the best resting order: a fill, or, when the resting order is the
/// taker's own, its cancellation (self-trade prevention, SPEC.md §8.1).
struct Fill {
    /// The resting order's leaf index, its price and sequence number, and the order before the step.
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
    p: [Field; ACTION_PAYLOAD],
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
    /// Place: the path of the resting slot (GTC, post-only) or of the no-crossing probe (IOC
    /// remainder). Cancel: the path of the cancelled order.
    rest_path: [Sibling; BOOK_HEIGHT],
    /// Cancel: the cancelled order's remaining lots.
    cancel_lots: u64,
}

/// Trade segment (SPEC.md §6.5, §8.1–§8.6, §10.4): executes up to TA signed PlaceOrder,
/// CancelOrder and Withdraw actions in order, in any listed market. An order matches the best
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
    // is bound to the account by its leaf, which every action proves against the accounts root.
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
    assert(
        exposure_fresh(old, a.taker_actv, st.markets, params.max_age, r.time),
        "index too old for a withdrawal",
    );
    let after = equity(old, st.markets) - amount as i64;
    assert(covers(after, initial_margin(old, a.taker_actv, st.markets, params)), "insufficient margin");

    assert(enc_commitment(a.taker_k_enc) == a.taker_pub.enc_commitment, "taker k_enc");
    let mut p = old;
    p.collateral = old.collateral - amount as i64;
    p.blind = blind(a.taker_k_enc, idx, da_nonce, r.da_len);
    let new_leaf = account_leaf(a.taker_pub, p);
    st.accounts_root =
        update(DS_ACCT_NODE, st.accounts_root, idx, account_leaf(a.taker_pub, old), new_leaf, a.taker_acct_path);
    r = emit_change(r, idx, new_leaf, p, a.taker_k_enc, da_nonce);

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
    st.activity_root = update(DS_ACTV_NODE, st.activity_root, idx, a.taker_actv.hash(), act.hash(), a.taker_actv_path);
    (st, r)
}

fn place(state: State, running: Running, a: Action, da_nonce: Field, params: Params) -> (State, Running) {
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
    assert((tif == TIF_GTC) | (tif == TIF_IOC) | (tif == TIF_FOK) | (tif == TIF_POST_ONLY), "time in force");
    assert((reduce_only == 0) | (reduce_only == 1), "reduce-only flag");
    let rests = (tif == TIF_GTC) | (tif == TIF_POST_ONLY);
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
    let mut taker = a.taker_priv;
    let mut act = a.taker_actv;
    act.nonce = a.nonce;
    let size_before = a.taker_priv.positions[mid].size;
    let mut traded = false;
    let mut remaining = lots;
    assert(a.n_fills <= F, "too many fills");
    for j in 0..F {
        if j < a.n_fills {
            let f = a.fills[j];
            assert(f.order.side != side, "maker must be on the other side");
            assert(f.order.lots > 0, "empty maker order");
            assert(f.index == order_index(f.order.side, f.price, f.seq), "maker order index");
            assert(remaining > 0, "order already filled");
            let mp_price = f.price as u64;
            // Best price-time: no same-side order lies ahead of it (SPEC.md §6.5).
            let before = walk(f.order.leaf(), f.order.ask_lots(), f.order.bid_lots(), f.index, f.book_path);
            assert(before.root == market.book_root, "maker order path");
            if side == SIDE_BID {
                assert(before.asks_left == 0, "not the best ask");
                assert(mp_price <= price, "best ask above the limit");
            } else {
                assert(before.bids_right == 0, "not the best bid");
                assert(mp_price >= price, "best bid below the limit");
            }
            if f.order.account_index == idx {
                // Self-trade prevention: cancel the taker's own resting order and continue.
                market.book_root = walk(0, 0, 0, f.index, f.book_path).root;
                if f.order.side == SIDE_BID {
                    act.open_bid[mid] -= f.order.lots;
                } else {
                    act.open_ask[mid] -= f.order.lots;
                }
                act.open_orders -= 1;
            } else {
                let q = if remaining < f.order.lots { remaining } else { f.order.lots };
                let left = Order { side: f.order.side, account_index: f.order.account_index, lots: f.order.lots - q };
                market.book_root = walk(left.leaf(), left.ask_lots(), left.bid_lots(), f.index, f.book_path).root;
                let (st2, r2, m2) = fill_maker(st, r, market, mid, mp.maker_fee_ppm, f, q, left.lots, da_nonce);
                st = st2;
                r = r2;
                market = m2;

                // Taker side of the fill.
                if !traded {
                    let (c, pos, dust) = settle_funding(taker.collateral, taker.positions[mid], market.cum_funding);
                    taker.collateral = c;
                    taker.positions[mid] = pos;
                    st.insurance_micro += dust;
                    traded = true;
                }
                let dm: i64 = if f.order.side == SIDE_BID { q as i64 } else { 0 - (q as i64) };
                let tpos = taker.positions[mid];
                let (ts, te, tpnl) = fill(tpos.size, tpos.entry, 0 - dm, mp_price as i64);
                let tfee = fee(q, mp_price, mp.taker_fee_ppm);
                market = shift_oi(market, tpos.size, ts);
                taker.positions[mid] = Position { size: ts, entry: te, funding: tpos.funding };
                taker.collateral = taker.collateral + tpnl - tfee as i64;
                assert(abs(taker.collateral) < MAX_COLLATERAL, "collateral out of range");
                st.fees_pending += tfee;
                remaining -= q;
            }
        }
    }
    assert(market.oi_long == market.oi_short, "open interest out of balance");
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
        let slot = order_index(side, price as u32, seq);
        let probe = walk(0, 0, 0, slot, a.rest_path);
        assert(probe.root == market.book_root, "resting slot path");
        if side == SIDE_BID {
            assert(probe.asks_left == 0, "crossing asks remain");
        } else {
            assert(probe.bids_right == 0, "crossing bids remain");
        }
        if rests {
            let o = Order { side, account_index: idx, lots: remaining };
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

/// The maker side of a fill of `q` lots at the maker's price, leaving `left` lots resting:
/// settles the maker's funding, applies the fill and the maker fee, writes and publishes the
/// maker's leaf, and updates its open lots.
fn fill_maker(
    state: State,
    running: Running,
    market: Market,
    mid: u32,
    maker_fee_ppm: u64,
    f: Fill,
    q: u64,
    left: u64,
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
    let mut mact = f.maker_actv;
    if f.order.side == SIDE_BID {
        mact.open_bid[mid] = f.maker_actv.open_bid[mid] - q;
    } else {
        mact.open_ask[mid] = f.maker_actv.open_ask[mid] - q;
    }
    if left == 0 {
        mact.open_orders = f.maker_actv.open_orders - 1;
    }
    st.activity_root = update(DS_ACTV_NODE, st.activity_root, mi, f.maker_actv.hash(), mact.hash(), f.maker_actv_path);
    (st, r, mkt)
}

fn cancel(state: State, a: Action) -> State {
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
    let index = order_index(side, price, seq);
    let o = Order { side, account_index: a.account_index, lots: a.cancel_lots };
    let (root, _) = replace(st.markets[mid].book_root, index, o, Order::empty(), a.rest_path);
    st.markets[mid].book_root = root;
    let mut act = a.taker_actv;
    act.nonce = a.nonce;
    if side == SIDE_BID {
        act.open_bid[mid] = a.taker_actv.open_bid[mid] - a.cancel_lots;
    } else {
        act.open_ask[mid] = a.taker_actv.open_ask[mid] - a.cancel_lots;
    }
    act.open_orders = a.taker_actv.open_orders - 1;
    st.activity_root =
        update(DS_ACTV_NODE, st.activity_root, a.account_index, a.taker_actv.hash(), act.hash(), a.taker_actv_path);
    st
}

/// Moves one account's contribution to open interest from `before` to `after`.
fn shift_oi(m: Market, before: i64, after: i64) -> Market {
    let mut out = m;
    let long_before = if before > 0 { before as u64 } else { 0 };
    let long_after = if after > 0 { after as u64 } else { 0 };
    let short_before = if before < 0 { (0 - before) as u64 } else { 0 };
    let short_after = if after < 0 { (0 - after) as u64 } else { 0 };
    out.oi_long = m.oi_long + long_after - long_before;
    out.oi_short = m.oi_short + short_after - short_before;
    out
}
