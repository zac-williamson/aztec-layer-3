use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, Activity, blind, enc_commitment},
    consts::{
        ACCOUNTS_HEIGHT, CLASS_USER, DS_ACCT_NODE, DS_ACTV_NODE, DS_WD_CHAIN, DS_WDSALT, KIND_DEPOSIT,
        KIND_FORCED_WITHDRAW, KIND_REGISTER, LOG_PRIORITY, MAX_COLLATERAL, MAX_DEPOSIT, PPM, TAG_FULL, TAG_WD,
    },
    da::{absorb, emit_change, emit_full, open_segment, segment_nonce},
    params::Params,
    request::Request,
    state::State,
    trade::{equity, exposure_fresh, initial_margin},
    tree::{merkle_root, update},
    withdrawal_record,
};
use l3x_types::{DS_ACTION_LOG, hash::hash, NodeOutput, priority_next_head, Running};

global PR: u32 = 4;

/// Witness for one priority request.
struct Item {
    req: Request,
    /// Register: the new account's index. Deposit: the credited account's index.
    account_index: u32,
    /// Deposit: the credited account's current leaf preimage.
    acct_pub: AccountPub,
    acct_priv: AccountPriv,
    acct_path: [Field; ACCOUNTS_HEIGHT],
    /// Register: path of the empty activity slot. ForcedWithdraw: the account's activity, for its
    /// margin, and its path.
    actv: Activity,
    actv_path: [Field; ACCOUNTS_HEIGHT],
    /// The account's encryption key. The Bridge checked it against the commitment at
    /// registration and delivered it to the operator, so every request is processable.
    k_enc: Field,
}

/// Priority segment (SPEC.md §7.3, §12): executes the next `n` queued requests in order.
/// Register creates the next account with zero collateral and no positions; Deposit credits an
/// existing account or, if the account does not exist, refunds the depositor; ForcedWithdraw
/// withdraws an account's free collateral when its owner asked. No request can be skipped, and a
/// request's own fields can never make the segment unprovable: an invalid request is consumed
/// without effect. Forced closes and cancellations go through seg_forced.
fn main(
    vk_tree_root: Field,
    params: Params,
    start: Running,
    state: State,
    n: u32,
    items: [Item; PR],
) -> pub NodeOutput {
    assert(start.state == state.trees(), "state opening");
    assert(n <= PR, "too many requests");
    let mut end = start;
    for i in 0..PR {
        if i < n {
            let entry = items[i].req.entry();
            end.priority_head = priority_next_head(end.priority_head, entry);
            end.action_log = hash([DS_ACTION_LOG, end.action_log, entry, LOG_PRIORITY]);
        }
    }
    end.priority_cursor = start.priority_cursor + n as u64;
    let da_nonce = segment_nonce(start, end.action_log);
    end = open_segment(end, da_nonce);
    let mut st = state;
    for i in 0..PR {
        if i < n {
            let (st2, end2) = apply(st, end, items[i], da_nonce, params);
            st = st2;
            end = end2;
        }
    }
    end.state = st.trees();
    NodeOutput { config_hash: params.config(vk_tree_root), start, end, receipts_root: 0 }
}

fn apply(state: State, running: Running, w: Item, da_nonce: Field, params: Params) -> (State, Running) {
    let req = w.req;
    let mut st = state;
    let mut r = running;
    if req.kind == KIND_REGISTER {
        let idx = st.num_accounts;
        assert(w.account_index == idx, "register index");
        assert(enc_commitment(w.k_enc) == req.b, "k_enc does not open the commitment");
        let pubv =
            AccountPub { owner: req.sender, master_auth: req.a, enc_commitment: req.b, class: CLASS_USER };
        let privv = AccountPriv::empty(blind(w.k_enc, idx, da_nonce, r.da_len));
        let leaf = account_leaf(pubv, privv);
        st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, idx, 0, leaf, w.acct_path);
        st.activity_root = update(DS_ACTV_NODE, st.activity_root, idx, 0, Activity::new().hash(), w.actv_path);
        st.num_accounts = idx + 1;
        r = emit_full(r, TAG_FULL, idx, leaf, pubv, privv, w.k_enc, da_nonce);
    } else if req.kind == KIND_FORCED_WITHDRAW {
        let (st2, r2) = forced_withdraw(st, r, w, da_nonce, params);
        st = st2;
        r = r2;
    } else {
        assert(req.kind == KIND_DEPOSIT, "request kind not executed by this segment");
        let amount = req.b as u64;
        assert(amount as Field == req.b, "deposit amount out of range");
        assert(amount < MAX_DEPOSIT, "deposit amount out of range");
        let idx = req.a as u32;
        let exists = (idx as Field == req.a) & (idx < st.num_accounts);
        let mut credited = false;
        if exists {
            assert(w.account_index == idx, "deposit index");
            let old_leaf = account_leaf(w.acct_pub, w.acct_priv);
            // A credit that would take collateral out of range is refunded instead, so no deposit
            // can make the queue unprocessable.
            credited = w.acct_priv.collateral + (amount as i64) < MAX_COLLATERAL as i64;
            let mut leaf = old_leaf;
            let mut privv = w.acct_priv;
            if credited {
                assert(enc_commitment(w.k_enc) == w.acct_pub.enc_commitment, "k_enc does not open the commitment");
                privv.collateral = w.acct_priv.collateral + amount as i64;
                privv.blind = blind(w.k_enc, idx, da_nonce, r.da_len);
                leaf = account_leaf(w.acct_pub, privv);
            }
            st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, idx, old_leaf, leaf, w.acct_path);
            if credited {
                r = emit_change(r, idx, leaf, privv, w.k_enc, da_nonce);
            }
        }
        if !credited {
            // No such account, or no room: refund the depositor from the vault (SPEC.md §10.4).
            // The priority entry is public and unique, so it serves as the record's salt.
            let record = withdrawal_record(req.sender, amount, req.entry(), r.batch, r.withdrawals_count);
            r.withdrawals = hash([DS_WD_CHAIN, r.withdrawals, record]);
            r.withdrawals_count += 1;
            r.withdrawals_amount += amount;
            r = absorb(absorb(r, TAG_WD), record);
        }
    }
    (st, r)
}

/// ForcedWithdraw (SPEC.md §7.3): if the account exists and the request came from its owner,
/// withdraws all free collateral, max(0, min(collateral, equity − IM)), to the recipient in `b`.
/// Equity needs fresh indices wherever the account is exposed; otherwise nothing is free, and a
/// flat account needs none. A request that does not qualify is consumed without effect.
fn forced_withdraw(state: State, running: Running, w: Item, da_nonce: Field, params: Params) -> (State, Running) {
    let req = w.req;
    let mut st = state;
    let mut r = running;
    let idx = req.a as u32;
    let exists = (idx as Field == req.a) & (idx < st.num_accounts);
    if exists {
        assert(w.account_index == idx, "forced withdrawal index");
        assert(
            merkle_root(DS_ACTV_NODE, w.actv.hash(), idx, w.actv_path) == st.activity_root,
            "activity path",
        );
        let old = w.acct_priv;
        let mut amount: u64 = 0;
        if (w.acct_pub.owner == req.sender)
            & exposure_fresh(old, w.actv, st.markets, params.max_age, r.time) {
            let im = initial_margin(old, w.actv, st.markets, params);
            let im_units = ((im + (PPM as u128) - 1) / (PPM as u128)) as u64;
            let free = equity(old, st.markets) - im_units as i64;
            let limit = if free < old.collateral { free } else { old.collateral };
            if limit > 0 {
                amount = limit as u64;
            }
        }
        let old_leaf = account_leaf(w.acct_pub, old);
        let mut new_leaf = old_leaf;
        let mut p = old;
        if amount > 0 {
            assert(enc_commitment(w.k_enc) == w.acct_pub.enc_commitment, "k_enc does not open the commitment");
            p.collateral = old.collateral - amount as i64;
            p.blind = blind(w.k_enc, idx, da_nonce, r.da_len);
            new_leaf = account_leaf(w.acct_pub, p);
        }
        st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, idx, old_leaf, new_leaf, w.acct_path);
        if amount > 0 {
            r = emit_change(r, idx, new_leaf, p, w.k_enc, da_nonce);
            let index = r.withdrawals_count;
            let salt = hash([DS_WDSALT, w.k_enc, r.batch as Field, index as Field]);
            let record = withdrawal_record(req.b, amount, salt, r.batch, index);
            r.withdrawals = hash([DS_WD_CHAIN, r.withdrawals, record]);
            r.withdrawals_count = index + 1;
            r.withdrawals_amount += amount;
            r = absorb(absorb(r, TAG_WD), record);
        }
    }
    (st, r)
}
