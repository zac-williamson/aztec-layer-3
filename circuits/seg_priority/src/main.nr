use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, Activity, blind, enc_commitment},
    consts::{
        ACCOUNTS_HEIGHT, CLASS_USER, DS_ACCT_NODE, DS_ACTV_NODE, DS_WD_CHAIN, KIND_DEPOSIT,
        KIND_REGISTER, LOG_PRIORITY, MAX_DEPOSIT, TAG_CHANGE, TAG_WD,
    },
    da::{absorb, emit_account, open_segment, segment_nonce},
    params::Params,
    request::Request,
    state::State,
    tree::update,
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
    /// Register: path of the empty activity slot.
    actv_path: [Field; ACCOUNTS_HEIGHT],
    /// The account's encryption key. The Bridge checked it against the commitment at
    /// registration and delivered it to the operator, so every request is processable.
    k_enc: Field,
}

/// Priority segment (SPEC.md §7.3, §12): executes the next `n` queued requests in order.
/// Register creates the next account with zero collateral; Deposit credits an existing account
/// or, if the account does not exist, refunds the depositor. No request can be skipped.
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
            let (st2, end2) = apply(st, end, items[i], da_nonce);
            st = st2;
            end = end2;
        }
    }
    end.state = st.trees();
    NodeOutput { config_hash: params.config(vk_tree_root), start, end }
}

fn apply(state: State, running: Running, w: Item, da_nonce: Field) -> (State, Running) {
    let req = w.req;
    let mut st = state;
    let mut r = running;
    if req.kind == KIND_REGISTER {
        let idx = st.num_accounts;
        assert(w.account_index == idx, "register index");
        assert(enc_commitment(w.k_enc) == req.b, "k_enc does not open the commitment");
        let pubv =
            AccountPub { owner: req.sender, master_auth: req.a, enc_commitment: req.b, class: CLASS_USER };
        let privv =
            AccountPriv { collateral: 0, size: 0, entry: 0, blind: blind(w.k_enc, idx, da_nonce, r.da_len) };
        let leaf = account_leaf(pubv, privv);
        st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, idx, 0, leaf, w.acct_path);
        st.activity_root =
            update(DS_ACTV_NODE, st.activity_root, idx, 0, Activity::new().hash(), w.actv_path);
        st.num_accounts = idx + 1;
        r = emit_account(r, TAG_CHANGE, idx, leaf, pubv, privv, w.k_enc, da_nonce);
    } else {
        assert(req.kind == KIND_DEPOSIT, "unknown request kind");
        let amount = req.b as u64;
        assert(amount as Field == req.b, "deposit amount out of range");
        assert(amount < MAX_DEPOSIT, "deposit amount out of range");
        let idx = req.a as u32;
        let exists = (idx as Field == req.a) & (idx < st.num_accounts);
        if exists {
            assert(w.account_index == idx, "deposit index");
            assert(enc_commitment(w.k_enc) == w.acct_pub.enc_commitment, "k_enc does not open the commitment");
            let old_leaf = account_leaf(w.acct_pub, w.acct_priv);
            let mut privv = w.acct_priv;
            privv.collateral = w.acct_priv.collateral + amount as i64;
            privv.blind = blind(w.k_enc, idx, da_nonce, r.da_len);
            let leaf = account_leaf(w.acct_pub, privv);
            st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, idx, old_leaf, leaf, w.acct_path);
            r = emit_account(r, TAG_CHANGE, idx, leaf, w.acct_pub, privv, w.k_enc, da_nonce);
        } else {
            // No such account: refund the depositor from the vault (SPEC.md §10.4). The priority
            // entry is public and unique, so it serves as the record's salt.
            let record = withdrawal_record(req.sender, amount, req.entry(), r.batch, r.withdrawals_count);
            r.withdrawals = hash([DS_WD_CHAIN, r.withdrawals, record]);
            r.withdrawals_count += 1;
            r.withdrawals_amount += amount;
            r = absorb(absorb(r, TAG_WD), record);
        }
    }
    (st, r)
}
