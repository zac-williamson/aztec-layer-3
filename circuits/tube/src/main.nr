mod pinned;

use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, Activity, Key, master_auth_p},
    consts::{ACCOUNTS_HEIGHT, DS_ACCT_NODE, DS_ACTV_NODE, KEYS_HEIGHT, MASTER_KEY},
    da::{open_segment, segment_nonce},
    params::Params,
    state::State,
    trade::{ACTION_PAYLOAD, action_msg, KIND_ADD_KEY, KIND_REVOKE_KEY, KIND_WITHDRAW, withdraw, write_key_slot},
    tree::update,
};
use l3x_types::{
    AggOutput, CHONK_PROOF_LENGTH, CHONK_VK_LENGTH, DS_ACTION_LOG, DS_AGG, hash::hash, MAX_CLIENT_PROOFS, NodeOutput,
    PROOF_TYPE_CHONK, Running,
};

/// One action a client proof authorizes. `msg`, `account_index` and `auth_binding` are the
/// proof's public inputs; the rest opens the account and the action.
struct ClientAction {
    /// The client circuit's VK hash, as agg_app verified the proof against it.
    vk_hash: Field,
    msg: Field,
    account_index: Field,
    auth_binding: Field,
    kind: Field,
    nonce: u64,
    p: [Field; ACTION_PAYLOAD],
    acct_pub: AccountPub,
    acct_priv: AccountPriv,
    acct_path: [Field; ACCOUNTS_HEIGHT],
    /// Opens the account's encryption commitment; a withdrawal publishes the account under it.
    k_enc: Field,
    actv: Activity,
    actv_path: [Field; ACCOUNTS_HEIGHT],
    key: Key,
    key_path: [Field; KEYS_HEIGHT],
}

/// Tube (SPEC.md §7.4, §9.2): the merge-tree leaf of a P-segment. Verifies the segment's Chonk
/// proof against the pinned Chonk VK (the hiding kernel's VK); the IVC verified up to
/// MAX_CLIENT_PROOFS client proofs, each of a circuit in the client subtree of the VK tree it
/// outputs, and folded the first `count` proofs' VK hashes and public inputs into
/// `actions_hash`. The tube requires that VK tree to be the configuration's, recomputes the fold
/// from the actions, so every action applied here is exactly what a client proof authorized, and
/// applies them:
/// - the account's master authorization is the proof's client circuit with the proof's auth
///   binding (lane P, SPEC.md §7.1);
/// - the proof's message is the action's message under the master key, with the next nonce;
/// - the action grants or revokes a session key (SPEC.md §7.2, D9), so one proof authorizes many
///   fast signed actions afterwards, or withdraws collateral under the same rules as a master-key
///   withdrawal, publishing the account change and the withdrawal record.
/// Proved with the noir-rollup-no-zk target, so the IPA claim produced by the Chonk verifier
/// travels up the merge tree to the root.
fn main(
    chonk_vk: [Field; CHONK_VK_LENGTH],
    chonk_proof: [Field; CHONK_PROOF_LENGTH],
    agg: AggOutput,
    vk_tree_root: Field,
    params: Params,
    start: Running,
    state: State,
    actions: [ClientAction; MAX_CLIENT_PROOFS],
) -> pub NodeOutput {
    std::verify_proof_with_type(
        chonk_vk,
        chonk_proof,
        agg.to_fields(),
        pinned::CHONK_VK_HASH,
        PROOF_TYPE_CHONK,
    );
    assert(start.state == state.trees(), "state opening");
    assert(agg.count <= MAX_CLIENT_PROOFS, "too many client proofs");
    assert(agg.vk_tree_root == vk_tree_root, "client proofs verified under another VK tree");
    let mut acc: Field = 0;
    for i in 0..MAX_CLIENT_PROOFS {
        if i < agg.count {
            let a = actions[i];
            acc = hash([DS_AGG, acc, a.vk_hash, a.msg, a.account_index, a.auth_binding]);
        }
    }
    assert(acc == agg.actions_hash, "client actions do not match the proofs");
    let mut end = start;
    end.action_log = hash([DS_ACTION_LOG, start.action_log, agg.actions_hash, agg.count as Field]);
    let da_nonce = segment_nonce(start, end.action_log);
    end = open_segment(end, da_nonce);
    let domain = params.domain();
    let mut st = state;
    for i in 0..MAX_CLIENT_PROOFS {
        if i < agg.count {
            let (st2, end2) = apply(st, end, actions[i], domain, da_nonce, params);
            st = st2;
            end = end2;
        }
    }
    end.state = st.trees();
    NodeOutput { config_hash: params.config(vk_tree_root), start, end, receipts_root: 0 }
}

fn apply(state: State, running: Running, a: ClientAction, domain: Field, da_nonce: Field, params: Params) -> (State, Running) {
    let mut st = state;
    let mut r = running;
    let idx = a.account_index as u32;
    assert((idx as Field == a.account_index) & (idx < st.num_accounts), "account");
    assert(
        a.acct_pub.master_auth == master_auth_p(a.vk_hash, a.auth_binding),
        "client proof does not control the account",
    );
    assert(a.msg == action_msg(domain, a.kind, idx, MASTER_KEY, a.nonce, a.p), "proof authorizes another action");
    assert(a.actv.nonce + 1 == a.nonce, "nonce");
    let is_key = (a.kind == KIND_ADD_KEY) | (a.kind == KIND_REVOKE_KEY);
    assert(is_key | (a.kind == KIND_WITHDRAW), "client proofs only manage session keys and withdraw");
    // The account's leaf binds the master authorization checked above.
    let old_leaf = account_leaf(a.acct_pub, a.acct_priv);
    let mut new_leaf = old_leaf;
    let mut act = a.actv;
    act.nonce = a.nonce;
    if is_key {
        act.keys_root = write_key_slot(a.actv.keys_root, a.key, a.key_path, a.kind == KIND_ADD_KEY, a.p);
    } else {
        let (leaf, r2) = withdraw(r, st.markets, params, idx, a.acct_pub, a.acct_priv, a.actv, a.k_enc, a.p, da_nonce);
        new_leaf = leaf;
        r = r2;
    }
    st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, idx, old_leaf, new_leaf, a.acct_path);
    st.activity_root = update(DS_ACTV_NODE, st.activity_root, idx, a.actv.hash(), act.hash(), a.actv_path);
    (st, r)
}
