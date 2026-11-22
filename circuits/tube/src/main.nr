mod pinned;

use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, Activity, Key, master_auth_p},
    consts::{ACCOUNTS_HEIGHT, DS_ACCT_NODE, DS_ACTV_NODE, KEYS_HEIGHT, MASTER_KEY},
    params::Params,
    state::State,
    trade::{ACTION_PAYLOAD, action_msg, KIND_ADD_KEY, KIND_REVOKE_KEY, write_key_slot},
    tree::update,
};
use l3x_types::{
    AggOutput, CHONK_PROOF_LENGTH, CHONK_VK_LENGTH, DS_ACTION_LOG, DS_AGG, hash::hash, MAX_CLIENT_PROOFS, NodeOutput,
    PROOF_TYPE_CHONK, Running,
};

/// One action a client proof authorizes. `msg`, `account_index` and `auth_binding` are the
/// proof's public inputs; the rest opens the account and the action.
struct ClientAction {
    msg: Field,
    account_index: Field,
    auth_binding: Field,
    kind: Field,
    nonce: u64,
    p: [Field; ACTION_PAYLOAD],
    acct_pub: AccountPub,
    acct_priv: AccountPriv,
    acct_path: [Field; ACCOUNTS_HEIGHT],
    actv: Activity,
    actv_path: [Field; ACCOUNTS_HEIGHT],
    key: Key,
    key_path: [Field; KEYS_HEIGHT],
}

/// Tube (SPEC.md §7.4, §9.2): the merge-tree leaf of a P-segment. Verifies the segment's Chonk
/// proof against the pinned Chonk VK (the hiding kernel's VK); the IVC verified up to
/// MAX_CLIENT_PROOFS client proofs of the pinned client circuit and folded the first `count`
/// proofs' public inputs into `actions_hash`. The tube recomputes that fold from the actions, so
/// every action applied here is exactly what a client proof authorized, and applies them:
/// - the account's master authorization is the client circuit with the proof's auth binding
///   (lane P, SPEC.md §7.1);
/// - the proof's message is the action's message under the master key, with the next nonce;
/// - the action grants or revokes a session key (SPEC.md §7.2, D9), so one proof authorizes many
///   fast signed actions afterwards.
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
    let mut acc: Field = 0;
    for i in 0..MAX_CLIENT_PROOFS {
        if i < agg.count {
            let a = actions[i];
            acc = hash([DS_AGG, acc, pinned::CLIENT_VK_HASH, a.msg, a.account_index, a.auth_binding]);
        }
    }
    assert(acc == agg.actions_hash, "client actions do not match the proofs");
    let mut end = start;
    end.action_log = hash([DS_ACTION_LOG, start.action_log, agg.actions_hash, agg.count as Field]);
    let domain = params.domain();
    let mut st = state;
    for i in 0..MAX_CLIENT_PROOFS {
        if i < agg.count {
            st = apply(st, actions[i], domain);
        }
    }
    end.state = st.trees();
    NodeOutput { config_hash: params.config(vk_tree_root), start, end, receipts_root: 0 }
}

fn apply(state: State, a: ClientAction, domain: Field) -> State {
    let mut st = state;
    let idx = a.account_index as u32;
    assert((idx as Field == a.account_index) & (idx < st.num_accounts), "account");
    assert(
        a.acct_pub.master_auth == master_auth_p(pinned::CLIENT_VK_HASH, a.auth_binding),
        "client proof does not control the account",
    );
    assert(a.msg == action_msg(domain, a.kind, idx, MASTER_KEY, a.nonce, a.p), "proof authorizes another action");
    assert(a.actv.nonce + 1 == a.nonce, "nonce");
    assert((a.kind == KIND_ADD_KEY) | (a.kind == KIND_REVOKE_KEY), "client proofs grant and revoke session keys");
    // The account's leaf binds the master authorization checked above.
    let leaf = account_leaf(a.acct_pub, a.acct_priv);
    st.accounts_root = update(DS_ACCT_NODE, st.accounts_root, idx, leaf, leaf, a.acct_path);
    let mut act = a.actv;
    act.nonce = a.nonce;
    act.keys_root = write_key_slot(a.actv.keys_root, a.key, a.key_path, a.kind == KIND_ADD_KEY, a.p);
    st.activity_root = update(DS_ACTV_NODE, st.activity_root, idx, a.actv.hash(), act.hash(), a.actv_path);
    st
}
