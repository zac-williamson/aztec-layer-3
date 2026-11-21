use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, enc_commitment},
    consts::{ACCOUNTS_HEIGHT, DS_ACCT_NODE, TAG_REFRESH},
    da::{emit_account, open_segment, segment_nonce},
    params::Params,
    state::State,
    tree::merkle_root,
};
use l3x_types::{NodeOutput, Running};

global RF: u32 = 4;

struct Item {
    pub_part: AccountPub,
    priv_part: AccountPriv,
    path: [Field; ACCOUNTS_HEIGHT],
    k_enc: Field,
}

/// Refresh segment (SPEC.md §9.5): republishes the next `n` accounts after refresh_cursor, in
/// index order and wrapping around, each as its unchanged leaf with the full opening encrypted
/// under a fresh keystream. Run often enough, it makes the DA of the last window W sufficient to
/// rebuild every account, active or not.
fn main(
    vk_tree_root: Field,
    params: Params,
    start: Running,
    state: State,
    n: u32,
    items: [Item; RF],
) -> pub NodeOutput {
    assert(start.state == state.trees(), "state opening");
    assert(n <= RF, "too many refresh entries");
    assert(n <= state.num_accounts, "more refresh entries than accounts");
    let da_nonce = segment_nonce(start, start.action_log);
    let mut end = open_segment(start, da_nonce);
    let mut st = state;
    let mut cursor = st.refresh_cursor;
    for i in 0..RF {
        if i < n {
            let w = items[i];
            let leaf = account_leaf(w.pub_part, w.priv_part);
            assert(merkle_root(DS_ACCT_NODE, leaf, cursor, w.path) == st.accounts_root, "account path");
            assert(enc_commitment(w.k_enc) == w.pub_part.enc_commitment, "k_enc does not open the commitment");
            end = emit_account(end, TAG_REFRESH, cursor, leaf, w.pub_part, w.priv_part, w.k_enc, da_nonce);
            cursor = if cursor + 1 == st.num_accounts { 0 } else { cursor + 1 };
        }
    }
    st.refresh_cursor = cursor;
    end.state = st.trees();
    NodeOutput { config_hash: params.config(vk_tree_root), start, end }
}
