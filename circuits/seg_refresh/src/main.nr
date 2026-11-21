use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, blind, enc_commitment},
    consts::{
        ACCOUNTS_HEIGHT, CLASS_FEE, CLASS_INSURANCE, DS_ACCT_NODE, FEE_INDEX, INSURANCE_INDEX, MAX_COLLATERAL, MICRO,
        PROTOCOL_ACCOUNTS, TAG_REFRESH,
    },
    da::{emit_change, emit_full, open_segment, segment_nonce},
    params::Params,
    state::State,
    trade::abs,
    tree::{merkle_root, update},
};
use l3x_types::{NodeOutput, Running};

global RF: u32 = 4;

struct Item {
    pub_part: AccountPub,
    priv_part: AccountPriv,
    path: [Field; ACCOUNTS_HEIGHT],
    k_enc: Field,
}

/// Maintenance segment (SPEC.md §8.6, §9.5).
///
/// With `sweep`, it first credits the fees collected so far to the fee account and the whole
/// micro-units of funding remainders to the insurance account, which keeps those balances out of
/// every trade's witness (SPEC.md §8.8).
///
/// It then republishes the next `n` accounts after refresh_cursor, in index order and wrapping
/// around, each as its unchanged leaf with the full opening encrypted under a fresh keystream. Run
/// often enough, refresh makes the DA of the last window W sufficient to rebuild every account,
/// active or not.
fn main(
    vk_tree_root: Field,
    params: Params,
    start: Running,
    state: State,
    sweep: bool,
    protocol: [Item; PROTOCOL_ACCOUNTS],
    n: u32,
    items: [Item; RF],
) -> pub NodeOutput {
    assert(start.state == state.trees(), "state opening");
    assert(n <= RF, "too many refresh entries");
    assert(n <= state.num_accounts, "more refresh entries than accounts");
    let da_nonce = segment_nonce(start, start.action_log);
    let mut end = open_segment(start, da_nonce);
    let mut st = state;
    if sweep {
        for k in 0..PROTOCOL_ACCOUNTS {
            let w = protocol[k];
            let (idx, class, credit) = if k == INSURANCE_INDEX {
                (INSURANCE_INDEX, CLASS_INSURANCE, st.insurance_micro / MICRO)
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
        st.fees_pending = 0;
    }
    let mut cursor = st.refresh_cursor;
    for i in 0..RF {
        if i < n {
            let w = items[i];
            let leaf = account_leaf(w.pub_part, w.priv_part);
            assert(merkle_root(DS_ACCT_NODE, leaf, cursor, w.path) == st.accounts_root, "account path");
            assert(enc_commitment(w.k_enc) == w.pub_part.enc_commitment, "k_enc does not open the commitment");
            end = emit_full(end, TAG_REFRESH, cursor, leaf, w.pub_part, w.priv_part, w.k_enc, da_nonce);
            cursor = if cursor + 1 == st.num_accounts { 0 } else { cursor + 1 };
        }
    }
    st.refresh_cursor = cursor;
    end.state = st.trees();
    NodeOutput { config_hash: params.config(vk_tree_root), start, end }
}
