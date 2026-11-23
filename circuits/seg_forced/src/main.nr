use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, Activity, blind, enc_commitment},
    book::{Sibling, SIDE_ASK, SIDE_BID},
    consts::{
        ACCOUNTS_HEIGHT, BOOK_HEIGHT, DS_ACCT_NODE, DS_ACTV_NODE, KIND_FORCED_CANCEL_ALL, KIND_FORCED_CLOSE,
        LOG_PRIORITY, MARKETS, MAX_FEES, MAX_PRICE,
    },
    da::{emit_change, open_segment, segment_nonce},
    matching::{assert_no_crossing, Fill, match_order, Taker},
    params::Params,
    request::Request,
    state::State,
    trade::abs,
    tree::update,
};
use l3x_types::{DS_ACTION_LOG, hash::hash, NodeOutput, priority_next_head, Running};

/// Matching steps per forced close.
global F: u32 = 2;

/// Forced segment (SPEC.md §7.3, §12): executes the next queued request when it is a ForcedClose
/// or a ForcedCancelAll, which need the book. A request whose account does not exist, that did not
/// come from the account's owner, or whose fields are out of range is consumed without effect, so
/// no request can make the queue unprocessable.
///
/// - ForcedClose (b = market, c = worst price): the account closes its position in the market as a
///   reduce-only IOC order, paying the taker fee, at prices no worse than c. It stops early only
///   when its matching steps run out or no liquidity is left within c; the owner can submit
///   another request for the rest.
/// - ForcedCancelAll: advances the account's order epoch, as a signed CancelAll does, which voids
///   all its orders at once.
fn main(
    vk_tree_root: Field,
    params: Params,
    start: Running,
    state: State,
    req: Request,
    account_index: u32,
    acct_pub: AccountPub,
    acct_priv: AccountPriv,
    k_enc: Field,
    acct_path: [Field; ACCOUNTS_HEIGHT],
    actv: Activity,
    actv_path: [Field; ACCOUNTS_HEIGHT],
    n_fills: u32,
    fills: [Fill; F],
    probe_path: [Sibling; BOOK_HEIGHT],
) -> pub NodeOutput {
    assert(start.state == state.trees(), "state opening");
    assert((req.kind == KIND_FORCED_CLOSE) | (req.kind == KIND_FORCED_CANCEL_ALL), "not a forced close or cancel-all");
    let entry = req.entry();
    let mut end = start;
    end.priority_head = priority_next_head(start.priority_head, entry);
    end.priority_cursor = start.priority_cursor + 1;
    end.action_log = hash([DS_ACTION_LOG, start.action_log, entry, LOG_PRIORITY]);
    let da_nonce = segment_nonce(start, end.action_log);
    end = open_segment(end, da_nonce);
    let mut st = state;

    let idx = req.a as u32;
    let exists = (idx as Field == req.a) & (idx < st.num_accounts);
    if exists {
        assert(account_index == idx, "forced request index");
        let authorized = acct_pub.owner == req.sender;
        let mut a = acct_priv;
        let mut act = actv;
        let mut traded = false;

        if authorized & (req.kind == KIND_FORCED_CLOSE) {
            let m = req.b as u32;
            let worst = req.c as u64;
            let valid = (m as Field == req.b) & (m < MARKETS) & (worst as Field == req.c) & (worst > 0)
                & (worst < MAX_PRICE);
            let mi = if valid { m } else { 0 };
            let mp = params.markets[mi];
            let pos = acct_priv.positions[mi];
            if valid & mp.listed() & (pos.size != 0) {
                let side = if pos.size > 0 { SIDE_ASK } else { SIDE_BID };
                let taker = Taker { index: idx, priv: a, act, traded: false };
                let (st2, r2, market, t, remaining, _) = match_order(
                    st,
                    end,
                    st.markets[mi],
                    mi,
                    side,
                    worst,
                    abs(pos.size),
                    taker,
                    fills,
                    n_fills,
                    mp.maker_fee_ppm,
                    mp.taker_fee_ppm,
                    da_nonce,
                );
                st = st2;
                end = r2;
                if (remaining > 0) & (n_fills < F) {
                    let _ = assert_no_crossing(market.book_root, side, worst, market.next_seq, probe_path);
                }
                st.markets[mi] = market;
                a = t.priv;
                act = t.act;
                traded = t.traded;
                assert(st.fees_pending < MAX_FEES, "fees out of range");
            } else {
                assert(n_fills == 0, "no close to match");
            }
        } else {
            assert(n_fills == 0, "no close to match");
        }

        if authorized & (req.kind == KIND_FORCED_CANCEL_ALL) {
            act = actv.cancel_all();
        }

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
    } else {
        assert(n_fills == 0, "no such account");
    }
    end.state = st.trees();
    NodeOutput { config_hash: params.config(vk_tree_root), start, end, receipts_root: 0 }
}
