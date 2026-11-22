use l3x_exchange::{
    book::{best_ask, best_bid, Order, Sibling},
    consts::{BOOK_HEIGHT, DS_BLOCK, LOG_BLOCK, LOG_ORACLE, MARKETS, MAX_PRICE, N_ORACLES, PPM},
    mark::tick,
    oracle_message,
    params::Params,
    sig::{assert_signed, Signature},
    state::State,
};
use l3x_types::{DS_ACTION_LOG, hash::hash, NodeOutput, Running};

/// Oracle updates per block segment.
global U: u32 = 4;

/// A side's best order at the moment of the tick, or a proof that the side is empty.
struct TopOfBook {
    has: bool,
    price: u32,
    seq: u64,
    order: Order,
    path: [Sibling; BOOK_HEIGHT],
}

struct OracleUpdate {
    market: u32,
    price: u64,
    external: u64,
    time: u64,
    signed: [bool; N_ORACLES],
    sigs: [Signature; N_ORACLES],
    bid: TopOfBook,
    ask: TopOfBook,
}

/// Block segment (SPEC.md §8.4, §9.1): opens an L3 block at `block_time` and applies up to U
/// index updates, each signed by at least `oracle_k` of the configured publishers. Every update is
/// a mark tick for its market: it proves the top of book, recomputes the mark, accrues the premium
/// and applies funding when an interval is due. This is the only segment that advances L3 time, so
/// a long gap is always crossed by a block that carries nothing but oracle data.
fn main(
    vk_tree_root: Field,
    params: Params,
    start: Running,
    state: State,
    block_time: u64,
    n: u32,
    updates: [OracleUpdate; U],
) -> pub NodeOutput {
    assert(start.state == state.trees(), "state opening");
    assert(block_time >= start.time, "time regressed");
    assert(n <= U, "too many oracle updates");
    assert(params.oracle_k > 0, "oracle threshold");
    let mut end = start;
    let mut st = state;
    end.time = block_time;
    end.action_log =
        hash([DS_ACTION_LOG, end.action_log, hash([DS_BLOCK, block_time as Field]), LOG_BLOCK]);
    let domain = params.domain();
    for i in 0..U {
        if i < n {
            let u = updates[i];
            assert(u.market < MARKETS, "market");
            let mp = params.markets[u.market];
            assert(mp.listed(), "market not listed");
            let msg = oracle_message(domain, u.market, u.price, u.external, u.time);
            let mut count: u32 = 0;
            for j in 0..N_ORACLES {
                if u.signed[j] {
                    assert_signed(params.oracle_pk_x[j], params.oracle_pk_y[j], u.sigs[j], msg);
                    count += 1;
                }
            }
            assert(count >= params.oracle_k, "not enough oracle signatures");
            let m = st.markets[u.market];
            assert(u.time > m.index_time, "stale oracle update");
            assert(u.time <= block_time, "oracle update from the future");
            assert((u.price > 0) & (u.price < MAX_PRICE), "oracle price out of range");
            assert((u.external > 0) & (u.external < MAX_PRICE), "external mark out of range");
            let old = m.index_price;
            if old != 0 {
                let diff = if u.price > old { u.price - old } else { old - u.price };
                assert(diff * PPM <= old * mp.max_jump_ppm, "oracle jump too large");
            }
            let bb = best_bid(m.book_root, u.bid.has, u.bid.price, u.bid.seq, u.bid.order, u.bid.path);
            let ba = best_ask(m.book_root, u.ask.has, u.ask.price, u.ask.seq, u.ask.order, u.ask.path);
            st.markets[u.market] =
                tick(m, mp, params.funding_interval, u.price, u.external, u.time, bb, ba, block_time);
            end.action_log = hash([DS_ACTION_LOG, end.action_log, msg, LOG_ORACLE]);
        }
    }
    end.state = st.trees();
    NodeOutput { config_hash: params.config(vk_tree_root), start, end, receipts_root: 0 }
}
