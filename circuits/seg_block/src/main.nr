use l3x_exchange::{
    consts::{DS_BLOCK, LOG_BLOCK, LOG_ORACLE, MAX_PRICE, PPM},
    oracle_message,
    params::Params,
    sig::{assert_signed, Signature},
    state::State,
};
use l3x_types::{DS_ACTION_LOG, hash::hash, NodeOutput, Running};

struct OracleUpdate {
    price: u64,
    time: u64,
    sig: Signature,
}

/// Block segment (SPEC.md §8.4, §9.1): opens an L3 block at `block_time` and optionally applies
/// one signed index update. It is the only segment that advances L3 time, so a long gap is always
/// crossed by a block that carries nothing but oracle data.
fn main(
    vk_tree_root: Field,
    params: Params,
    start: Running,
    state: State,
    block_time: u64,
    has_update: bool,
    update: OracleUpdate,
) -> pub NodeOutput {
    assert(start.state == state.trees(), "state opening");
    assert(block_time >= start.time, "time regressed");
    let mut end = start;
    let mut st = state;
    end.time = block_time;
    end.action_log =
        hash([DS_ACTION_LOG, end.action_log, hash([DS_BLOCK, block_time as Field]), LOG_BLOCK]);
    if has_update {
        let msg = oracle_message(params.domain(), update.price, update.time);
        assert_signed(params.oracle_pk_x, params.oracle_pk_y, update.sig, msg);
        assert(update.time > st.market.index_time, "stale oracle update");
        assert(update.time <= block_time, "oracle update from the future");
        assert((update.price > 0) & (update.price < MAX_PRICE), "oracle price out of range");
        let old = st.market.index_price;
        if old != 0 {
            let diff = if update.price > old { update.price - old } else { old - update.price };
            assert(diff * PPM <= old * params.max_jump_ppm, "oracle jump too large");
        }
        st.market.index_price = update.price;
        st.market.index_time = update.time;
        end.action_log = hash([DS_ACTION_LOG, end.action_log, msg, LOG_ORACLE]);
    }
    end.state = st.trees();
    NodeOutput { config_hash: params.config(vk_tree_root), start, end }
}
