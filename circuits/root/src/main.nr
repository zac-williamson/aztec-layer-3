use bb_proof_verification::verify_root_rolluphonk_proof;
use l3x_types::{
    BatchHeader, config_hash, da_finalize, da_iv, merge::{Child, combine}, state_root, trees,
};

/// Root circuit (SPEC.md §9.2–9.4). The top merge: it checks its two children as a merge does,
/// verifies them with verify_root_rolluphonk_proof, which accumulates their IPA claims and closes
/// the accumulator (G1), and binds the batch's whole transition into the header. The result is a
/// plain UltraHonk ZK proof whose only public input is H(header), checked by the Bridge with
/// verify_honk_proof against root_vk_hash.
///
/// The root pins no constants. The VK tree root and parameters come from the configuration it
/// commits to in the header, and the Bridge checks that against its own config_hash (§9.3).
fn main(
    vk_tree_root: Field,
    params_hash: Field,
    left: Child,
    right: Child,
    end_accounts_root: Field,
    end_other_root: Field,
    batch_number: u64,
) -> pub Field {
    let config = config_hash(vk_tree_root, params_hash);
    let out = combine(config, vk_tree_root, left, right);
    verify_root_rolluphonk_proof(left.vk, left.proof, left.out.to_fields(), left.vk_hash);
    verify_root_rolluphonk_proof(right.vk, right.proof, right.out.to_fields(), right.vk_hash);
    let s = out.start;
    let e = out.end;

    assert(batch_number > 0, "batch numbers start at 1");
    // Per-batch accumulators start empty.
    assert(s.action_log == 0, "action log must start empty");
    assert(s.da == da_iv(), "DA must start empty");
    assert(s.da_len == 0, "DA must start empty");
    assert(s.withdrawals == 0, "withdrawals must start empty");
    assert(s.withdrawals_count == 0, "withdrawals must start empty");
    // The new state root opens to the accounts root, so exits can rely on published data alone.
    assert(e.state == trees(end_accounts_root, end_other_root), "end state opening");

    let header = BatchHeader {
        prev_state_root: state_root(s.state, s.priority_cursor, batch_number - 1, s.time),
        new_state_root: state_root(e.state, e.priority_cursor, batch_number, e.time),
        new_accounts_root: end_accounts_root,
        batch_number,
        min_time: s.time,
        max_time: e.time,
        priority_start: s.priority_cursor,
        priority_end: e.priority_cursor,
        priority_head_start: s.priority_head,
        priority_head_end: e.priority_head,
        withdrawals_root: e.withdrawals,
        withdrawals_count: e.withdrawals_count as u64,
        action_log_root: e.action_log,
        da_hash: da_finalize(e.da, e.da_len),
        market_data_hash: 0,
        config_hash: config,
    };
    header.hash()
}
