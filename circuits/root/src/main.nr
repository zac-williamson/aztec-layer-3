mod pinned;

use bb_proof_verification::{RollupHonkProof, RollupHonkVerificationKey, verify_root_rolluphonk_proof};
use l3x_types::{
    AggOutput, BatchHeader, DS_ACCOUNTS, DS_CONFIG, MAX_PRIORITY, DA_LEN, da_hash, hash::hash,
    priority_next_head, state_root,
};

/// Root circuit (SPEC.md §9.2–9.4), reduced for P0. It verifies two RollupHonk proofs with
/// verify_root_rolluphonk_proof, which accumulates their IPA claims and closes the accumulator
/// (G1); bb requires exactly two. P0 has one real segment (the tube) and one padding segment.
/// The result is a plain UltraHonk proof the Bridge checks with verify_honk_proof. The root then
/// binds everything the Bridge checks into the batch header and returns H(header) as its only
/// public input.
///
/// P0 stubs: the "accounts root" absorbs the actions hash; withdrawals and market data are empty.
fn main(
    tube_vk: RollupHonkVerificationKey,
    tube_proof: RollupHonkProof,
    agg: AggOutput,
    padding_vk: RollupHonkVerificationKey,
    padding_proof: RollupHonkProof,
    prev_accounts_root: Field,
    prev_last_time: u64,
    batch_number: u64,
    min_time: u64,
    max_time: u64,
    priority_start: u64,
    priority_n: u32,
    priority_head_start: Field,
    priority_entries: [Field; MAX_PRIORITY],
    da_payload: [Field; DA_LEN],
    config_hash: Field,
) -> pub Field {
    verify_root_rolluphonk_proof(tube_vk, tube_proof, agg.to_fields(), pinned::TUBE_VK_HASH);
    verify_root_rolluphonk_proof(padding_vk, padding_proof, [0, 0], pinned::PADDING_VK_HASH);

    // The configuration commits to the pinned circuit set (stand-in for the VK tree root, §9.3).
    let expected_config = hash(
        [
            DS_CONFIG, pinned::CLIENT_VK_HASH, pinned::AGG_APP_VK_HASH, pinned::INIT_KERNEL_VK_HASH,
            pinned::TAIL_KERNEL_VK_HASH, pinned::CHONK_VK_HASH, pinned::TUBE_VK_HASH,
            pinned::PADDING_VK_HASH,
        ],
    );
    assert(config_hash == expected_config, "config mismatch");

    assert(batch_number > 0, "batch numbers start at 1");
    assert(min_time <= max_time, "time order");
    assert(prev_last_time <= min_time, "time regressed");
    assert(priority_n <= MAX_PRIORITY, "too many priority entries");

    // Fold exactly priority_n consumed entries from the head the Bridge holds for priority_start.
    let mut head = priority_head_start;
    for i in 0..MAX_PRIORITY {
        if i < priority_n {
            head = priority_next_head(head, priority_entries[i]);
        }
    }
    let priority_end = priority_start + priority_n as u64;

    let prev_state_root = state_root(prev_accounts_root, priority_start, batch_number - 1, prev_last_time);
    let new_accounts_root = hash([DS_ACCOUNTS, prev_accounts_root, agg.actions_hash]);
    let new_state_root = state_root(new_accounts_root, priority_end, batch_number, max_time);

    let header = BatchHeader {
        prev_state_root,
        new_state_root,
        new_accounts_root,
        batch_number,
        min_time,
        max_time,
        priority_start,
        priority_end,
        priority_head_start,
        priority_head_end: head,
        withdrawals_root: 0,
        withdrawals_count: 0,
        action_log_root: agg.actions_hash,
        da_hash: da_hash(da_payload),
        market_data_hash: 0,
        config_hash,
    };
    header.hash()
}
