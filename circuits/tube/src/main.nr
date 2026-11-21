mod pinned;

use l3x_types::{
    AggOutput, CHONK_PROOF_LENGTH, CHONK_VK_LENGTH, DS_ACTION_LOG, hash::hash, NodeOutput,
    PROOF_TYPE_CHONK, Running,
};

/// Tube (SPEC.md §9.2): the merge-tree leaf of a P-segment. Verifies the segment's Chonk proof
/// against the pinned Chonk VK (the hiding kernel's VK) and records it in the action log.
/// Proved with the noir-rollup-no-zk target, so the IPA claim produced by the Chonk verifier
/// travels up the merge tree to the root.
///
/// P1 executes no client-proof actions (the lane arrives in P2), so the tube changes no state.
fn main(
    chonk_vk: [Field; CHONK_VK_LENGTH],
    chonk_proof: [Field; CHONK_PROOF_LENGTH],
    agg: AggOutput,
    config_hash: Field,
    start: Running,
) -> pub NodeOutput {
    std::verify_proof_with_type(
        chonk_vk,
        chonk_proof,
        agg.to_fields(),
        pinned::CHONK_VK_HASH,
        PROOF_TYPE_CHONK,
    );
    let mut end = start;
    end.action_log = hash([DS_ACTION_LOG, start.action_log, agg.actions_hash, agg.count as Field]);
    NodeOutput { config_hash, start, end }
}
