mod pinned;

use l3x_types::{
    AggOutput, CHONK_PROOF_LENGTH, CHONK_VK_LENGTH, DS_ACCOUNTS, DS_ACTION_LOG, hash::hash, NodeOutput,
    PROOF_TYPE_CHONK, Running, trees,
};

/// Tube (SPEC.md §9.2): the merge-tree leaf of a P-segment. Verifies the segment's Chonk proof
/// against the pinned Chonk VK (the hiding kernel's VK) and applies the segment's effect to the
/// running state. Proved with the noir-rollup-no-zk target, so the IPA claim produced by the
/// Chonk verifier travels up the merge tree to the root.
///
/// P0 stub effect: the accounts root absorbs the actions hash, and the action log records it.
fn main(
    chonk_vk: [Field; CHONK_VK_LENGTH],
    chonk_proof: [Field; CHONK_PROOF_LENGTH],
    agg: AggOutput,
    config_hash: Field,
    start: Running,
    accounts_root: Field,
    other_root: Field,
) -> pub NodeOutput {
    std::verify_proof_with_type(
        chonk_vk,
        chonk_proof,
        agg.to_fields(),
        pinned::CHONK_VK_HASH,
        PROOF_TYPE_CHONK,
    );
    assert(start.state == trees(accounts_root, other_root), "state opening");
    let mut end = start;
    end.state = trees(hash([DS_ACCOUNTS, accounts_root, agg.actions_hash]), other_root);
    end.action_log = hash([DS_ACTION_LOG, start.action_log, agg.actions_hash, agg.count as Field]);
    NodeOutput { config_hash, start, end }
}
