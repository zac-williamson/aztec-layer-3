use bb_proof_verification::verify_rolluphonk_proof;
use l3x_types::{config_hash, merge::{Child, combine}, NodeOutput};

/// Merge (SPEC.md §9.2): verifies two merge-tree nodes as RollupHonk proofs, checks that both
/// used this configuration, that their VKs sit in the tube, segment or merge subtrees of the VK
/// tree, and that they chain, and outputs the combined transition. bb accumulates the two
/// children's IPA claims into this proof's claim. Proved with the noir-rollup-no-zk target.
///
/// The VK tree root is a witness bound by config_hash, not a constant, because a merge verifies
/// merges and so cannot contain its own VK hash.
fn main(vk_tree_root: Field, params_hash: Field, left: Child, right: Child) -> pub NodeOutput {
    let out = combine(config_hash(vk_tree_root, params_hash), vk_tree_root, left, right);
    verify_rolluphonk_proof(left.vk, left.proof, left.out.to_fields(), left.vk_hash);
    verify_rolluphonk_proof(right.vk, right.proof, right.out.to_fields(), right.vk_hash);
    out
}
