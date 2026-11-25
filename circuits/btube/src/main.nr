mod pinned;

use l3x_types::{CHONK_PROOF_LENGTH, CHONK_VK_LENGTH, NodeOutput, PROOF_TYPE_CHONK};

/// Batch tube (SPEC.md §9.2, P2.28): verifies a Chonk run of segment apps against the pinned
/// hiding batch kernel VK and outputs its transition as a merge-tree node. The kernels checked
/// the configuration, the app VKs and the chaining. Proved with the noir-rollup-no-zk target,
/// so the IPA claim from the Chonk verifier travels to the root.
fn main(chonk_vk: [Field; CHONK_VK_LENGTH], chonk_proof: [Field; CHONK_PROOF_LENGTH], out: NodeOutput) -> pub NodeOutput {
    std::verify_proof_with_type(chonk_vk, chonk_proof, out.to_fields(), pinned::BK_CHONK_VK_HASH, PROOF_TYPE_CHONK);
    out
}
