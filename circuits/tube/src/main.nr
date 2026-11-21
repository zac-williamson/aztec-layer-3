mod pinned;

use l3x_types::{AggOutput, CHONK_PROOF_LENGTH, CHONK_VK_LENGTH, PROOF_TYPE_CHONK};

/// Tube (SPEC.md §9.2): verifies the segment's Chonk proof against the pinned Chonk VK (the
/// hiding kernel's VK) and re-exposes its output. Proved with the noir-rollup-no-zk target,
/// so the IPA claim produced by the Chonk verifier is carried to the root.
fn main(
    chonk_vk: [Field; CHONK_VK_LENGTH],
    chonk_proof: [Field; CHONK_PROOF_LENGTH],
    output: pub AggOutput,
) {
    std::verify_proof_with_type(
        chonk_vk,
        chonk_proof,
        output.to_fields(),
        pinned::CHONK_VK_HASH,
        PROOF_TYPE_CHONK,
    );
}
