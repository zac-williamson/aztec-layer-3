mod pinned;

use l3x_types::{MEGA_KERNEL_VK_LENGTH, NodeOutput, PROOF_TYPE_HN_FINAL};

/// Hiding batch kernel (SPEC.md §9.2, P2.28): verifies the tail batch kernel (HN_FINAL) and
/// exposes the run's transition as the Chonk proof's public inputs.
fn main(prev: call_data(0) NodeOutput, prev_vk: [Field; MEGA_KERNEL_VK_LENGTH]) -> pub NodeOutput {
    std::verify_proof_with_type(prev_vk, [], [], pinned::BK_TAIL_VK_HASH, PROOF_TYPE_HN_FINAL);
    prev
}
