mod pinned;

use l3x_types::{AggOutput, MEGA_KERNEL_VK_LENGTH, PROOF_TYPE_HN_FINAL};

/// Final IVC kernel: verifies the tail kernel (HN_FINAL) and exposes the aggregation output as
/// the Chonk proof's public inputs.
fn main(prev: call_data(0) AggOutput, prev_vk: [Field; MEGA_KERNEL_VK_LENGTH]) -> pub AggOutput {
    std::verify_proof_with_type(prev_vk, [], [], pinned::TAIL_KERNEL_VK_HASH, PROOF_TYPE_HN_FINAL);
    prev
}
