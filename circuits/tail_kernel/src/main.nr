mod pinned;

use l3x_types::{AggOutput, MEGA_KERNEL_VK_LENGTH, PROOF_TYPE_HN};

/// Second IVC kernel: folds the init kernel (HN) and passes its output through.
fn main(prev: call_data(0) AggOutput, prev_vk: [Field; MEGA_KERNEL_VK_LENGTH]) -> return_data AggOutput {
    std::verify_proof_with_type(prev_vk, [], [], pinned::INIT_KERNEL_VK_HASH, PROOF_TYPE_HN);
    prev
}
