use l3x_types::{batch::assert_kernel_vk, config_hash, MEGA_KERNEL_VK_LENGTH, merge::VkMembership, NodeOutput, PROOF_TYPE_HN};

/// Tail batch kernel (SPEC.md §9.2, P2.28): folds the last init or inner kernel and passes the
/// run's transition on. bb masks the op queue in the circuit before the hiding kernel.
fn main(
    vk_tree_root: Field,
    params_hash: Field,
    prev: call_data(0) NodeOutput,
    prev_vk: [Field; MEGA_KERNEL_VK_LENGTH],
    prev_vk_hash: Field,
    prev_membership: VkMembership,
) -> return_data NodeOutput {
    std::verify_proof_with_type(prev_vk, [], [], prev_vk_hash, PROOF_TYPE_HN);
    assert(prev.config_hash == config_hash(vk_tree_root, params_hash), "kernel config mismatch");
    assert_kernel_vk(prev_vk_hash, prev_membership, vk_tree_root);
    prev
}
