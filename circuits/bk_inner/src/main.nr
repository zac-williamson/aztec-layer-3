use l3x_types::{
    batch::{APPS_PER_KERNEL, assert_kernel_vk, extend, group}, config_hash, MEGA_APP_VK_LENGTH,
    MEGA_KERNEL_VK_LENGTH, merge::VkMembership, NodeOutput, PROOF_TYPE_HN,
};

/// Inner batch kernel (SPEC.md §9.2, P2.28): folds the previous batch kernel and the next five
/// segment apps, and extends the transition. The previous kernel is the init or an inner kernel,
/// so its VK is checked by membership in the VK tree, not pinned.
fn main(
    vk_tree_root: Field,
    params_hash: Field,
    prev: call_data(0) NodeOutput,
    prev_vk: [Field; MEGA_KERNEL_VK_LENGTH],
    prev_vk_hash: Field,
    prev_membership: VkMembership,
    a0: call_data(1) NodeOutput,
    a1: call_data(2) NodeOutput,
    a2: call_data(3) NodeOutput,
    a3: call_data(4) NodeOutput,
    a4: call_data(5) NodeOutput,
    vks: [[Field; MEGA_APP_VK_LENGTH]; APPS_PER_KERNEL],
    vk_hashes: [Field; APPS_PER_KERNEL],
    memberships: [VkMembership; APPS_PER_KERNEL],
) -> return_data NodeOutput {
    std::verify_proof_with_type(prev_vk, [], [], prev_vk_hash, PROOF_TYPE_HN);
    for i in 0..APPS_PER_KERNEL {
        std::verify_proof_with_type(vks[i], [], [], vk_hashes[i], PROOF_TYPE_HN);
    }
    let config = config_hash(vk_tree_root, params_hash);
    assert(prev.config_hash == config, "kernel config mismatch");
    assert_kernel_vk(prev_vk_hash, prev_membership, vk_tree_root);
    extend(prev, group(config, vk_tree_root, [a0, a1, a2, a3, a4], vk_hashes, memberships))
}
