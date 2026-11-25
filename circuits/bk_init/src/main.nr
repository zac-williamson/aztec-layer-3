use l3x_types::{
    batch::{APPS_PER_KERNEL, group}, config_hash, MEGA_APP_VK_LENGTH, merge::VkMembership, NodeOutput,
    PROOF_TYPE_HN, PROOF_TYPE_OINK,
};

/// First batch kernel (SPEC.md §9.2, P2.28): folds the run's first five segment apps (the first
/// by its Oink proof, the rest by HyperNova) and outputs their chained transition. Each app's
/// output arrives on the databus (call_data(1..5)), which bb binds to that app's return data.
fn main(
    vk_tree_root: Field,
    params_hash: Field,
    a0: call_data(1) NodeOutput,
    a1: call_data(2) NodeOutput,
    a2: call_data(3) NodeOutput,
    a3: call_data(4) NodeOutput,
    a4: call_data(5) NodeOutput,
    vks: [[Field; MEGA_APP_VK_LENGTH]; APPS_PER_KERNEL],
    vk_hashes: [Field; APPS_PER_KERNEL],
    memberships: [VkMembership; APPS_PER_KERNEL],
) -> return_data NodeOutput {
    std::verify_proof_with_type(vks[0], [], [], vk_hashes[0], PROOF_TYPE_OINK);
    for i in 1..APPS_PER_KERNEL {
        std::verify_proof_with_type(vks[i], [], [], vk_hashes[i], PROOF_TYPE_HN);
    }
    group(config_hash(vk_tree_root, params_hash), vk_tree_root, [a0, a1, a2, a3, a4], vk_hashes, memberships)
}
