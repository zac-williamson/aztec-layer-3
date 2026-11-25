use crate::{
    merge::{VK_ROLE_SLOTS, vk_tree_root_from, VkMembership},
    NodeOutput,
    receipt_node,
};

/// Chonk batch aggregation (SPEC.md §9.2, P2.28). Segments are proved as Mega apps in one Chonk
/// run; batch kernels fold them five at a time with HyperNova and check that they chain, so each
/// segment costs its kernel a folding verification (Goblin defers the elliptic-curve work to the
/// ECCVM) instead of a 740k-gate RollupHonk verification in a merge. One batch tube per run
/// turns the Chonk proof into a merge-tree node.
pub global APPS_PER_KERNEL: u32 = 5;
/// Segment apps: the role-3 segments' Mega builds, slot for slot, and seg_quote's at slot 0
/// (padding, slot 0 of role 3, has no app: a kernel group is padded with APP_PAD instead).
pub global ROLE_SEGMENT_APP: u32 = 6;
/// Batch kernels and the padding app.
pub global ROLE_BATCH: u32 = 7;
pub global SLOT_BK_INIT: u32 = 0;
pub global SLOT_BK_INNER: u32 = 1;
pub global SLOT_BK_TAIL: u32 = 2;
pub global SLOT_APP_PAD: u32 = 3;

/// A kernel's app: any segment app, or the padding app.
pub fn assert_app_vk(vk_hash: Field, m: VkMembership, vk_tree_root: Field) {
    let role = m.index / VK_ROLE_SLOTS;
    assert(
        (role == ROLE_SEGMENT_APP) | (m.index == ROLE_BATCH * VK_ROLE_SLOTS + SLOT_APP_PAD),
        "app VK role not allowed",
    );
    assert(vk_tree_root_from(vk_hash, m) == vk_tree_root, "app VK not in VK tree");
}

/// The kernel a kernel folds: the init or an inner kernel (the tail folds the same).
pub fn assert_kernel_vk(vk_hash: Field, m: VkMembership, vk_tree_root: Field) {
    assert(
        (m.index == ROLE_BATCH * VK_ROLE_SLOTS + SLOT_BK_INIT)
            | (m.index == ROLE_BATCH * VK_ROLE_SLOTS + SLOT_BK_INNER),
        "kernel VK role not allowed",
    );
    assert(vk_tree_root_from(vk_hash, m) == vk_tree_root, "kernel VK not in VK tree");
}

/// One kernel's group of apps: each used this configuration and is an allowed app, and they chain.
/// The group's receipts root pairs the apps level by level, carrying an odd node up unpaired, as
/// the merge tree does over segments.
pub fn group(
    config: Field,
    vk_tree_root: Field,
    outs: [NodeOutput; APPS_PER_KERNEL],
    vk_hashes: [Field; APPS_PER_KERNEL],
    memberships: [VkMembership; APPS_PER_KERNEL],
) -> NodeOutput {
    for i in 0..APPS_PER_KERNEL {
        assert(outs[i].config_hash == config, "app config mismatch");
        assert_app_vk(vk_hashes[i], memberships[i], vk_tree_root);
        if i > 0 {
            assert(outs[i - 1].end == outs[i].start, "apps do not chain");
        }
    }
    let r = outs.map(|o: NodeOutput| o.receipts_root);
    let receipts = receipt_node(receipt_node(receipt_node(r[0], r[1]), receipt_node(r[2], r[3])), r[4]);
    NodeOutput { config_hash: config, start: outs[0].start, end: outs[APPS_PER_KERNEL - 1].end, receipts_root: receipts }
}

/// Appends a group to the transition folded so far.
pub fn extend(prev: NodeOutput, g: NodeOutput) -> NodeOutput {
    assert(prev.config_hash == g.config_hash, "kernel config mismatch");
    assert(prev.end == g.start, "groups do not chain");
    NodeOutput { config_hash: g.config_hash, start: prev.start, end: g.end, receipts_root: receipt_node(prev.receipts_root, g.receipts_root) }
}

