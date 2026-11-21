use crate::{DS_VK_NODE, hash::hash, NodeOutput};
use bb_proof_verification::{RollupHonkProof, RollupHonkVerificationKey};

/// Role-partitioned VK tree (SPEC.md §9.3). Leaf index = role * VK_ROLE_SLOTS + slot, so each
/// role owns one aligned subtree; the leaf is the VK hash and empty slots are zero.
pub global VK_TREE_HEIGHT: u32 = 6;
pub global VK_ROLE_SLOTS: u32 = 8;
pub global VK_TREE_LEAVES: u32 = 64;
pub global ROLE_CLIENT: u32 = 0;
pub global ROLE_CHONK: u32 = 1;
pub global ROLE_TUBE: u32 = 2;
pub global ROLE_SEGMENT: u32 = 3;
pub global ROLE_MERGE: u32 = 4;

pub struct VkMembership {
    pub index: u32,
    pub path: [Field; VK_TREE_HEIGHT],
}

pub fn vk_node(left: Field, right: Field) -> Field {
    hash([DS_VK_NODE, left, right])
}

pub fn vk_tree_root_from(leaf: Field, m: VkMembership) -> Field {
    assert(m.index < VK_TREE_LEAVES, "VK index out of range");
    let mut node = leaf;
    let mut idx = m.index;
    for i in 0..VK_TREE_HEIGHT {
        node = if idx % 2 == 0 {
            vk_node(node, m.path[i])
        } else {
            vk_node(m.path[i], node)
        };
        idx = idx / 2;
    }
    node
}

/// A child of a merge or of the root: a RollupHonk proof of some merge-tree node, its VK, the VK
/// hash (bb constrains hash(vk) == vk_hash), the VK's place in the VK tree, and the node's output.
pub struct Child {
    pub vk: RollupHonkVerificationKey,
    pub proof: RollupHonkProof,
    pub vk_hash: Field,
    pub membership: VkMembership,
    pub out: NodeOutput,
}

/// Merges and the root accept tubes, segments and merges as children, and nothing else, so a
/// client, Chonk or root proof can never stand in for a segment.
pub fn assert_merge_child_vk(vk_hash: Field, m: VkMembership, vk_tree_root: Field) {
    let role = m.index / VK_ROLE_SLOTS;
    assert(
        (role == ROLE_TUBE) | (role == ROLE_SEGMENT) | (role == ROLE_MERGE),
        "child VK role not allowed",
    );
    assert(vk_tree_root_from(vk_hash, m) == vk_tree_root, "child VK not in VK tree");
}

/// Everything a merge and the root check about two children except the proofs themselves: both
/// used this configuration, both VKs are allowed, and the left child's end is the right child's
/// start. Returns the combined transition.
pub fn combine(config_hash: Field, vk_tree_root: Field, left: Child, right: Child) -> NodeOutput {
    assert(left.out.config_hash == config_hash, "left child config mismatch");
    assert(right.out.config_hash == config_hash, "right child config mismatch");
    assert_merge_child_vk(left.vk_hash, left.membership, vk_tree_root);
    assert_merge_child_vk(right.vk_hash, right.membership, vk_tree_root);
    assert(left.out.end == right.out.start, "children do not chain");
    NodeOutput { config_hash, start: left.out.start, end: right.out.end }
}

/// Root of the VK tree over all its leaves. Used by the Bridge when a new configuration is
/// scheduled, so the published preimage is checked on-chain.
pub fn vk_tree_root_of(leaves: [Field; VK_TREE_LEAVES]) -> Field {
    let mut layer = leaves;
    let mut width = VK_TREE_LEAVES;
    for _ in 0..VK_TREE_HEIGHT {
        width = width / 2;
        for i in 0..VK_TREE_LEAVES / 2 {
            if i < width {
                layer[i] = vk_node(layer[2 * i], layer[2 * i + 1]);
            }
        }
    }
    layer[0]
}

#[test]
fn test_vk_tree_root_matches_membership() {
    let mut leaves: [Field; VK_TREE_LEAVES] = [0; VK_TREE_LEAVES];
    for i in 0..VK_TREE_LEAVES {
        leaves[i] = (i * 7 + 1) as Field;
    }
    let root = vk_tree_root_of(leaves);
    // Build the path of leaf 27 from the layers by hand.
    let index: u32 = 27;
    let mut path: [Field; VK_TREE_HEIGHT] = [0; VK_TREE_HEIGHT];
    let mut layer = leaves;
    let mut idx = index;
    let mut width = VK_TREE_LEAVES;
    for level in 0..VK_TREE_HEIGHT {
        path[level] = layer[idx ^ 1];
        width = width / 2;
        for i in 0..VK_TREE_LEAVES / 2 {
            if i < width {
                layer[i] = vk_node(layer[2 * i], layer[2 * i + 1]);
            }
        }
        idx = idx / 2;
    }
    assert(vk_tree_root_from(leaves[index], VkMembership { index, path }) == root);
}
