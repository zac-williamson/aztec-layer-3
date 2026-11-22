use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use l3x_types::{
    AggOutput, CLIENT_PUBLIC_INPUTS, DS_AGG, hash::hash, MAX_CLIENT_PROOFS,
    merge::{ROLE_CLIENT, VK_ROLE_SLOTS, vk_tree_root_from, VkMembership},
};

/// Measurement circuit for M1 (SPEC.md §14): the same work as agg_app, verifying MAX_CLIENT_PROOFS
/// client proofs against VKs in the client subtree, but in a plain UltraHonk circuit. Proved with
/// the noir-rollup-no-zk target it could enter the merge tree directly, with no Chonk IVC or tube.
/// Not part of the pipeline and not in the VK tree.
fn main(
    vk_tree_root: Field,
    client_vks: [UltraHonkVerificationKey; MAX_CLIENT_PROOFS],
    vk_hashes: [Field; MAX_CLIENT_PROOFS],
    memberships: [VkMembership; MAX_CLIENT_PROOFS],
    proofs: [UltraHonkZKProof; MAX_CLIENT_PROOFS],
    public_inputs: [[Field; CLIENT_PUBLIC_INPUTS]; MAX_CLIENT_PROOFS],
    count: u32,
) -> pub AggOutput {
    assert(count <= MAX_CLIENT_PROOFS, "too many client proofs");
    let mut acc: Field = 0;
    for i in 0..MAX_CLIENT_PROOFS {
        verify_honk_proof(client_vks[i], proofs[i], public_inputs[i], vk_hashes[i]);
        assert(memberships[i].index / VK_ROLE_SLOTS == ROLE_CLIENT, "client VK role not allowed");
        assert(vk_tree_root_from(vk_hashes[i], memberships[i]) == vk_tree_root, "client VK not in VK tree");
        if i < count {
            let pi = public_inputs[i];
            acc = hash([DS_AGG, acc, vk_hashes[i], pi[0], pi[1], pi[2]]);
        }
    }
    AggOutput { actions_hash: acc, count, vk_tree_root }
}
