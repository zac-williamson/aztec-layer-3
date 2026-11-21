mod pinned;

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use l3x_types::{AggOutput, CLIENT_PUBLIC_INPUTS, DS_AGG, MAX_CLIENT_PROOFS, hash::hash};

/// Chonk app circuit (SPEC.md §7.4, §9.2 P-segment). Verifies MAX_CLIENT_PROOFS proofs of the
/// pinned client circuit and folds the first `count` public-input triples, together with the
/// client VK hash, into a hash chain. Slots at index >= count carry a fixed valid dummy proof.
/// The client VK hash is a compile-time constant, so no other circuit's proofs are accepted (G2).
fn main(
    client_vk: UltraHonkVerificationKey,
    proofs: [UltraHonkZKProof; MAX_CLIENT_PROOFS],
    public_inputs: [[Field; CLIENT_PUBLIC_INPUTS]; MAX_CLIENT_PROOFS],
    count: u32,
) -> return_data AggOutput {
    assert(count <= MAX_CLIENT_PROOFS, "too many client proofs");
    let mut acc: Field = 0;
    for i in 0..MAX_CLIENT_PROOFS {
        verify_honk_proof(client_vk, proofs[i], public_inputs[i], pinned::CLIENT_VK_HASH);
        if i < count {
            let pi = public_inputs[i];
            acc = hash([DS_AGG, acc, pinned::CLIENT_VK_HASH, pi[0], pi[1], pi[2]]);
        }
    }
    AggOutput { actions_hash: acc, count }
}
