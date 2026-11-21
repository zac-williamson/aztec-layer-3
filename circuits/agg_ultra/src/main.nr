mod pinned;

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use l3x_types::{AggOutput, CLIENT_PUBLIC_INPUTS, DS_AGG, hash::hash, MAX_CLIENT_PROOFS};

/// Measurement circuit for M1 (SPEC.md §14): the same work as agg_app, verifying MAX_CLIENT_PROOFS
/// client proofs against the pinned client VK, but in a plain UltraHonk circuit. Proved with the
/// noir-rollup-no-zk target it could enter the merge tree directly, with no Chonk IVC or tube.
/// Not part of the pipeline and not in the VK tree.
fn main(
    client_vk: UltraHonkVerificationKey,
    proofs: [UltraHonkZKProof; MAX_CLIENT_PROOFS],
    public_inputs: [[Field; CLIENT_PUBLIC_INPUTS]; MAX_CLIENT_PROOFS],
    count: u32,
) -> pub AggOutput {
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
