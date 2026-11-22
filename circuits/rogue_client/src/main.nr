/// Adversarial test fixture, never deployed: a client circuit with the client interface that
/// authorizes any message for any account and auth binding without knowing anything. Its VK is not
/// in the client subtree, so agg_app must reject its proofs (SPEC.md §3 G2, §9.3);
/// scripts/src/vk_substitution.ts checks that it does.
/// Public inputs, in order: (msg, account_index, auth_binding).
fn main(msg: pub Field, account_index: pub Field, auth_binding: pub Field) {
    let _ = (msg, account_index, auth_binding);
}
