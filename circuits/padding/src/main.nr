use l3x_types::AggOutput;

/// Empty segment. bb's root-rollup verifier requires exactly two nested IPA claims, so the root
/// always verifies two RollupHonk proofs (SPEC.md §9.2). A batch with one real segment pairs it
/// with this circuit's proof, proved with the noir-rollup-no-zk target, which carries bb's
/// default IPA claim. Its output must be the empty aggregation.
fn main(output: pub AggOutput) {
    assert(output.actions_hash == 0, "padding segment must be empty");
    assert(output.count == 0, "padding segment must be empty");
}
