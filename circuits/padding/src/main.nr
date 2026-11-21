use l3x_types::NodeOutput;

/// Empty segment (SPEC.md §9.2). bb's root-rollup verifier needs exactly two nested IPA claims,
/// so the root always verifies two RollupHonk proofs; a batch with one real child pairs it with
/// this circuit's proof, which carries bb's default IPA claim. Its transition is the identity,
/// so it chains after any node.
fn main(out: pub NodeOutput) {
    assert(out.start == out.end, "padding segment must be empty");
}
