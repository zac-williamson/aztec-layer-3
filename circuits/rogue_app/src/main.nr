use l3x_types::AggOutput;

/// Adversarial test fixture, never deployed. It has the same databus interface as agg_app but
/// verifies nothing and returns any output the prover chooses. scripts/src/vk_substitution.ts
/// folds it into the IVC in place of agg_app; proving MUST fail because init_kernel pins the
/// agg_app VK hash (SPEC.md §3 G2, §17).
fn main(actions_hash: Field, count: u32) -> return_data AggOutput {
    AggOutput { actions_hash, count }
}
