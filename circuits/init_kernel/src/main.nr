mod pinned;

use l3x_types::{AggOutput, MEGA_APP_VK_LENGTH, PROOF_TYPE_OINK};

/// First IVC kernel: accumulates the aggregation app (OINK) and passes its output through.
/// The app VK is a witness but its hash is pinned, and barretenberg enforces
/// hash(app_vk) == key_hash, so only agg_app can occupy the app slot.
fn main(app_output: call_data(1) AggOutput, app_vk: [Field; MEGA_APP_VK_LENGTH]) -> return_data AggOutput {
    std::verify_proof_with_type(app_vk, [], [], pinned::AGG_APP_VK_HASH, PROOF_TYPE_OINK);
    app_output
}
