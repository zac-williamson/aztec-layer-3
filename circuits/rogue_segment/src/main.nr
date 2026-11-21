use l3x_types::NodeOutput;

/// Adversarial fixture for the VK tests: a rollup-target circuit that claims any transition.
/// It is never placed in the VK tree. Never deployed.
fn main(out: pub NodeOutput) {
    assert(out.end.time == out.end.time);
}
