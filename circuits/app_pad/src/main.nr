use l3x_types::NodeOutput;

/// Padding app (SPEC.md §9.2, P2.28): fills a batch kernel's last group of five. Its transition
/// is the identity and it carries no receipts, like the padding segment.
fn main(out: NodeOutput) -> return_data NodeOutput {
    assert(out.start == out.end, "padding app must be empty");
    assert(out.receipts_root == 0, "padding app must be empty");
    out
}
