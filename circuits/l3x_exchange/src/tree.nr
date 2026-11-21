use l3x_types::hash::hash;

/// Root of a binary Merkle tree of height H from a leaf, its index and its siblings (leaf level
/// first). Nodes are hash([ds, left, right]).
pub fn merkle_root<let H: u32>(ds: Field, leaf: Field, index: u32, path: [Field; H]) -> Field {
    let mut node = leaf;
    let mut idx = index;
    for i in 0..H {
        let (l, r) = if idx & 1 == 0 { (node, path[i]) } else { (path[i], node) };
        node = hash([ds, l, r]);
        idx = idx >> 1;
    }
    node
}

/// Root of the empty tree of height H (empty leaves are zero).
pub fn empty_root<let H: u32>(ds: Field) -> Field {
    let mut e = 0;
    for _ in 0..H {
        e = hash([ds, e, e]);
    }
    e
}

/// Proves `old_leaf` at `index` under `root` and returns the root after writing `new_leaf`.
pub fn update<let H: u32>(
    ds: Field,
    root: Field,
    index: u32,
    old_leaf: Field,
    new_leaf: Field,
    path: [Field; H],
) -> Field {
    assert(merkle_root(ds, old_leaf, index, path) == root, "Merkle path does not match root");
    merkle_root(ds, new_leaf, index, path)
}
