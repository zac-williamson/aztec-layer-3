//! The order book (SPEC.md §6.5): a price-keyed sparse Merkle tree of height 80 whose nodes carry
//! the resting ask and bid lots beneath them. Leaf index = price · 2^48 + seq for asks and
//! price · 2^48 + (2^48 − 1 − seq) for bids. Sequence numbers stay below 2^47, so within a price
//! every bid sits above every ask: a resting bid has no ask at or below its price exactly when no
//! ask lies to its left, and symmetrically for asks.
use crate::consts::{BOOK_HEIGHT, DS_BOOK, DS_ORDER};
use l3x_types::hash::hash;

pub global SIDE_BID: Field = 0;
pub global SIDE_ASK: Field = 1;
pub global SEQ_LIMIT: u64 = 0x800000000000; // 2^47
global TWO_48: Field = 0x1000000000000;
global TWO_64: Field = 0x10000000000000000;

/// A node: one Poseidon2 permutation over (left, right, ask_lots + bid_lots · 2^64, DS_BOOK).
pub fn book_node(left: Field, right: Field, ask: u64, bid: u64) -> Field {
    std::hash::poseidon2_permutation([left, right, (ask as Field) + (bid as Field) * TWO_64, DS_BOOK])[0]
}

pub fn empty_root() -> Field {
    let mut e = 0;
    for _ in 0..BOOK_HEIGHT {
        e = book_node(e, e, 0, 0);
    }
    e
}

pub struct Order {
    pub side: Field,
    pub account_index: u32,
    pub lots: u64,
}

impl Order {
    pub fn empty() -> Self {
        Order { side: 0, account_index: 0, lots: 0 }
    }

    /// The leaf value; an order with no lots left is the empty leaf.
    pub fn leaf(self) -> Field {
        if self.lots == 0 {
            0
        } else {
            hash([DS_ORDER, self.side, self.account_index as Field, self.lots as Field])
        }
    }

    pub fn ask_lots(self) -> u64 {
        if self.side == SIDE_ASK { self.lots } else { 0 }
    }

    pub fn bid_lots(self) -> u64 {
        if self.side == SIDE_BID { self.lots } else { 0 }
    }
}

pub fn order_index(side: Field, price: u32, seq: u64) -> Field {
    assert(seq < SEQ_LIMIT, "sequence number too large");
    let base = (price as Field) * TWO_48;
    if side == SIDE_ASK {
        base + seq as Field
    } else {
        base + (TWO_48 - 1 - seq as Field)
    }
}

pub struct Sibling {
    pub hash: Field,
    pub ask: u64,
    pub bid: u64,
}

pub struct Walk {
    pub root: Field,
    /// Ask lots in subtrees to the left of the leaf, and bid lots to its right.
    pub asks_left: u64,
    pub bids_right: u64,
}

/// Walks from a leaf with the given sums to the root.
pub fn walk(leaf: Field, ask: u64, bid: u64, index: Field, path: [Sibling; BOOK_HEIGHT]) -> Walk {
    let bits: [bool; BOOK_HEIGHT] = index.to_le_bits();
    let mut node = leaf;
    let mut a = ask;
    let mut b = bid;
    let mut asks_left: u64 = 0;
    let mut bids_right: u64 = 0;
    for i in 0..BOOK_HEIGHT {
        let s = path[i];
        let is_right = bits[i];
        let (l, r) = if is_right { (s.hash, node) } else { (node, s.hash) };
        if is_right {
            asks_left += s.ask;
        } else {
            bids_right += s.bid;
        }
        a += s.ask;
        b += s.bid;
        node = book_node(l, r, a, b);
    }
    Walk { root: node, asks_left, bids_right }
}

/// Replaces the order at `index` and returns the new root; `old` must be there now.
pub fn replace(root: Field, index: Field, old: Order, new: Order, path: [Sibling; BOOK_HEIGHT]) -> (Field, Walk) {
    let before = walk(old.leaf(), old.ask_lots(), old.bid_lots(), index, path);
    assert(before.root == root, "book path does not match root");
    let after = walk(new.leaf(), new.ask_lots(), new.bid_lots(), index, path);
    (after.root, before)
}
