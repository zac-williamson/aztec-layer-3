//! The state trees, mirroring scripts/src/exchange/tree.ts and circuits/l3x_exchange/src/{tree,book}.nr:
//! a binary Merkle tree with nodes hash([ds, left, right]), and the order book's aggregate tree,
//! whose nodes carry the ask and bid lots beneath them. Empty leaves are zero; only written nodes
//! are stored.
use crate::poseidon2::{hash3, iv, permute};
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Zero};
use rustc_hash::FxHashMap;

#[derive(Clone)]
pub struct Tree {
    pub height: usize,
    ds: Fr,
    iv3: Fr,
    empty: Vec<Fr>,
    levels: Vec<FxHashMap<u128, Fr>>,
}

impl Tree {
    pub fn new(height: usize, ds: Fr) -> Self {
        let iv3 = iv(3);
        let mut empty = vec![Fr::ZERO];
        for i in 0..height {
            let e = empty[i];
            empty.push(hash3(ds, e, e, iv3));
        }
        Tree { height, ds, iv3, empty, levels: vec![FxHashMap::default(); height + 1] }
    }

    #[inline(always)]
    fn node(&self, level: usize, index: u128) -> Fr {
        self.levels[level].get(&index).copied().unwrap_or(self.empty[level])
    }

    pub fn root(&self) -> Fr {
        self.node(self.height, 0)
    }

    pub fn get(&self, index: u128) -> Fr {
        self.node(0, index)
    }

    pub fn path(&self, index: u128) -> Vec<Fr> {
        let mut idx = index;
        (0..self.height)
            .map(|level| {
                let s = self.node(level, idx ^ 1);
                idx >>= 1;
                s
            })
            .collect()
    }

    pub fn set(&mut self, index: u128, leaf: Fr) {
        self.levels[0].insert(index, leaf);
        let mut idx = index;
        let mut cur = leaf;
        for level in 0..self.height {
            let sib = self.node(level, idx ^ 1);
            cur = if idx & 1 == 1 { hash3(self.ds, sib, cur, self.iv3) } else { hash3(self.ds, cur, sib, self.iv3) };
            idx >>= 1;
            self.levels[level + 1].insert(idx, cur);
        }
    }
}

#[derive(Clone, Copy)]
pub struct BookNode {
    pub hash: Fr,
    pub ask: u128,
    pub bid: u128,
}

#[derive(Clone)]
pub struct Book {
    pub height: usize,
    ds: Fr,
    two_64: Fr,
    empty: Vec<Fr>,
    levels: Vec<FxHashMap<u128, BookNode>>,
}

impl Book {
    pub fn new(height: usize, ds: Fr) -> Self {
        let two_64 = Fr::from(1u128 << 64);
        let mut b = Book { height, ds, two_64, empty: vec![Fr::ZERO], levels: vec![FxHashMap::default(); height + 1] };
        for i in 0..height {
            let e = b.empty[i];
            let n = b.node_hash(e, e, 0, 0);
            b.empty.push(n);
        }
        b
    }

    /// book.nr `book_node`: one permutation over (left, right, ask + bid · 2^64, DS_BOOK).
    #[inline(always)]
    fn node_hash(&self, l: Fr, r: Fr, ask: u128, bid: u128) -> Fr {
        permute([l, r, Fr::from(ask) + Fr::from(bid) * self.two_64, self.ds])[0]
    }

    #[inline(always)]
    pub fn node(&self, level: usize, index: u128) -> BookNode {
        self.levels[level].get(&index).copied().unwrap_or(BookNode { hash: self.empty[level], ask: 0, bid: 0 })
    }

    pub fn root(&self) -> BookNode {
        self.node(self.height, 0)
    }

    pub fn path(&self, index: u128) -> Vec<BookNode> {
        let mut idx = index;
        (0..self.height)
            .map(|level| {
                let s = self.node(level, idx ^ 1);
                idx >>= 1;
                s
            })
            .collect()
    }

    /// Writes a leaf with its ask and bid lots and updates the path; a zero leaf is removed.
    pub fn set(&mut self, index: u128, leaf: Fr, ask: u128, bid: u128) {
        let mut cur = BookNode { hash: leaf, ask, bid };
        if leaf.is_zero() {
            self.levels[0].remove(&index);
        } else {
            self.levels[0].insert(index, cur);
        }
        let mut idx = index;
        for level in 0..self.height {
            let sib = self.node(level, idx ^ 1);
            let (l, r) = if idx & 1 == 1 { (sib, cur) } else { (cur, sib) };
            let a = l.ask + r.ask;
            let b = l.bid + r.bid;
            cur = BookNode { hash: self.node_hash(l.hash, r.hash, a, b), ask: a, bid: b };
            idx >>= 1;
            self.levels[level + 1].insert(idx, cur);
        }
    }

    /// Indices of the non-empty leaves, in index order.
    pub fn leaves(&self) -> Vec<u128> {
        let mut v: Vec<u128> = self.levels[0].keys().copied().collect();
        v.sort_unstable();
        v
    }
}
