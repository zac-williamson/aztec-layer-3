//! l3x-native: the L3X operator's cryptography in process (SPEC.md §14). Hashing through bb.js
//! costs a round trip to a bb process per permutation; these bindings compute the same values in
//! the calling thread. Every function mirrors a TypeScript one in scripts/src, and
//! scripts/src/perf/native_check.ts checks them against bb.js and those mirrors.
mod grumpkin;
mod params;
mod poseidon2;
mod tree;

use ark_bn254::{Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger256, PrimeField, Zero};
use napi::bindgen_prelude::BigInt;
use napi::{Error, Result};
use napi_derive::napi;

fn le_bytes(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// A JavaScript bigint as a field element, reduced as bb.js's `toBytes32` reduces it.
fn to_fr(b: &BigInt) -> Fr {
    let v = if b.words.len() <= 4 {
        let mut w = [0u64; 4];
        w[..b.words.len()].copy_from_slice(&b.words);
        Fr::from_bigint(BigInteger256::new(w)).unwrap_or_else(|| Fr::from_le_bytes_mod_order(&le_bytes(&b.words)))
    } else {
        Fr::from_le_bytes_mod_order(&le_bytes(&b.words))
    };
    if b.sign_bit {
        -v
    } else {
        v
    }
}

/// A JavaScript bigint as a Grumpkin scalar, reduced modulo the group order.
fn to_fq(b: &BigInt) -> Fq {
    let v = Fq::from_le_bytes_mod_order(&le_bytes(&b.words));
    if b.sign_bit {
        -v
    } else {
        v
    }
}

fn from_fr(f: Fr) -> BigInt {
    BigInt { sign_bit: false, words: f.into_bigint().0.to_vec() }
}

fn from_fq(f: Fq) -> BigInt {
    BigInt { sign_bit: false, words: f.into_bigint().0.to_vec() }
}

fn to_u128(b: &BigInt) -> Result<u128> {
    if b.sign_bit || b.words.iter().skip(2).any(|w| *w != 0) {
        return Err(Error::from_reason("index out of range"));
    }
    let lo = *b.words.first().unwrap_or(&0) as u128;
    let hi = *b.words.get(1).unwrap_or(&0) as u128;
    Ok(lo | (hi << 64))
}

fn from_u128(x: u128) -> BigInt {
    BigInt { sign_bit: false, words: vec![x as u64, (x >> 64) as u64] }
}

fn affine_out(p: grumpkin::Projective) -> Vec<BigInt> {
    match p.into_affine().xy() {
        None => vec![],
        Some((x, y)) => vec![from_fr(x), from_fr(y)],
    }
}

/// The Poseidon2 permutation of a 4-element state.
#[napi]
pub fn permute(state: Vec<BigInt>) -> Result<Vec<BigInt>> {
    if state.len() != 4 {
        return Err(Error::from_reason("permute takes four elements"));
    }
    let s = poseidon2::permute([to_fr(&state[0]), to_fr(&state[1]), to_fr(&state[2]), to_fr(&state[3])]);
    Ok(s.iter().map(|x| from_fr(*x)).collect())
}

/// The L3X hash (l3x_types/src/hash.nr).
#[napi]
pub fn hash(inputs: Vec<BigInt>) -> BigInt {
    let xs: Vec<Fr> = inputs.iter().map(to_fr).collect();
    from_fr(poseidon2::hash(&xs))
}

/// A binary Merkle tree with nodes hash([ds, left, right]) (tree.ts `MerkleTree`).
#[napi(js_name = "MerkleTree")]
pub struct JsTree {
    inner: tree::Tree,
}

#[napi]
impl JsTree {
    #[napi(constructor)]
    pub fn new(height: u32, ds: BigInt) -> Self {
        JsTree { inner: tree::Tree::new(height as usize, to_fr(&ds)) }
    }

    #[napi(getter)]
    pub fn height(&self) -> u32 {
        self.inner.height as u32
    }

    #[napi(getter)]
    pub fn root(&self) -> BigInt {
        from_fr(self.inner.root())
    }

    #[napi]
    pub fn get(&self, index: BigInt) -> Result<BigInt> {
        Ok(from_fr(self.inner.get(to_u128(&index)?)))
    }

    #[napi]
    pub fn path(&self, index: BigInt) -> Result<Vec<BigInt>> {
        Ok(self.inner.path(to_u128(&index)?).into_iter().map(from_fr).collect())
    }

    #[napi]
    pub fn set(&mut self, index: BigInt, leaf: BigInt) -> Result<()> {
        self.inner.set(to_u128(&index)?, to_fr(&leaf));
        Ok(())
    }

    /// A copy of this tree.
    #[napi]
    pub fn copy(&self) -> JsTree {
        JsTree { inner: self.inner.clone() }
    }

    /// Replaces this tree's contents with a copy of `from`'s.
    #[napi]
    pub fn restore(&mut self, from: &JsTree) {
        self.inner = from.inner.clone();
    }
}

/// The order book's aggregate tree (tree.ts `BookTree`).
#[napi(js_name = "BookTree")]
pub struct JsBook {
    inner: tree::Book,
}

#[napi]
impl JsBook {
    #[napi(constructor)]
    pub fn new(height: u32, ds: BigInt) -> Self {
        JsBook { inner: tree::Book::new(height as usize, to_fr(&ds)) }
    }

    #[napi(getter)]
    pub fn height(&self) -> u32 {
        self.inner.height as u32
    }

    #[napi(getter)]
    pub fn root(&self) -> BigInt {
        from_fr(self.inner.root().hash)
    }

    /// The ask and bid lots in the whole book.
    #[napi]
    pub fn totals(&self) -> Vec<BigInt> {
        let r = self.inner.root();
        vec![from_u128(r.ask), from_u128(r.bid)]
    }

    /// The siblings from the leaf up, flattened as (hash, ask, bid) triples.
    #[napi]
    pub fn path(&self, index: BigInt) -> Result<Vec<BigInt>> {
        let mut out = Vec::with_capacity(3 * self.inner.height);
        for s in self.inner.path(to_u128(&index)?) {
            out.push(from_fr(s.hash));
            out.push(from_u128(s.ask));
            out.push(from_u128(s.bid));
        }
        Ok(out)
    }

    #[napi]
    pub fn set(&mut self, index: BigInt, leaf: BigInt, ask: BigInt, bid: BigInt) -> Result<()> {
        self.inner.set(to_u128(&index)?, to_fr(&leaf), to_u128(&ask)?, to_u128(&bid)?);
        Ok(())
    }

    #[napi]
    pub fn leaves(&self) -> Vec<BigInt> {
        self.inner.leaves().into_iter().map(from_u128).collect()
    }

    #[napi]
    pub fn copy(&self) -> JsBook {
        JsBook { inner: self.inner.clone() }
    }

    #[napi]
    pub fn restore(&mut self, from: &JsBook) {
        self.inner = from.inner.clone();
    }
}

/// k·P on Grumpkin, as [x, y], or [] for the point at infinity (or a P that is not on the curve).
#[napi]
pub fn grumpkin_mul(x: BigInt, y: BigInt, k: BigInt) -> Vec<BigInt> {
    match grumpkin::point(to_fr(&x), to_fr(&y)) {
        None => vec![],
        Some(p) => affine_out(grumpkin::mul(p, to_fq(&k))),
    }
}

/// k·G on Grumpkin, from a fixed-base table.
#[napi]
pub fn grumpkin_base_mul(k: BigInt) -> Vec<BigInt> {
    affine_out(grumpkin::base_mul(to_fq(&k)))
}

/// Schnorr verification (grumpkin.ts `verify`).
#[napi]
pub fn schnorr_verify(pk_x: BigInt, pk_y: BigInt, s: BigInt, e: BigInt, msg: BigInt) -> bool {
    let Some(pk) = grumpkin::point(to_fr(&pk_x), to_fr(&pk_y)) else { return false };
    // The challenge is a hash output, so a valid one is below the field modulus.
    if e.sign_bit || e.words.len() > 4 {
        return false;
    }
    let mut w = [0u64; 4];
    w[..e.words.len()].copy_from_slice(&e.words);
    let Some(e_fr) = Fr::from_bigint(BigInteger256::new(w)) else { return false };
    grumpkin::verify(pk, to_fq(&s), grumpkin::fr_to_fq(e_fr), e_fr, to_fr(&msg))
}

/// One attempt at grumpkin.ts `sign` with the given randomness: [s, e], or [] to retry.
#[napi]
pub fn schnorr_sign(sk: BigInt, msg: BigInt, rand: BigInt) -> Vec<BigInt> {
    let sk = to_fq(&sk);
    if sk.is_zero() {
        return vec![];
    }
    match grumpkin::sign(sk, to_fr(&msg), to_fr(&rand)) {
        None => vec![],
        Some((s, e)) => vec![from_fq(s), from_fr(e)],
    }
}
