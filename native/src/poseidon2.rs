//! Poseidon2 over the BN254 scalar field (t = 4, d = 5, 8 full and 56 partial rounds), as
//! barretenberg's `Poseidon2Permutation` computes it, and the L3X sponge of
//! circuits/l3x_types/src/hash.nr.
use crate::params::{DIAG_MINUS_ONE, ROUNDS_F, ROUNDS_P, ROUND_CONSTANTS};
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};

#[inline(always)]
fn sbox(x: &mut Fr) {
    let x4 = x.square().square();
    *x *= x4;
}

/// The external linear layer: the 4×4 MDS matrix [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]].
#[inline(always)]
fn external(s: &mut [Fr; 4]) {
    let t0 = s[0] + s[1];
    let t1 = s[2] + s[3];
    let t2 = s[1].double() + t1;
    let t3 = s[3].double() + t0;
    let t4 = t1.double().double() + t3;
    let t5 = t0.double().double() + t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    *s = [t6, t5, t7, t4];
}

/// The internal linear layer: x_i ← (D_i − 1)·x_i + Σx.
#[inline(always)]
fn internal(s: &mut [Fr; 4]) {
    let sum = s[0] + s[1] + s[2] + s[3];
    for i in 0..4 {
        s[i] *= DIAG_MINUS_ONE[i];
        s[i] += sum;
    }
}

pub fn permute(mut s: [Fr; 4]) -> [Fr; 4] {
    external(&mut s);
    let half = ROUNDS_F / 2;
    for rc in &ROUND_CONSTANTS[..half] {
        for i in 0..4 {
            s[i] += rc[i];
            sbox(&mut s[i]);
        }
        external(&mut s);
    }
    for rc in &ROUND_CONSTANTS[half..half + ROUNDS_P] {
        s[0] += rc[0];
        sbox(&mut s[0]);
        internal(&mut s);
    }
    for rc in &ROUND_CONSTANTS[half + ROUNDS_P..] {
        for i in 0..4 {
            s[i] += rc[i];
            sbox(&mut s[i]);
        }
        external(&mut s);
    }
    s
}

/// The capacity element of a sponge over `n` inputs: n · 2^64.
#[inline(always)]
pub fn iv(n: usize) -> Fr {
    Fr::from((n as u128) << 64)
}

/// The L3X hash: a Poseidon2 sponge of rate 3 with the input length in the capacity element.
pub fn hash(inputs: &[Fr]) -> Fr {
    let mut s = [Fr::ZERO, Fr::ZERO, Fr::ZERO, iv(inputs.len())];
    let mut pos = 0;
    for x in inputs {
        s[pos] += x;
        pos += 1;
        if pos == 3 {
            s = permute(s);
            pos = 0;
        }
    }
    if pos != 0 {
        s = permute(s);
    }
    s[0]
}

/// hash([a, b, c]): one permutation.
#[inline(always)]
pub fn hash3(a: Fr, b: Fr, c: Fr, iv3: Fr) -> Fr {
    permute([a, b, c, iv3])[0]
}
