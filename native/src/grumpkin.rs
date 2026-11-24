//! Grumpkin (y² = x³ − 17 over the BN254 scalar field; its group order is the BN254 base field
//! modulus) and Schnorr signatures with a Poseidon2 challenge, matching noir-lang/schnorr v0.4.0 and
//! scripts/src/exchange/grumpkin.ts (SPEC.md §7.1):
//!   R = s·G + e·PK,  e = H(DST, R.x, PK.x, PK.y, msg).
use crate::poseidon2::hash;
use ark_bn254::{Fq, Fr};
use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{Affine as SwAffine, Projective as SwProjective, SWCurveConfig},
    AffineRepr, CurveGroup,
};
use ark_ff::{AdditiveGroup, BigInteger, Field, MontFp, PrimeField, Zero};
use std::sync::OnceLock;

#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
pub struct GrumpkinConfig;

impl CurveConfig for GrumpkinConfig {
    type BaseField = Fr;
    type ScalarField = Fq;
    const COFACTOR: &'static [u64] = &[1];
    const COFACTOR_INV: Fq = Fq::ONE;
}

impl SWCurveConfig for GrumpkinConfig {
    const COEFF_A: Fr = Fr::ZERO;
    const COEFF_B: Fr = MontFp!("-17");
    const GENERATOR: SwAffine<Self> =
        SwAffine::new_unchecked(MontFp!("1"), MontFp!("17631683881184975370165255887551781615748388533673675138860"));

    #[inline(always)]
    fn mul_by_a(_: Fr) -> Fr {
        Fr::ZERO
    }
}

pub type Affine = SwAffine<GrumpkinConfig>;
pub type Projective = SwProjective<GrumpkinConfig>;

/// "l3x.nonce" (grumpkin.ts DS_NONCE) and noir-lang/schnorr's challenge domain separator.
pub const DS_NONCE: Fr = MontFp!("1995957125305621963621");
pub const SCHNORR_DST: Fr = MontFp!("1039724458310855835854085587815411796074386164731432807240139482077033366318");

/// d · 16^w · G for every window w < 64 and digit d < 16.
fn base_table() -> &'static Vec<[Affine; 16]> {
    static TABLE: OnceLock<Vec<[Affine; 16]>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut out = Vec::with_capacity(64);
        let mut base = Projective::from(GrumpkinConfig::GENERATOR);
        for _ in 0..64 {
            let mut row = [Projective::zero(); 16];
            for d in 1..16 {
                row[d] = row[d - 1] + base;
            }
            let aff = Projective::normalize_batch(&row);
            out.push(aff.try_into().expect("16 points"));
            for _ in 0..4 {
                base.double_in_place();
            }
        }
        out
    })
}

#[inline(always)]
fn nibble(k: &<Fq as PrimeField>::BigInt, w: usize) -> usize {
    ((k.0[w / 16] >> ((w % 16) * 4)) & 0xf) as usize
}

/// k · G from the fixed-base table: at most 64 mixed additions.
pub fn base_mul(k: Fq) -> Projective {
    let bits = k.into_bigint();
    let t = base_table();
    let mut acc = Projective::zero();
    for w in 0..64 {
        let d = nibble(&bits, w);
        if d != 0 {
            acc += &t[w][d];
        }
    }
    acc
}

/// k · P with a 4-bit fixed window.
pub fn mul(p: Affine, k: Fq) -> Projective {
    let mut row = [Projective::zero(); 16];
    let pp = Projective::from(p);
    for d in 1..16 {
        row[d] = row[d - 1] + pp;
    }
    let table = Projective::normalize_batch(&row);
    let bits = k.into_bigint();
    let mut acc = Projective::zero();
    for w in (0..64).rev() {
        for _ in 0..4 {
            acc.double_in_place();
        }
        let d = nibble(&bits, w);
        if d != 0 {
            acc += &table[d];
        }
    }
    acc
}

/// A field element (below the BN254 scalar modulus) as a Grumpkin scalar.
#[inline(always)]
pub fn fr_to_fq(x: Fr) -> Fq {
    Fq::from_le_bytes_mod_order(&x.into_bigint().to_bytes_le())
}

/// A Grumpkin scalar reduced into the BN254 scalar field, as hashing it does.
#[inline(always)]
pub fn fq_to_fr(x: Fq) -> Fr {
    Fr::from_le_bytes_mod_order(&x.into_bigint().to_bytes_le())
}

pub fn point(x: Fr, y: Fr) -> Option<Affine> {
    let p = Affine::new_unchecked(x, y);
    if (x.is_zero() && y.is_zero()) || !p.is_on_curve() {
        None
    } else {
        Some(p)
    }
}

pub fn verify(pk: Affine, s: Fq, e_scalar: Fq, e: Fr, msg: Fr) -> bool {
    let r = (base_mul(s) + mul(pk, e_scalar)).into_affine();
    match r.xy() {
        None => false,
        Some((rx, _)) => hash(&[SCHNORR_DST, rx, pk.x, pk.y, msg]) == e,
    }
}

/// grumpkin.ts `sign` for one draw of randomness: None if that draw must be retried.
pub fn sign(sk: Fq, msg: Fr, rand: Fr) -> Option<(Fq, Fr)> {
    let pk = base_mul(sk).into_affine();
    let (pkx, pky) = pk.xy()?;
    let k_fr = hash(&[DS_NONCE, fq_to_fr(sk), msg, rand]);
    let k = fr_to_fq(k_fr);
    if k.is_zero() {
        return None;
    }
    let r = base_mul(k).into_affine();
    let (rx, _) = r.xy()?;
    let e = hash(&[SCHNORR_DST, rx, pkx, pky, msg]);
    let s = k - fr_to_fq(e) * sk;
    if s.is_zero() || e.is_zero() {
        return None;
    }
    Some((s, e))
}
