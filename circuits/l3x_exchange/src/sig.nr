use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar};

/// Schnorr over Grumpkin with a Poseidon2 challenge (SPEC.md §7.1), noir-lang/schnorr v0.4.0.
pub struct Signature {
    pub s: EmbeddedCurveScalar,
    pub e: EmbeddedCurveScalar,
}

pub fn assert_signed(pk_x: Field, pk_y: Field, sig: Signature, msg: Field) {
    let pk = EmbeddedCurvePoint { x: pk_x, y: pk_y };
    schnorr::assert_valid_signature(pk, (sig.s, sig.e), msg);
}
