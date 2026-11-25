//! The gateway's per-action cryptography, in batches on a thread pool so the sequencer's thread only
//! sequences (SPEC.md §5, §11, §14): each signed action's message, its signer's master
//! authorization and its signature; and the operator's receipt signatures.
use crate::grumpkin::{self, fr_to_fq};
use crate::poseidon2::hash;
use ark_bn254::{Fq, Fr};
use ark_ff::PrimeField;
use rayon::prelude::*;
use std::sync::OnceLock;

static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

/// The pool, built with `threads` workers on first use (L3X_CRYPTO_THREADS, or 8, if not given).
pub fn pool(threads: Option<usize>) -> &'static rayon::ThreadPool {
    POOL.get_or_init(|| {
        let n = threads
            .or_else(|| std::env::var("L3X_CRYPTO_THREADS").ok().and_then(|s| s.parse().ok()))
            .unwrap_or(8)
            .max(1);
        rayon::ThreadPoolBuilder::new().num_threads(n).thread_name(|i| format!("l3x-crypto-{i}")).build().expect("thread pool")
    })
}

/// Fields of one signed action: kind, account, key id, nonce, payload (8), pk_x, pk_y; then the
/// signature (s as a scalar, e as a field element below the modulus, or None if it is not).
pub const ACTION_FIELDS: usize = 14;

pub struct ActionIn {
    pub fields: [Fr; ACTION_FIELDS],
    pub s: Fq,
    pub e: Option<Fr>,
}

pub struct Prepared {
    pub msg: Fr,
    pub master_auth: Fr,
    pub ok: bool,
}

pub fn prepare(ds_action: Fr, ds_mauth: Fr, domain: Fr, actions: &[ActionIn]) -> Vec<Prepared> {
    pool(None).install(|| {
        actions
            .par_iter()
            .map(|a| {
                let f = &a.fields;
                let mut inputs = Vec::with_capacity(14);
                inputs.push(ds_action);
                inputs.push(domain);
                inputs.extend_from_slice(&f[..12]);
                let msg = hash(&inputs);
                let (pk_x, pk_y) = (f[12], f[13]);
                let master_auth = hash(&[ds_mauth, pk_x, pk_y]);
                let ok = match (grumpkin::point(pk_x, pk_y), a.e) {
                    (Some(pk), Some(e)) => grumpkin::verify(pk, a.s, fr_to_fq(e), e, msg),
                    _ => false,
                };
                Prepared { msg, master_auth, ok }
            })
            .collect()
    })
}

/// Receipt signatures (SPEC.md §11): Sign(H(DS_RECEIPT_SIG, domain, msg, seq, issued_at)), each
/// with the hedged nonce of grumpkin.ts `sign` drawn from `seed + i`.
pub fn sign_receipts(ds: Fr, domain: Fr, sk: Fq, seed: Fr, items: &[[Fr; 3]]) -> Vec<(Fq, Fr)> {
    pool(None).install(|| {
        items
            .par_iter()
            .enumerate()
            .map(|(i, it)| {
                let receipt = hash(&[ds, domain, it[0], it[1], it[2]]);
                let mut rand = seed + Fr::from(i as u64);
                loop {
                    if let Some(sig) = grumpkin::sign(sk, receipt, rand) {
                        return sig;
                    }
                    // Probability about 2^-252: draw again.
                    rand += Fr::from_bigint(ark_ff::BigInteger256::new([0, 0, 0, 1 << 40])).unwrap_or(Fr::from(7u64));
                }
            })
            .collect()
    })
}
