use crate::{
    account::{AccountPriv, AccountPub, keystream},
    consts::{DS_DANONCE, PLAINTEXT_LEN, TAG_SEG},
};
use l3x_types::{da_absorb, hash::hash, Running};

pub fn absorb(r: Running, x: Field) -> Running {
    let (da, len) = da_absorb(r.da, r.da_len, x);
    let mut out = r;
    out.da = da;
    out.da_len = len;
    out
}

/// A segment's DA nonce (SPEC.md §9.4): bound to the batch, the action log after the segment's
/// actions and the segment's position in the payload, so different contents or positions never
/// reuse a keystream. Published in the segment header so owners can decrypt.
pub fn segment_nonce(start: Running, action_log_end: Field) -> Field {
    hash([DS_DANONCE, start.batch as Field, action_log_end, start.da_len as Field])
}

pub fn open_segment(r: Running, da_nonce: Field) -> Running {
    absorb(absorb(r, TAG_SEG), da_nonce)
}

/// Appends an account entry (change or refresh) at the current DA position. `p.blind` must be
/// the blind for this position if the entry writes a new leaf.
pub fn emit_account(
    r: Running,
    tag: Field,
    account_index: u32,
    leaf: Field,
    pubv: AccountPub,
    privv: AccountPriv,
    k_enc: Field,
    da_nonce: Field,
) -> Running {
    let pos = r.da_len;
    let pt = privv.plaintext();
    let mut out = r;
    out = absorb(out, tag);
    out = absorb(out, account_index as Field);
    out = absorb(out, leaf);
    out = absorb(out, pubv.owner);
    out = absorb(out, pubv.master_auth);
    out = absorb(out, pubv.enc_commitment);
    out = absorb(out, pubv.class);
    for i in 0..PLAINTEXT_LEN {
        out = absorb(out, pt[i] + keystream(k_enc, account_index, da_nonce, pos, i));
    }
    out
}
