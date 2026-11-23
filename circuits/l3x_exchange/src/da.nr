use crate::{
    account::{AccountPriv, AccountPub, keystream},
    consts::{DS_DANONCE, PLAINTEXT_LEN, TAG_CHANGE, TAG_DISPLAY, TAG_SEG},
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

/// Appends the ciphertexts of an account's opening. `pos` is the entry's first DA position: the
/// keystream index runs from it, so no two entries share a keystream.
fn emit_ciphertexts(r: Running, account_index: u32, privv: AccountPriv, k_enc: Field, da_nonce: Field, pos: u32) -> Running {
    let pt = privv.plaintext();
    let mut out = r;
    for i in 0..PLAINTEXT_LEN {
        out = absorb(out, pt[i] + keystream(k_enc, account_index, da_nonce, pos, i));
    }
    out
}

global TWO_48: Field = 0x1000000000000;
global TWO_80: Field = 0x100000000000000000000;

/// A displayed order's resting lots after a change (SPEC.md §8.4, [D1]): zero once it leaves the
/// book. The entry names the order, never its owner: [TAG_DISPLAY, key, lots] with
/// key = (market·2 + side)·2^80 + price·2^48 + seq (prices below 2^32, sequence numbers below 2^47).
pub fn emit_display(r: Running, market: u32, side: Field, price: u32, seq: u64, lots: u64) -> Running {
    let key = ((market as Field) * 2 + side) * TWO_80 + (price as Field) * TWO_48 + (seq as Field);
    absorb(absorb(absorb(r, TAG_DISPLAY), key), lots as Field)
}

/// A change entry: the account's public part is unchanged, so only the index, the new leaf and
/// the encrypted opening are published (SPEC.md §9.5). `privv.blind` must be the blind for the
/// entry's position.
pub fn emit_change(r: Running, account_index: u32, leaf: Field, privv: AccountPriv, k_enc: Field, da_nonce: Field) -> Running {
    let pos = r.da_len;
    let mut out = absorb(r, TAG_CHANGE);
    out = absorb(out, account_index as Field);
    out = absorb(out, leaf);
    emit_ciphertexts(out, account_index, privv, k_enc, da_nonce, pos)
}

/// A full entry, with the public part in clear: registration (TAG_FULL) and refresh (TAG_REFRESH).
pub fn emit_full(
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
    let mut out = absorb(r, tag);
    out = absorb(out, account_index as Field);
    out = absorb(out, leaf);
    out = absorb(out, pubv.owner);
    out = absorb(out, pubv.master_auth);
    out = absorb(out, pubv.enc_commitment);
    out = absorb(out, pubv.class);
    emit_ciphertexts(out, account_index, privv, k_enc, da_nonce, pos)
}
