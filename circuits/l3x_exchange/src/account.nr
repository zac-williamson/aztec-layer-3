use crate::consts::{DS_ACCT, DS_ACCT_PRIV, DS_ACCT_PUB, DS_ACTV, DS_BLIND, DS_ENC, DS_KS, DS_MAUTH};
use l3x_types::hash::hash;

/// Signed values are stored as 64-bit two's complement.
pub fn enc(x: i64) -> Field {
    (x as u64) as Field
}

/// Public part of an account leaf (SPEC.md §6.3), published in clear in every account DA entry.
pub struct AccountPub {
    pub owner: Field,
    pub master_auth: Field,
    pub enc_commitment: Field,
    pub class: Field,
}

impl AccountPub {
    pub fn hash(self) -> Field {
        hash([DS_ACCT_PUB, self.owner, self.master_auth, self.enc_commitment, self.class])
    }
}

impl Eq for AccountPub {
    fn eq(self, other: Self) -> bool {
        (self.owner == other.owner)
            & (self.master_auth == other.master_auth)
            & (self.enc_commitment == other.enc_commitment)
            & (self.class == other.class)
    }
}

/// Private part (P1: one market, so one position slot). `entry` is the position's entry
/// notional in collateral units; funding snapshots arrive in P2.
pub struct AccountPriv {
    pub collateral: i64,
    pub size: i64,
    pub entry: i64,
    pub blind: Field,
}

impl AccountPriv {
    pub fn hash(self) -> Field {
        hash([DS_ACCT_PRIV, enc(self.collateral), enc(self.size), enc(self.entry), self.blind])
    }

    pub fn plaintext(self) -> [Field; 4] {
        [enc(self.collateral), enc(self.size), enc(self.entry), self.blind]
    }
}

pub fn account_leaf(p: AccountPub, q: AccountPriv) -> Field {
    hash([DS_ACCT, p.hash(), q.hash()])
}

/// Lane-S master authorization: a Grumpkin public key (SPEC.md §7.2).
pub fn master_auth_of(pk_x: Field, pk_y: Field) -> Field {
    hash([DS_MAUTH, pk_x, pk_y])
}

pub fn enc_commitment(k_enc: Field) -> Field {
    hash([DS_ENC, k_enc])
}

/// The blind of a leaf written by the DA entry at position `pos` of a batch whose segment has
/// nonce `da_nonce`. Position and nonce make every blind and keystream specific to one entry of
/// one batch attempt (SPEC.md §9.4).
pub fn blind(k_enc: Field, account_index: u32, da_nonce: Field, pos: u32) -> Field {
    hash([DS_BLIND, k_enc, account_index as Field, da_nonce, pos as Field])
}

pub fn keystream(k_enc: Field, account_index: u32, da_nonce: Field, pos: u32, i: u32) -> Field {
    hash([DS_KS, k_enc, account_index as Field, da_nonce, (pos + i) as Field])
}

/// Activity leaf (SPEC.md §6.4), never published. P1 has no session keys: the master key signs.
pub struct Activity {
    pub nonce: u64,
    pub open_bid: u64,
    pub open_ask: u64,
    pub open_orders: u32,
}

impl Activity {
    pub fn new() -> Self {
        Activity { nonce: 0, open_bid: 0, open_ask: 0, open_orders: 0 }
    }

    pub fn hash(self) -> Field {
        hash(
            [
                DS_ACTV, self.nonce as Field, self.open_bid as Field, self.open_ask as Field,
                self.open_orders as Field,
            ],
        )
    }
}
