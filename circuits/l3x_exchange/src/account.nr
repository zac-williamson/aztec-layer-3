use crate::consts::{
    DS_ACCT, DS_ACCT_PRIV, DS_ACCT_PUB, DS_ACTV, DS_BLIND, DS_ENC, DS_KS, DS_MAUTH, MARKETS, PLAINTEXT_LEN,
};
use l3x_types::hash::hash;

global TWO_64: Field = 0x10000000000000000;
global TWO_128: Field = 0x100000000000000000000000000000000;

/// Signed values are stored as 64-bit two's complement.
pub fn enc(x: i64) -> Field {
    (x as u64) as Field
}

/// Public part of an account leaf (SPEC.md §6.3). Published in clear at registration and in
/// every refresh entry.
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

/// A position in one market (SPEC.md §6.3): signed size in lots, entry notional in collateral
/// units, and the market's cumulative funding index when funding was last settled.
pub struct Position {
    pub size: i64,
    pub entry: i64,
    pub funding: i64,
}

impl Position {
    pub fn empty() -> Self {
        Position { size: 0, entry: 0, funding: 0 }
    }

    /// One field: size, entry and funding snapshot as three 64-bit two's-complement limbs.
    pub fn pack(self) -> Field {
        enc(self.size) + enc(self.entry) * TWO_64 + enc(self.funding) * TWO_128
    }
}

impl Eq for Position {
    fn eq(self, other: Self) -> bool {
        (self.size == other.size) & (self.entry == other.entry) & (self.funding == other.funding)
    }
}

/// Splits a packed position into its limbs, with every limb range-checked, so each field has
/// exactly one opening.
pub fn unpack(x: Field) -> Position {
    let a = x as u64;
    let rest = (x - a as Field) / TWO_64;
    let b = rest as u64;
    let top = (rest - b as Field) / TWO_64;
    let c = top as u64;
    assert(c as Field == top, "packed position out of range");
    Position { size: a as i64, entry: b as i64, funding: c as i64 }
}

/// Private part: collateral and one position per market.
pub struct AccountPriv {
    pub collateral: i64,
    pub positions: [Position; MARKETS],
    pub blind: Field,
}

impl AccountPriv {
    pub fn empty(blind: Field) -> Self {
        AccountPriv { collateral: 0, positions: [Position::empty(); MARKETS], blind }
    }

    /// The values a DA entry encrypts, in order: collateral, packed positions, blind. The leaf's
    /// private hash is over the same fields, so an owner who decrypts an entry holds its opening.
    pub fn plaintext(self) -> [Field; PLAINTEXT_LEN] {
        let mut pt: [Field; PLAINTEXT_LEN] = [0; PLAINTEXT_LEN];
        pt[0] = enc(self.collateral);
        for m in 0..MARKETS {
            pt[1 + m] = self.positions[m].pack();
        }
        pt[PLAINTEXT_LEN - 1] = self.blind;
        pt
    }

    pub fn hash(self) -> Field {
        priv_hash(self.plaintext())
    }
}

pub fn priv_hash(pt: [Field; PLAINTEXT_LEN]) -> Field {
    let mut inputs: [Field; PLAINTEXT_LEN + 1] = [0; PLAINTEXT_LEN + 1];
    inputs[0] = DS_ACCT_PRIV;
    for i in 0..PLAINTEXT_LEN {
        inputs[1 + i] = pt[i];
    }
    hash(inputs)
}

/// Rebuilds a private part from its plaintext, range-checking every limb.
pub fn from_plaintext(pt: [Field; PLAINTEXT_LEN]) -> AccountPriv {
    let c = pt[0] as u64;
    assert(c as Field == pt[0], "collateral out of range");
    let mut positions = [Position::empty(); MARKETS];
    for m in 0..MARKETS {
        positions[m] = unpack(pt[1 + m]);
    }
    AccountPriv { collateral: c as i64, positions, blind: pt[PLAINTEXT_LEN - 1] }
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

/// Activity leaf (SPEC.md §6.4), never published: the master key's nonce, the number of open
/// orders, and the open bid and ask lots per market.
pub struct Activity {
    pub nonce: u64,
    pub open_orders: u32,
    pub open_bid: [u64; MARKETS],
    pub open_ask: [u64; MARKETS],
}

impl Activity {
    pub fn new() -> Self {
        Activity { nonce: 0, open_orders: 0, open_bid: [0; MARKETS], open_ask: [0; MARKETS] }
    }

    pub fn hash(self) -> Field {
        let mut inputs: [Field; 3 + MARKETS] = [0; 3 + MARKETS];
        inputs[0] = DS_ACTV;
        inputs[1] = self.nonce as Field;
        inputs[2] = self.open_orders as Field;
        for m in 0..MARKETS {
            inputs[3 + m] = (self.open_bid[m] as Field) + (self.open_ask[m] as Field) * TWO_64;
        }
        hash(inputs)
    }
}

#[test]
fn packing_round_trips() {
    let p = Position { size: -5, entry: -10_000, funding: -123_456_789 };
    assert(unpack(p.pack()) == p);
    let q = Position { size: 7, entry: 14_000, funding: 9_000_000_000 };
    assert(unpack(q.pack()) == q);
    let mut a = AccountPriv::empty(42);
    a.collateral = 1_000_000;
    a.positions[2] = p;
    let b = from_plaintext(a.plaintext());
    assert(b.hash() == a.hash());
    assert(b.positions[2] == p);
}
