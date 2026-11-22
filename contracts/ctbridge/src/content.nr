//! The contents of the messages the bridge exchanges with its L1 portal (SPEC.md §10.6). They are
//! the standard Aztec TokenPortal's: sha256ToField over the ABI encoding of a pseudo-call, whose
//! selector only makes the content unique to its action.
use aztec::protocol::{address::{AztecAddress, EthAddress}, hash::sha256_to_field, traits::ToField};

/// Selectors of mint_to_public(bytes32,uint256), mint_to_private(uint256) and
/// withdraw(address,uint256,address).
global MINT_TO_PUBLIC: [u8; 4] = [0xbc, 0x6a, 0x9b, 0xd3];
global MINT_TO_PRIVATE: [u8; 4] = [0x8b, 0x3a, 0xf5, 0xe8];
global WITHDRAW: [u8; 4] = [0x69, 0x32, 0x8d, 0xec];

fn put<let N: u32>(bytes: &mut [u8; N], at: u32, word: Field) {
    let w: [u8; 32] = word.to_be_bytes();
    for i in 0..32 {
        bytes[at + i] = w[i];
    }
}

fn put_selector<let N: u32>(bytes: &mut [u8; N], selector: [u8; 4]) {
    for i in 0..4 {
        bytes[i] = selector[i];
    }
}

/// An L1 deposit to the public balance of `to`.
pub fn mint_to_public_content(to: AztecAddress, amount: u128) -> Field {
    let mut bytes: [u8; 68] = [0; 68];
    put_selector(&mut bytes, MINT_TO_PUBLIC);
    put(&mut bytes, 4, to.to_field());
    put(&mut bytes, 36, amount as Field);
    sha256_to_field(bytes)
}

/// An L1 deposit whose recipient the claimer names on L2.
pub fn mint_to_private_content(amount: u128) -> Field {
    let mut bytes: [u8; 36] = [0; 36];
    put_selector(&mut bytes, MINT_TO_PRIVATE);
    put(&mut bytes, 4, amount as Field);
    sha256_to_field(bytes)
}

/// A withdrawal to `recipient` on L1; `caller`, unless zero, is the only L1 account that may
/// execute it.
pub fn withdraw_content(recipient: EthAddress, amount: u128, caller: EthAddress) -> Field {
    let mut bytes: [u8; 100] = [0; 100];
    put_selector(&mut bytes, WITHDRAW);
    put(&mut bytes, 4, recipient.to_field());
    put(&mut bytes, 36, amount as Field);
    put(&mut bytes, 68, caller.to_field());
    sha256_to_field(bytes)
}
