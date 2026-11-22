//! Credits: the confidential balance representation (SPEC.md §10.5).
use aztec::context::{NullifierExistenceRequest, PrivateContext};
use aztec::protocol::{
    address::AztecAddress,
    constants::PRIVATE_LOG_CIPHERTEXT_LEN,
    hash::{compute_siloed_nullifier, poseidon2_hash_with_separator},
    traits::{Deserialize, Serialize, ToField},
};

// Domain separators ("ct.credit", "ct.created", "ct.spent"), and the tag of the plaintext log that
// names a transfer's parties ("ct.parties").
pub global DS_CREDIT: Field = 0x63742e637265646974;
pub global DS_CREATED: Field = 0x63742e63726561746564;
pub global DS_SPENT: Field = 0x63742e7370656e74;
pub global PARTIES_LOG_TAG: Field = 0x63742e70617274696573;

/// Credits a transfer or unshield spends, and the inputs and outputs of a settlement.
pub global TRANSFER_INPUTS: u32 = 2;
pub global SETTLE_INPUTS: u32 = 4;
pub global SETTLE_OUTPUTS: u32 = 4;

/// The opening of a credit, as its owner holds it. A zero amount marks an unused input: no credit
/// has a zero amount.
#[derive(Deserialize, Eq, Serialize)]
pub struct Credit {
    pub amount: u128,
    pub blind: Field,
}

impl Credit {
    pub fn empty() -> Self {
        Credit { amount: 0, blind: 0 }
    }
}

/// A new credit for `to`. A zero amount marks an unused output.
#[derive(Deserialize, Eq, Serialize)]
pub struct Output {
    pub to: AztecAddress,
    pub amount: u128,
    pub blind: Field,
}

impl Output {
    pub fn empty() -> Self {
        Output { to: AztecAddress::zero(), amount: 0, blind: 0 }
    }
}

/// A credit's identifier: a hiding commitment to its owner, amount and blind (SPEC.md §10.5). It
/// never appears on chain; only its two nullifiers do.
pub fn credit_id(owner: AztecAddress, amount: u128, blind: Field) -> Field {
    poseidon2_hash_with_separator([owner.to_field(), amount as Field, blind], DS_CREDIT)
}

/// Emitted when a credit is created; its existence proves the credit exists.
pub fn created_nullifier(credit: Field) -> Field {
    poseidon2_hash_with_separator([credit], DS_CREATED)
}

/// Emitted when a credit is spent, so it can be spent once.
pub fn spent_nullifier(credit: Field) -> Field {
    poseidon2_hash_with_separator([credit], DS_SPENT)
}

/// Spends the non-empty inputs, which must be distinct credits of `owner` created in earlier
/// transactions, and returns their total.
pub fn spend<let N: u32>(context: &mut PrivateContext, token: AztecAddress, owner: AztecAddress, inputs: [Credit; N]) -> u128 {
    let mut ids = [0; N];
    let mut total: u128 = 0;
    for i in 0..N {
        let input = inputs[i];
        if input.amount > 0 {
            let credit = credit_id(owner, input.amount, input.blind);
            for j in 0..N {
                if j < i {
                    assert(ids[j] != credit, "credit spent twice");
                }
            }
            ids[i] = credit;
            context.assert_nullifier_exists(
                NullifierExistenceRequest::for_settled(compute_siloed_nullifier(token, created_nullifier(credit))),
            );
            context.push_nullifier_unsafe(spent_nullifier(credit));
            total += input.amount;
        }
    }
    total
}

/// Creates a credit; the duplicate-nullifier rule makes every credit unique.
pub fn create(context: &mut PrivateContext, owner: AztecAddress, amount: u128, blind: Field) -> Field {
    let credit = credit_id(owner, amount, blind);
    context.push_nullifier_unsafe(created_nullifier(credit));
    credit
}

/// The plaintext record of a confidential payment's parties.
pub fn emit_parties(context: &mut PrivateContext, from: AztecAddress, to: AztecAddress) {
    let mut log: BoundedVec<Field, PRIVATE_LOG_CIPHERTEXT_LEN> = BoundedVec::new();
    log.push(from.to_field());
    log.push(to.to_field());
    context.emit_private_log_unsafe(PARTIES_LOG_TAG, log);
}
