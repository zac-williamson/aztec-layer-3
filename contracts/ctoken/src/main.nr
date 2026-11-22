mod credits;
mod test;

use aztec::macros::aztec;
pub use credits::{
    create, created_nullifier, Credit, credit_id, DS_CREATED, DS_CREDIT, DS_SPENT, emit_parties, Output,
    PARTIES_LOG_TAG, SETTLE_INPUTS, SETTLE_OUTPUTS, spend, spent_nullifier, TRANSFER_INPUTS,
};

/// The L3X collateral token (SPEC.md §10.5, D7): amounts hidden, addresses public.
///
/// Balances come in two forms. A public balance is a plain amount per address, as in an ERC-20;
/// the minter (the token's bridge) mints into public balances, and contracts that must pay without
/// a secret, such as the L3X vault, hold one. A confidential balance is a set of credits. A credit is
/// a commitment `credit_id(owner, amount, blind)` that is never published: creating it emits
/// `created_nullifier(credit)` and spending it emits `spent_nullifier(credit)`, so a credit can be
/// spent once, only by its owner, and only if it was created. Every private function checks value
/// conservation in the circuit and the owner of every spent credit against the caller (or the
/// caller's authorization).
///
/// Amounts are hidden; parties are not. Each confidential payment emits a plaintext log of its
/// payer and payee, and public balance changes are public. The two nullifiers of a credit cannot be
/// linked without its opening, so which earlier payment funded a later one stays hidden too.
///
/// A new credit's opening reaches its owner by constrained delivery unless the owner is the caller,
/// who chose it; change returns to the payer by unconstrained delivery, since only the payer could
/// be harmed by a wrong message.
#[aztec]
pub contract ConfidentialToken {
    use aztec::{
        macros::{
            events::event,
            functions::{authorize_once, external, initializer, internal, only_self, view},
            storage::storage,
        },
        messages::delivery::MessageDelivery,
        protocol::address::AztecAddress,
        state_vars::{Map, PublicImmutable, PublicMutable},
    };
    use super::{create, Credit, emit_parties, Output, SETTLE_INPUTS, SETTLE_OUTPUTS, spend, TRANSFER_INPUTS};

    /// Delivered to a credit's owner: its opening, and who created it.
    #[event]
    struct CreditReceived {
        from: AztecAddress,
        amount: u128,
        blind: Field,
    }

    /// A public balance changed. Minting has `from` zero and burning `to` zero; shielding has `to`
    /// and unshielding `from` equal to the token itself, which stands for the confidential side.
    #[event]
    struct PublicTransfer {
        from: AztecAddress,
        to: AztecAddress,
        amount: u128,
    }

    #[storage]
    struct Storage<Context> {
        minter: PublicImmutable<AztecAddress, Context>,
        public_balances: Map<AztecAddress, PublicMutable<u128, Context>, Context>,
        allowances: Map<AztecAddress, Map<AztecAddress, PublicMutable<u128, Context>, Context>, Context>,
    }

    #[external("public")]
    #[initializer]
    fn constructor(minter: AztecAddress) {
        self.storage.minter.initialize(minter);
    }

    // ---- Public balances ----

    /// The minter (the token's bridge) creates supply in a public balance.
    #[external("public")]
    fn mint(to: AztecAddress, amount: u128) {
        assert(self.msg_sender() == self.storage.minter.read(), "not minter");
        self.internal.add_public(to, amount);
        self.emit(PublicTransfer { from: AztecAddress::zero(), to, amount });
    }

    /// Destroys supply from the caller's public balance.
    #[external("public")]
    fn burn(amount: u128) {
        let from = self.msg_sender();
        self.internal.sub_public(from, amount);
        self.emit(PublicTransfer { from, to: AztecAddress::zero(), amount });
    }

    /// The minter burns from the public balance of `from`, the account its own caller is (SPEC.md
    /// §10.6): the token trusts its bridge, whose code fixes `from`.
    #[external("public")]
    fn burn_public(from: AztecAddress, amount: u128) {
        assert(self.msg_sender() == self.storage.minter.read(), "not minter");
        self.internal.sub_public(from, amount);
        self.emit(PublicTransfer { from, to: AztecAddress::zero(), amount });
    }

    #[external("public")]
    fn transfer_public(to: AztecAddress, amount: u128) {
        let from = self.msg_sender();
        self.internal.move_public(from, to, amount);
    }

    #[external("public")]
    fn approve(spender: AztecAddress, amount: u128) {
        self.storage.allowances.at(self.msg_sender()).at(spender).write(amount);
    }

    #[external("public")]
    fn transfer_public_from(from: AztecAddress, to: AztecAddress, amount: u128) {
        let allowance = self.storage.allowances.at(from).at(self.msg_sender());
        let allowed = allowance.read();
        assert(allowed >= amount, "insufficient allowance");
        allowance.write(allowed - amount);
        self.internal.move_public(from, to, amount);
    }

    #[external("public")]
    #[view]
    fn balance_of_public(owner: AztecAddress) -> u128 {
        self.storage.public_balances.at(owner).read()
    }

    // ---- Confidential balances ----

    /// Moves `amount` from the caller's public balance into a new credit of the caller, and returns
    /// its id. The amount is public; the caller chose the blind.
    #[external("private")]
    fn shield(amount: u128, blind: Field) -> Field {
        assert(amount > 0, "zero amount");
        let owner = self.msg_sender();
        let credit = create(self.context, owner, amount, blind);
        self.emit(CreditReceived { from: owner, amount, blind }).deliver_to(
            owner,
            MessageDelivery::onchain_unconstrained(),
        );
        self.enqueue_self._shield(owner, amount);
        credit
    }

    /// Pays `amount` from credits of `from` into a new credit of `to`, with blind `blind`, and returns
    /// its id. The rest returns to `from` as a change credit with blind `change_blind`. A caller other
    /// than `from` needs `from`'s authorization of this exact call.
    #[authorize_once("from", "authwit_nonce")]
    #[external("private")]
    fn transfer(
        from: AztecAddress,
        to: AztecAddress,
        amount: u128,
        credits: [Credit; TRANSFER_INPUTS],
        blind: Field,
        change_blind: Field,
        authwit_nonce: Field,
    ) -> Field {
        assert(amount > 0, "zero amount");
        let total = spend(self.context, self.address, from, credits);
        assert(total >= amount, "insufficient credits");
        let credit = create(self.context, to, amount, blind);
        if to != self.msg_sender() {
            self.emit(CreditReceived { from, amount, blind }).deliver_to(
                to,
                MessageDelivery::onchain_constrained(),
            );
        }
        let change = total - amount;
        if change > 0 {
            let _ = create(self.context, from, change, change_blind);
            self.emit(CreditReceived { from, amount: change, blind: change_blind }).deliver_to(
                from,
                MessageDelivery::onchain_unconstrained(),
            );
        }
        emit_parties(self.context, from, to);
        credit
    }

    /// The minter (the token's bridge) mints a claimed deposit straight into a credit of `to`, with
    /// blind `blind`, delivered to `to` by constrained delivery. The amount is public on L1 anyway;
    /// minting into a credit saves the owner a separate shield.
    #[external("private")]
    fn mint_confidential(to: AztecAddress, amount: u128, blind: Field) -> Field {
        let minter = self.storage.minter.read();
        assert(self.msg_sender() == minter, "not minter");
        assert(amount > 0, "zero amount");
        let credit = create(self.context, to, amount, blind);
        self.emit(CreditReceived { from: minter, amount, blind }).deliver_to(
            to,
            MessageDelivery::onchain_constrained(),
        );
        emit_parties(self.context, minter, to);
        credit
    }

    /// The minter burns `amount` from credits of `from`, the account its own caller is (SPEC.md
    /// §10.6), and returns the rest to `from` as change.
    #[external("private")]
    fn burn_confidential(from: AztecAddress, amount: u128, credits: [Credit; TRANSFER_INPUTS], change_blind: Field) {
        let minter = self.storage.minter.read();
        assert(self.msg_sender() == minter, "not minter");
        assert(amount > 0, "zero amount");
        let total = spend(self.context, self.address, from, credits);
        assert(total >= amount, "insufficient credits");
        let change = total - amount;
        if change > 0 {
            let _ = create(self.context, from, change, change_blind);
            self.emit(CreditReceived { from, amount: change, blind: change_blind }).deliver_to(
                from,
                MessageDelivery::onchain_unconstrained(),
            );
        }
        emit_parties(self.context, from, minter);
    }

    /// Pays `amount` from the caller's credits into the public balance of `to`; the amount becomes
    /// public. The rest returns to the caller as change.
    #[external("private")]
    fn unshield(to: AztecAddress, amount: u128, credits: [Credit; TRANSFER_INPUTS], change_blind: Field) {
        assert(amount > 0, "zero amount");
        let from = self.msg_sender();
        let total = spend(self.context, self.address, from, credits);
        assert(total >= amount, "insufficient credits");
        let change = total - amount;
        if change > 0 {
            let _ = create(self.context, from, change, change_blind);
            self.emit(CreditReceived { from, amount: change, blind: change_blind }).deliver_to(
                from,
                MessageDelivery::onchain_unconstrained(),
            );
        }
        emit_parties(self.context, from, to);
        self.enqueue_self._unshield(to, amount);
    }

    /// For holders that pay many parties at once, such as the L3X Bridge's custody (SPEC.md §10.3):
    /// spends `credits` of the caller, creates the outputs, and moves `public_in` from the caller's
    /// public balance into them or `public_out` from them into the caller's public balance, so that
    /// inputs + public_in = outputs + public_out. Only the net public leg is public. Each output's
    /// owner receives its opening by constrained delivery. Returns the outputs' credit ids.
    #[external("private")]
    fn settle(
        credits: [Credit; SETTLE_INPUTS],
        outputs: [Output; SETTLE_OUTPUTS],
        public_in: u128,
        public_out: u128,
    ) -> [Field; SETTLE_OUTPUTS] {
        let from = self.msg_sender();
        let spent = spend(self.context, self.address, from, credits);
        let mut created = [0; SETTLE_OUTPUTS];
        let mut paid: u128 = 0;
        for i in 0..SETTLE_OUTPUTS {
            let o = outputs[i];
            if o.amount > 0 {
                created[i] = create(self.context, o.to, o.amount, o.blind);
                paid += o.amount;
                self.emit(CreditReceived { from, amount: o.amount, blind: o.blind }).deliver_to(
                    o.to,
                    MessageDelivery::onchain_constrained(),
                );
                emit_parties(self.context, from, o.to);
            }
        }
        assert(spent + public_in == paid + public_out, "value not conserved");
        if public_in > 0 {
            self.enqueue_self._shield(from, public_in);
        }
        if public_out > 0 {
            self.enqueue_self._unshield(from, public_out);
        }
        created
    }

    #[external("public")]
    #[only_self]
    fn _shield(from: AztecAddress, amount: u128) {
        self.internal.sub_public(from, amount);
        self.emit(PublicTransfer { from, to: self.address, amount });
    }

    #[external("public")]
    #[only_self]
    fn _unshield(to: AztecAddress, amount: u128) {
        self.internal.add_public(to, amount);
        self.emit(PublicTransfer { from: self.address, to, amount });
    }

    #[internal("public")]
    fn add_public(to: AztecAddress, amount: u128) {
        let b = self.storage.public_balances.at(to);
        b.write(b.read() + amount);
    }

    #[internal("public")]
    fn sub_public(from: AztecAddress, amount: u128) {
        let b = self.storage.public_balances.at(from);
        let balance = b.read();
        assert(balance >= amount, "insufficient balance");
        b.write(balance - amount);
    }

    #[internal("public")]
    fn move_public(from: AztecAddress, to: AztecAddress, amount: u128) {
        self.internal.sub_public(from, amount);
        self.internal.add_public(to, amount);
        self.emit(PublicTransfer { from, to, amount });
    }

}
