use aztec::macros::aztec;

/// Test collateral for P1's C0 custody: public balances with ERC-20 style allowances, so the
/// Bridge can pull a deposit and every amount is public. This is not the confidential token of
/// SPEC.md D7, which is specified separately.
#[aztec]
pub contract L3XToken {
    use aztec::{
        macros::{functions::{external, initializer, view}, storage::storage},
        protocol::address::AztecAddress,
        state_vars::{Map, PublicImmutable, PublicMutable},
    };

    #[storage]
    struct Storage<Context> {
        minter: PublicImmutable<AztecAddress, Context>,
        balances: Map<AztecAddress, PublicMutable<u128, Context>, Context>,
        allowances: Map<AztecAddress, Map<AztecAddress, PublicMutable<u128, Context>, Context>, Context>,
    }

    #[external("public")]
    #[initializer]
    fn constructor(minter: AztecAddress) {
        self.storage.minter.initialize(minter);
    }

    #[external("public")]
    fn mint(to: AztecAddress, amount: u128) {
        assert(self.msg_sender() == self.storage.minter.read(), "not minter");
        let b = self.storage.balances.at(to);
        b.write(b.read() + amount);
    }

    #[external("public")]
    fn transfer(to: AztecAddress, amount: u128) {
        let from = self.msg_sender();
        let fb = self.storage.balances.at(from);
        let balance = fb.read();
        assert(balance >= amount, "insufficient balance");
        fb.write(balance - amount);
        let tb = self.storage.balances.at(to);
        tb.write(tb.read() + amount);
    }

    #[external("public")]
    fn approve(spender: AztecAddress, amount: u128) {
        self.storage.allowances.at(self.msg_sender()).at(spender).write(amount);
    }

    #[external("public")]
    fn transfer_from(from: AztecAddress, to: AztecAddress, amount: u128) {
        let allowance = self.storage.allowances.at(from).at(self.msg_sender());
        let allowed = allowance.read();
        assert(allowed >= amount, "insufficient allowance");
        allowance.write(allowed - amount);
        let fb = self.storage.balances.at(from);
        let balance = fb.read();
        assert(balance >= amount, "insufficient balance");
        fb.write(balance - amount);
        let tb = self.storage.balances.at(to);
        tb.write(tb.read() + amount);
    }

    #[external("public")]
    #[view]
    fn balance_of(owner: AztecAddress) -> u128 {
        self.storage.balances.at(owner).read()
    }
}
