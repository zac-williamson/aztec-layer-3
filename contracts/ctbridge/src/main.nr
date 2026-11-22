mod content;
mod test;

use aztec::macros::aztec;

/// The L2 half of the collateral token's L1 bridge (SPEC.md §10.6, D7). Its L1 half is an escrow
/// portal, Aztec's standard TokenPortal: an L1 deposit locks the underlying ERC-20 and messages
/// this contract, which mints; an exit burns here and messages the portal, which releases.
///
/// This contract is the token's minter. A deposit is claimed into the recipient's public balance,
/// or straight into a credit; an exit burns from either. Amounts are public on L1 in both
/// directions, and the token publishes every confidential payment's parties, so the bridge hides
/// nothing the token would not.
#[aztec]
pub contract ConfidentialTokenBridge {
    use aztec::{
        macros::{functions::{external, initializer}, storage::storage},
        protocol::address::{AztecAddress, EthAddress},
        state_vars::PublicImmutable,
    };
    use crate::content::{mint_to_private_content, mint_to_public_content, withdraw_content};
    use ctoken::{ConfidentialToken, Credit, TRANSFER_INPUTS};

    #[storage]
    struct Storage<Context> {
        portal: PublicImmutable<EthAddress, Context>,
        /// Set once, by the deployer, after the token is deployed with this contract as its minter:
        /// each needs the other's address.
        token: PublicImmutable<AztecAddress, Context>,
        deployer: PublicImmutable<AztecAddress, Context>,
    }

    #[external("public")]
    #[initializer]
    fn constructor(portal: EthAddress) {
        self.storage.portal.initialize(portal);
        self.storage.deployer.initialize(self.msg_sender());
    }

    /// Binds the token, once. Only the deployer may call it.
    #[external("public")]
    fn set_token(token: AztecAddress) {
        assert(self.msg_sender() == self.storage.deployer.read(), "not deployer");
        self.storage.token.initialize(token);
    }

    /// Claims a deposit the portal made to the public balance of `to`. Anyone holding the
    /// message's secret may claim; the funds go only to `to`.
    #[external("public")]
    fn claim_public(to: AztecAddress, amount: u128, secret: Field, message_leaf_index: Field) {
        let portal = self.storage.portal.read();
        self.context.consume_l1_to_l2_message(mint_to_public_content(to, amount), [secret], portal, message_leaf_index);
        self.call(ConfidentialToken::at(self.storage.token.read()).mint(to, amount));
    }

    /// Claims a deposit the portal made without a recipient, as a credit of `to` with blind `blind`.
    /// The claimer names the recipient by knowing the message's secret; the token publishes the
    /// payment's parties.
    #[external("private")]
    fn claim_confidential(to: AztecAddress, amount: u128, blind: Field, secret: Field, message_leaf_index: Field) {
        let portal = self.storage.portal.read();
        self.context.consume_l1_to_l2_message(mint_to_private_content(amount), [secret], portal, message_leaf_index);
        let _ = self.call(ConfidentialToken::at(self.storage.token.read()).mint_confidential(to, amount, blind));
    }

    /// Burns `amount` of the caller's public balance and asks the portal to release it to
    /// `recipient` on L1. A nonzero `caller_on_l1` is the only L1 account that may execute it.
    #[external("public")]
    fn exit_public(recipient: EthAddress, amount: u128, caller_on_l1: EthAddress) {
        let portal = self.storage.portal.read();
        self.call(ConfidentialToken::at(self.storage.token.read()).burn_public(self.msg_sender(), amount));
        self.context.message_portal(portal, withdraw_content(recipient, amount, caller_on_l1));
    }

    /// Burns `amount` from the caller's credits, returning the rest as change, and asks the portal
    /// to release it to `recipient` on L1.
    #[external("private")]
    fn exit_confidential(
        recipient: EthAddress,
        amount: u128,
        credits: [Credit; TRANSFER_INPUTS],
        change_blind: Field,
        caller_on_l1: EthAddress,
    ) {
        let portal = self.storage.portal.read();
        self.call(
            ConfidentialToken::at(self.storage.token.read()).burn_confidential(
                self.msg_sender(),
                amount,
                credits,
                change_blind,
            ),
        );
        self.context.message_portal(portal, withdraw_content(recipient, amount, caller_on_l1));
    }
}
