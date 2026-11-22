//! TXE tests for the token's L2 bridge (SPEC.md §10.6). TXE injects the portal's L1-to-L2
//! messages; the round trip through a real portal is tested end to end in scripts/src.
use crate::ConfidentialTokenBridge;
use crate::content::{mint_to_private_content, mint_to_public_content};
use aztec::{protocol::address::{AztecAddress, EthAddress}, test::helpers::test_environment::TestEnvironment};
use ctoken::{ConfidentialToken, Credit};

global PORTAL: Field = 0xc0ffee;
global SECRET: Field = 0x5ec;

struct Env {
    env: TestEnvironment,
    deployer: AztecAddress,
    alice: AztecAddress,
    bob: AztecAddress,
    bridge: AztecAddress,
    token: AztecAddress,
}

unconstrained fn setup() -> Env {
    let mut env = TestEnvironment::new();
    let deployer = env.create_light_account();
    let alice = env.create_light_account();
    let bob = env.create_light_account();
    // Each needs the other's address: the bridge is deployed first, the token names it as minter,
    // and the deployer then binds the token to the bridge, once.
    let bridge = env.deploy("ConfidentialTokenBridge").with_public_initializer(
        deployer,
        ConfidentialTokenBridge::interface().constructor(EthAddress::from_field(PORTAL)),
    );
    let token = env.deploy("@ctoken/ConfidentialToken").with_public_initializer(
        deployer,
        ConfidentialToken::interface().constructor(bridge),
    );
    env.call_public(deployer, ConfidentialTokenBridge::at(bridge).set_token(token));
    Env { env, deployer, alice, bob, bridge, token }
}

unconstrained fn public_balance(e: Env, who: AztecAddress) -> u128 {
    e.env.view_public(ConfidentialToken::at(e.token).balance_of_public(who))
}

/// The portal's deposit message for `content`, sent from `portal`; returns its leaf index.
unconstrained fn deposit_from(e: Env, content: Field, portal: Field) -> Field {
    e.env.send_l1_to_l2_message(content, SECRET, EthAddress::from_field(portal), e.bridge)
}

unconstrained fn claim_public(e: Env, to: AztecAddress, amount: u128, leaf: Field) {
    e.env.call_public(e.bob, ConfidentialTokenBridge::at(e.bridge).claim_public(to, amount, SECRET, leaf));
}

unconstrained fn claim_confidential(e: Env, claimer: AztecAddress, to: AztecAddress, amount: u128, blind: Field, leaf: Field) {
    e.env.call_private(claimer, ConfidentialTokenBridge::at(e.bridge).claim_confidential(to, amount, blind, SECRET, leaf));
}

#[test]
unconstrained fn public_deposit_is_claimed_to_its_recipient() {
    let e = setup();
    let leaf = deposit_from(e, mint_to_public_content(e.alice, 500), PORTAL);
    // Anyone holding the secret may claim; the funds go only to the named recipient.
    claim_public(e, e.alice, 500, leaf);
    assert(public_balance(e, e.alice) == 500);
    assert(public_balance(e, e.bob) == 0);
}

#[test(should_fail_with = "L1-to-L2 message is already nullified")]
unconstrained fn a_deposit_is_claimed_once() {
    let e = setup();
    let leaf = deposit_from(e, mint_to_public_content(e.alice, 500), PORTAL);
    claim_public(e, e.alice, 500, leaf);
    claim_public(e, e.alice, 500, leaf);
}

#[test(should_fail_with = "Tried to consume nonexistent L1-to-L2 message")]
unconstrained fn a_claim_cannot_inflate_the_deposit() {
    let e = setup();
    let leaf = deposit_from(e, mint_to_public_content(e.alice, 500), PORTAL);
    claim_public(e, e.alice, 501, leaf);
}

#[test(should_fail_with = "Tried to consume nonexistent L1-to-L2 message")]
unconstrained fn a_claim_cannot_redirect_the_deposit() {
    let e = setup();
    let leaf = deposit_from(e, mint_to_public_content(e.alice, 500), PORTAL);
    claim_public(e, e.bob, 500, leaf);
}

#[test(should_fail_with = "Tried to consume nonexistent L1-to-L2 message")]
unconstrained fn only_the_portal_deposits() {
    let e = setup();
    let leaf = deposit_from(e, mint_to_public_content(e.alice, 500), 0xbad);
    claim_public(e, e.alice, 500, leaf);
}

#[test]
unconstrained fn confidential_deposit_becomes_a_credit() {
    let e = setup();
    let leaf = deposit_from(e, mint_to_private_content(400), PORTAL);
    claim_confidential(e, e.alice, e.alice, 400, 0xa1, leaf);
    assert(public_balance(e, e.alice) == 0);
    e.env.call_private(e.alice, ConfidentialToken::at(e.token).unshield(e.alice, 400, [Credit { amount: 400, blind: 0xa1 }, Credit::empty()], 0));
    assert(public_balance(e, e.alice) == 400);
}

#[test(should_fail)]
unconstrained fn a_confidential_deposit_is_claimed_once() {
    let e = setup();
    let leaf = deposit_from(e, mint_to_private_content(400), PORTAL);
    claim_confidential(e, e.alice, e.alice, 400, 0xa1, leaf);
    claim_confidential(e, e.bob, e.bob, 400, 0xb1, leaf);
}

#[test]
unconstrained fn public_exit_burns_the_callers_balance() {
    let e = setup();
    let leaf = deposit_from(e, mint_to_public_content(e.alice, 500), PORTAL);
    claim_public(e, e.alice, 500, leaf);
    e.env.call_public(e.alice, ConfidentialTokenBridge::at(e.bridge).exit_public(EthAddress::from_field(0xa11ce), 200, EthAddress::zero()));
    assert(public_balance(e, e.alice) == 300);
}

#[test(should_fail_with = "insufficient balance")]
unconstrained fn public_exit_needs_the_balance() {
    let e = setup();
    let leaf = deposit_from(e, mint_to_public_content(e.alice, 500), PORTAL);
    claim_public(e, e.alice, 500, leaf);
    // Bob cannot exit Alice's balance: the bridge burns only its caller's.
    e.env.call_public(e.bob, ConfidentialTokenBridge::at(e.bridge).exit_public(EthAddress::from_field(0xb0b), 200, EthAddress::zero()));
}

#[test]
unconstrained fn confidential_exit_burns_credits_and_returns_change() {
    let e = setup();
    let leaf = deposit_from(e, mint_to_private_content(400), PORTAL);
    claim_confidential(e, e.alice, e.alice, 400, 0xa1, leaf);
    e.env.call_private(
        e.alice,
        ConfidentialTokenBridge::at(e.bridge).exit_confidential(
            EthAddress::from_field(0xa11ce),
            150,
            [Credit { amount: 400, blind: 0xa1 }, Credit::empty()],
            0xa2,
            EthAddress::zero(),
        ),
    );
    e.env.call_private(e.alice, ConfidentialToken::at(e.token).unshield(e.alice, 250, [Credit { amount: 250, blind: 0xa2 }, Credit::empty()], 0));
    assert(public_balance(e, e.alice) == 250);
}

#[test(should_fail)]
unconstrained fn confidential_exit_spends_only_the_callers_credits() {
    let e = setup();
    let leaf = deposit_from(e, mint_to_private_content(400), PORTAL);
    claim_confidential(e, e.alice, e.alice, 400, 0xa1, leaf);
    e.env.call_private(
        e.bob,
        ConfidentialTokenBridge::at(e.bridge).exit_confidential(
            EthAddress::from_field(0xb0b),
            400,
            [Credit { amount: 400, blind: 0xa1 }, Credit::empty()],
            0,
            EthAddress::zero(),
        ),
    );
}

#[test(should_fail_with = "not minter")]
unconstrained fn only_the_bridge_burns() {
    let e = setup();
    let leaf = deposit_from(e, mint_to_public_content(e.alice, 500), PORTAL);
    claim_public(e, e.alice, 500, leaf);
    e.env.call_public(e.bob, ConfidentialToken::at(e.token).burn_public(e.alice, 500));
}

#[test(should_fail_with = "not minter")]
unconstrained fn only_the_bridge_mints_credits() {
    let e = setup();
    let _: Field = e.env.call_private(e.bob, ConfidentialToken::at(e.token).mint_confidential(e.bob, 500, 0xb1));
}

#[test(should_fail_with = "not deployer")]
unconstrained fn only_the_deployer_binds_the_token() {
    let e = setup();
    e.env.call_public(e.bob, ConfidentialTokenBridge::at(e.bridge).set_token(e.token));
}

#[test(should_fail)]
unconstrained fn the_token_is_bound_once() {
    let e = setup();
    e.env.call_public(e.deployer, ConfidentialTokenBridge::at(e.bridge).set_token(e.alice));
}
