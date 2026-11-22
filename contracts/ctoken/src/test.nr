//! TXE tests for the confidential token (SPEC.md §10.5).
use crate::{ConfidentialToken, Credit, Output};
use aztec::{
    protocol::address::AztecAddress,
    test::helpers::{authwit::add_private_authwit_from_call, test_environment::{CallPrivateOptions, TestEnvironment}},
};

struct Env {
    env: TestEnvironment,
    minter: AztecAddress,
    alice: AztecAddress,
    bob: AztecAddress,
    carol: AztecAddress,
    dave: AztecAddress,
    erin: AztecAddress,
    token: AztecAddress,
}

unconstrained fn setup() -> Env {
    let mut env = TestEnvironment::new();
    let minter = env.create_light_account();
    let alice = env.create_contract_account();
    let bob = env.create_light_account();
    let carol = env.create_light_account();
    let dave = env.create_light_account();
    let erin = env.create_light_account();
    let token = env.deploy("ConfidentialToken").with_public_initializer(
        minter,
        ConfidentialToken::interface().constructor(minter),
    );
    env.call_public(minter, ConfidentialToken::at(token).mint(alice, 1000));
    Env { env, minter, alice, bob, carol, dave, erin, token }
}

unconstrained fn public_balance(e: Env, who: AztecAddress) -> u128 {
    e.env.view_public(ConfidentialToken::at(e.token).balance_of_public(who))
}

unconstrained fn shield(e: Env, who: AztecAddress, amount: u128, blind: Field) -> Field {
    e.env.call_private(who, ConfidentialToken::at(e.token).shield(amount, blind))
}

unconstrained fn credit(amount: u128, blind: Field) -> Credit {
    Credit { amount, blind }
}

unconstrained fn transfer(
    e: Env,
    caller: AztecAddress,
    from: AztecAddress,
    to: AztecAddress,
    amount: u128,
    inputs: [Credit; 2],
    blind: Field,
    change_blind: Field,
    nonce: Field,
) -> Field {
    // A caller paying on behalf of `from` runs `from`'s account contract to check the authorization,
    // which reads `from`'s key, so `from` must be in the call's scope.
    e.env.call_private_opts(
        caller,
        CallPrivateOptions::new().with_additional_scopes([from]),
        ConfidentialToken::at(e.token).transfer(from, to, amount, inputs, blind, change_blind, nonce),
    )
}

unconstrained fn unshield(e: Env, who: AztecAddress, to: AztecAddress, amount: u128, inputs: [Credit; 2], change_blind: Field) {
    e.env.call_private(who, ConfidentialToken::at(e.token).unshield(to, amount, inputs, change_blind));
}

#[test]
unconstrained fn shield_moves_public_balance_into_a_credit() {
    let e = setup();
    let id = shield(e, e.alice, 400, 0xa1);
    assert(id == crate::credit_id(e.alice, 400, 0xa1));
    assert(public_balance(e, e.alice) == 600);
    // The credit is spendable: unshield it back.
    unshield(e, e.alice, e.alice, 400, [credit(400, 0xa1), Credit::empty()], 0);
    assert(public_balance(e, e.alice) == 1000);
}

#[test(should_fail_with = "insufficient balance")]
unconstrained fn shield_needs_public_balance() {
    let e = setup();
    let _ = shield(e, e.bob, 1, 0xb1);
}

#[test]
unconstrained fn transfer_pays_the_recipient_and_returns_change() {
    let e = setup();
    let _ = shield(e, e.alice, 300, 0xa1);
    let _ = shield(e, e.alice, 200, 0xa2);
    let id = transfer(e, e.alice, e.alice, e.bob, 450, [credit(300, 0xa1), credit(200, 0xa2)], 0xb1, 0xa3, 0);
    assert(id == crate::credit_id(e.bob, 450, 0xb1));
    // Bob spends his credit to a public balance; Alice spends her change.
    unshield(e, e.bob, e.bob, 450, [credit(450, 0xb1), Credit::empty()], 0);
    unshield(e, e.alice, e.carol, 50, [credit(50, 0xa3), Credit::empty()], 0);
    assert(public_balance(e, e.bob) == 450);
    assert(public_balance(e, e.carol) == 50);
    assert(public_balance(e, e.alice) == 500);
}

#[test]
unconstrained fn partial_unshield_keeps_change() {
    let e = setup();
    let _ = shield(e, e.alice, 500, 0xa1);
    unshield(e, e.alice, e.bob, 120, [credit(500, 0xa1), Credit::empty()], 0xa2);
    unshield(e, e.alice, e.bob, 380, [credit(380, 0xa2), Credit::empty()], 0);
    assert(public_balance(e, e.bob) == 500);
}

#[test(should_fail)]
unconstrained fn a_credit_is_spent_once() {
    let e = setup();
    let _ = shield(e, e.alice, 100, 0xa1);
    unshield(e, e.alice, e.alice, 100, [credit(100, 0xa1), Credit::empty()], 0);
    unshield(e, e.alice, e.alice, 100, [credit(100, 0xa1), Credit::empty()], 0);
}

#[test(should_fail_with = "credit spent twice")]
unconstrained fn one_credit_cannot_fill_two_inputs() {
    let e = setup();
    let _ = shield(e, e.alice, 100, 0xa1);
    unshield(e, e.alice, e.alice, 200, [credit(100, 0xa1), credit(100, 0xa1)], 0);
}

#[test(should_fail)]
unconstrained fn only_the_owner_spends_a_credit() {
    let e = setup();
    let _ = shield(e, e.alice, 100, 0xa1);
    // Bob knows the opening but the credit is Alice's: as Bob's it was never created.
    unshield(e, e.bob, e.bob, 100, [credit(100, 0xa1), Credit::empty()], 0);
}

#[test(should_fail)]
unconstrained fn an_invented_credit_cannot_be_spent() {
    let e = setup();
    let _ = shield(e, e.alice, 100, 0xa1);
    unshield(e, e.alice, e.alice, 1000, [credit(1000, 0xa1), Credit::empty()], 0);
}

#[test(should_fail_with = "insufficient credits")]
unconstrained fn transfer_cannot_exceed_its_inputs() {
    let e = setup();
    let _ = shield(e, e.alice, 100, 0xa1);
    let _ = transfer(e, e.alice, e.alice, e.bob, 101, [credit(100, 0xa1), Credit::empty()], 0xb1, 0, 0);
}

#[test]
unconstrained fn authorized_caller_pays_on_behalf_of_the_owner() {
    let e = setup();
    let _ = shield(e, e.alice, 300, 0xa1);
    let call = ConfidentialToken::at(e.token).transfer(e.alice, e.carol, 100, [credit(300, 0xa1), Credit::empty()], 0xc1, 0xa2, 7);
    add_private_authwit_from_call(e.env, e.alice, e.bob, call);
    let _ = transfer(e, e.bob, e.alice, e.carol, 100, [credit(300, 0xa1), Credit::empty()], 0xc1, 0xa2, 7);
    unshield(e, e.carol, e.carol, 100, [credit(100, 0xc1), Credit::empty()], 0);
    unshield(e, e.alice, e.alice, 200, [credit(200, 0xa2), Credit::empty()], 0);
    assert(public_balance(e, e.carol) == 100);
    assert(public_balance(e, e.alice) == 900);
}

#[test(should_fail_with = "Unknown auth witness")]
unconstrained fn unauthorized_caller_cannot_spend() {
    let e = setup();
    let _ = shield(e, e.alice, 300, 0xa1);
    let _ = transfer(e, e.bob, e.alice, e.bob, 300, [credit(300, 0xa1), Credit::empty()], 0xb1, 0, 7);
}

#[test(should_fail)]
unconstrained fn authorization_covers_the_exact_call() {
    let e = setup();
    let _ = shield(e, e.alice, 300, 0xa1);
    let call = ConfidentialToken::at(e.token).transfer(e.alice, e.carol, 100, [credit(300, 0xa1), Credit::empty()], 0xc1, 0xa2, 7);
    add_private_authwit_from_call(e.env, e.alice, e.bob, call);
    // Bob redirects the payment to himself.
    let _ = transfer(e, e.bob, e.alice, e.bob, 100, [credit(300, 0xa1), Credit::empty()], 0xc1, 0xa2, 7);
}

#[test]
unconstrained fn settle_nets_outputs_against_the_public_balance() {
    let e = setup();
    let _ = shield(e, e.alice, 500, 0xa1);
    // Inputs 500 + public 100 = outputs 450 + 150.
    let outputs = [
        Output { to: e.bob, amount: 450, blind: 0xb1 },
        Output { to: e.carol, amount: 150, blind: 0xc1 },
        Output::empty(),
        Output::empty(),
    ];
    let ids: [Field; 4] = e.env.call_private(
        e.alice,
        ConfidentialToken::at(e.token).settle([credit(500, 0xa1), Credit::empty(), Credit::empty(), Credit::empty()], outputs, 100, 0),
    );
    assert(ids[0] == crate::credit_id(e.bob, 450, 0xb1));
    assert(ids[2] == 0);
    assert(public_balance(e, e.alice) == 400);
    // Bob and Carol settle their credits into Alice's public balance: net outflow.
    let back = [Output::empty(), Output::empty(), Output::empty(), Output::empty()];
    let _: [Field; 4] = e.env.call_private(
        e.bob,
        ConfidentialToken::at(e.token).settle([credit(450, 0xb1), Credit::empty(), Credit::empty(), Credit::empty()], back, 0, 450),
    );
    assert(public_balance(e, e.bob) == 450);
    unshield(e, e.carol, e.carol, 150, [credit(150, 0xc1), Credit::empty()], 0);
    assert(public_balance(e, e.carol) == 150);
}

#[test(should_fail_with = "value not conserved")]
unconstrained fn settle_conserves_value() {
    let e = setup();
    let _ = shield(e, e.alice, 500, 0xa1);
    let outputs = [Output { to: e.bob, amount: 501, blind: 0xb1 }, Output::empty(), Output::empty(), Output::empty()];
    let _: [Field; 4] = e.env.call_private(
        e.alice,
        ConfidentialToken::at(e.token).settle([credit(500, 0xa1), Credit::empty(), Credit::empty(), Credit::empty()], outputs, 0, 0),
    );
}

#[test]
unconstrained fn settle_pays_four_parties() {
    let e = setup();
    let _ = shield(e, e.alice, 1000, 0xa1);
    let outputs = [
        Output { to: e.bob, amount: 100, blind: 0xb1 },
        Output { to: e.carol, amount: 200, blind: 0xc1 },
        Output { to: e.dave, amount: 300, blind: 0xd1 },
        Output { to: e.erin, amount: 350, blind: 0xe1 },
    ];
    let _: [Field; 4] = e.env.call_private(
        e.alice,
        ConfidentialToken::at(e.token).settle([credit(1000, 0xa1), Credit::empty(), Credit::empty(), Credit::empty()], outputs, 0, 50),
    );
    assert(public_balance(e, e.alice) == 50);
}

#[test(should_fail_with = "not minter")]
unconstrained fn only_the_minter_mints() {
    let e = setup();
    e.env.call_public(e.bob, ConfidentialToken::at(e.token).mint(e.bob, 1));
}

#[test]
unconstrained fn public_transfers_and_allowances() {
    let e = setup();
    e.env.call_public(e.alice, ConfidentialToken::at(e.token).transfer_public(e.bob, 100));
    e.env.call_public(e.alice, ConfidentialToken::at(e.token).approve(e.carol, 50));
    e.env.call_public(e.carol, ConfidentialToken::at(e.token).transfer_public_from(e.alice, e.carol, 50));
    e.env.call_public(e.bob, ConfidentialToken::at(e.token).burn(40));
    assert(public_balance(e, e.alice) == 850);
    assert(public_balance(e, e.bob) == 60);
    assert(public_balance(e, e.carol) == 50);
}

#[test(should_fail_with = "insufficient allowance")]
unconstrained fn transfer_from_needs_an_allowance() {
    let e = setup();
    e.env.call_public(e.carol, ConfidentialToken::at(e.token).transfer_public_from(e.alice, e.carol, 1));
}
