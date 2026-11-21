//! TXE tests for the Bridge (SPEC.md §10, §12, §17). TXE simulates private functions without
//! proving, so the root proof here is a dummy and headers are built by hand; the proof binding is
//! tested end to end against real proofs in scripts/src.
use crate::L3XBridge;
use aztec::{protocol::{address::AztecAddress, traits::ToField}, test::helpers::test_environment::TestEnvironment};
use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof};
use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, enc_commitment, master_auth_of},
    consts::{ACCOUNTS_HEIGHT, CLASS_USER, DS_ACCT_NODE, DS_WD_NODE, MAX_WD_BATCH, WD_HEIGHT},
    state::{genesis_state_root, market_data_hash},
    tree::merkle_root,
    withdrawal_record, withdrawals_root,
};
use l3x_token::L3XToken;
use l3x_types::{BatchHeader, config_hash, DA_MAX, da_hash_flat, hash::hash, merge::{VK_TREE_LEAVES, vk_tree_root_of}};

global ROOT_VK: Field = 0x1234;
global CONFIG: Field = 0x5678;
global T_FORCE: u64 = 1000;
global T_CLAIM: u64 = 500;
global T_LAG: u64 = 15 * 60;
global UPGRADE_DELAY: u64 = 21 * 24 * 60 * 60;
global TEST_DA_LEN: u32 = 8;
global PRICE: u64 = 10;

struct Env {
    env: TestEnvironment,
    operator: AztecAddress,
    alice: AztecAddress,
    bob: AztecAddress,
    token: AztecAddress,
    bridge: AztecAddress,
}

unconstrained fn setup() -> Env {
    let mut env = TestEnvironment::new();
    let operator = env.create_light_account();
    let alice = env.create_light_account();
    let bob = env.create_light_account();
    let token = env.deploy("@l3x_token/L3XToken").with_public_initializer(
        operator,
        L3XToken::interface().constructor(operator),
    );
    let bridge = env.deploy("L3XBridge").with_public_initializer(
        operator,
        L3XBridge::interface().constructor(operator, ROOT_VK, CONFIG, token, T_FORCE, T_CLAIM),
    );
    let _ = env.call_public(operator, L3XToken::at(token).mint(alice, 10_000));
    let _ = env.call_public(alice, L3XToken::at(token).approve(bridge, 10_000));
    Env { env, operator, alice, bob, token, bridge }
}

unconstrained fn balance(e: Env, who: AztecAddress) -> u128 {
    e.env.view_public(L3XToken::at(e.token).balance_of(who))
}

unconstrained fn deposit(e: Env, from: AztecAddress, account: Field, amount: u128) {
    let _ = e.env.call_public(from, L3XBridge::at(e.bridge).deposit(account, amount));
}

unconstrained fn payload() -> [Field; DA_MAX] {
    let mut p: [Field; DA_MAX] = [0; DA_MAX];
    for i in 0..TEST_DA_LEN {
        p[i] = (i + 1) as Field;
    }
    p
}

unconstrained fn tip(e: Env) -> (Field, Field, u64, u64, u64, u64) {
    e.env.view_public(L3XBridge::at(e.bridge).get_tip())
}

/// A header for the next batch that passes every check in _apply at time `now`, consuming the
/// first `consume` pending priority requests.
unconstrained fn next_header(e: Env, now: u64, consume: u64) -> BatchHeader {
    let (state_root, accounts_root, batch_number, last_time, cursor, _) = tip(e);
    let (head_start, _, _) = e.env.view_public(L3XBridge::at(e.bridge).get_priority(cursor));
    let (head_end, _, _) = e.env.view_public(L3XBridge::at(e.bridge).get_priority(cursor + consume));
    BatchHeader {
        prev_state_root: state_root,
        new_state_root: state_root + 1,
        new_accounts_root: accounts_root,
        batch_number: batch_number + 1,
        min_time: last_time,
        max_time: now,
        priority_start: cursor,
        priority_end: cursor + consume,
        priority_head_start: head_start,
        priority_head_end: head_end,
        withdrawals_root: withdrawals_root([0; MAX_WD_BATCH]),
        withdrawals_count: 0,
        withdrawals_amount: 0,
        action_log_root: 0,
        da_hash: da_hash_flat(payload(), TEST_DA_LEN),
        market_data_hash: market_data_hash(PRICE, now),
        config_hash: CONFIG,
    }
}

/// Settles `h` in a block at time `now` with a dummy proof; the market data is (PRICE, max_time).
unconstrained fn settle(e: Env, from: AztecAddress, h: BatchHeader, now: u64) {
    e.env.set_next_block_timestamp(now);
    let proof: UltraHonkZKProof = [0; 458];
    let vk: UltraHonkVerificationKey = [0; 115];
    e.env.call_private(
        from,
        L3XBridge::at(e.bridge).settle(h.to_fields(), proof, vk, payload(), TEST_DA_LEN, [PRICE as Field, h.max_time as Field]),
    );
}

unconstrained fn now_plus(e: Env, seconds: u64) -> u64 {
    e.env.last_block_timestamp() + seconds
}

/// Root of an accounts tree holding `leaf` at index 0 and nothing else, and the leaf's path.
unconstrained fn single_account_tree(leaf: Field) -> (Field, [Field; ACCOUNTS_HEIGHT]) {
    let mut path: [Field; ACCOUNTS_HEIGHT] = [0; ACCOUNTS_HEIGHT];
    let mut empty = 0;
    for i in 0..ACCOUNTS_HEIGHT {
        path[i] = empty;
        empty = hash([DS_ACCT_NODE, empty, empty]);
    }
    (merkle_root(DS_ACCT_NODE, leaf, 0, path), path)
}

/// Path of record 0 in a withdrawals tree holding only that record.
unconstrained fn single_record_path() -> [Field; WD_HEIGHT] {
    let mut path: [Field; WD_HEIGHT] = [0; WD_HEIGHT];
    let mut empty = 0;
    for i in 0..WD_HEIGHT {
        path[i] = empty;
        empty = hash([DS_WD_NODE, empty, empty]);
    }
    path
}

// ---- Settlement checks (SPEC.md §10.2) ----

#[test]
unconstrained fn genesis_tip() {
    let e = setup();
    let (state_root, accounts_root, batch_number, last_time, cursor, count) = tip(e);
    assert(state_root == genesis_state_root());
    assert((accounts_root, batch_number, last_time, cursor, count) == (0, 0, 0, 0, 0));
}

#[test]
unconstrained fn settle_applies_header() {
    let e = setup();
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 0);
    h.new_accounts_root = 7;
    settle(e, e.operator, h, now);
    let (state_root, accounts_root, batch_number, last_time, _, _) = tip(e);
    assert((state_root, accounts_root, batch_number, last_time) == (h.new_state_root, 7, 1, now));
    let now2 = now_plus(e, 10);
    settle(e, e.operator, next_header(e, now2, 0), now2);
    let (_, _, batch_number, _, _, _) = tip(e);
    assert(batch_number == 2);
}

#[test(should_fail_with = "stale state root")]
unconstrained fn replay_rejected() {
    let e = setup();
    let now = now_plus(e, 10);
    let h = next_header(e, now, 0);
    settle(e, e.operator, h, now);
    settle(e, e.operator, h, now_plus(e, 10));
}

#[test(should_fail_with = "batch number")]
unconstrained fn skipped_batch_number_rejected() {
    let e = setup();
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 0);
    h.batch_number = 2;
    settle(e, e.operator, h, now);
}

#[test(should_fail_with = "not operator")]
unconstrained fn non_operator_rejected() {
    let e = setup();
    let now = now_plus(e, 10);
    settle(e, e.alice, next_header(e, now, 0), now);
}

#[test(should_fail_with = "config mismatch")]
unconstrained fn foreign_config_rejected() {
    let e = setup();
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 0);
    h.config_hash = CONFIG + 1;
    settle(e, e.operator, h, now);
}

#[test(should_fail_with = "da hash")]
unconstrained fn da_mismatch_rejected() {
    let e = setup();
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 0);
    h.da_hash = da_hash_flat(payload(), TEST_DA_LEN - 1);
    settle(e, e.operator, h, now);
}

#[test(should_fail_with = "market data")]
unconstrained fn market_data_mismatch_rejected() {
    let e = setup();
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 0);
    h.market_data_hash = market_data_hash(PRICE + 1, now);
    settle(e, e.operator, h, now);
}

// ---- Priority queue (SPEC.md §12) ----

#[test]
unconstrained fn deposit_moves_funds_into_the_vault_and_queues() {
    let e = setup();
    deposit(e, e.alice, 0, 1000);
    assert(balance(e, e.alice) == 9000);
    assert(balance(e, e.bridge) == 1000);
    let (_, _, _, _, cursor, count) = tip(e);
    assert((cursor, count) == (0, 1));
}

#[test(should_fail_with = "insufficient allowance")]
unconstrained fn deposit_needs_allowance() {
    let e = setup();
    let _ = e.env.call_public(e.operator, L3XToken::at(e.token).mint(e.bob, 100));
    deposit(e, e.bob, 0, 50);
}

#[test(should_fail_with = "deposit amount out of range")]
unconstrained fn zero_deposit_rejected() {
    let e = setup();
    deposit(e, e.alice, 0, 0);
}

#[test]
unconstrained fn register_queues_with_the_caller_as_owner() {
    let e = setup();
    let k_enc = 0xbeef;
    e.env.call_private(e.alice, L3XBridge::at(e.bridge).register(master_auth_of(1, 2), enc_commitment(k_enc), k_enc));
    let (_, _, _, _, _, count) = tip(e);
    assert(count == 1);
}

#[test(should_fail_with = "k_enc does not open the commitment")]
unconstrained fn register_rejects_a_wrong_key() {
    let e = setup();
    e.env.call_private(e.alice, L3XBridge::at(e.bridge).register(master_auth_of(1, 2), enc_commitment(0xbeef), 0xbeee));
}

#[test]
unconstrained fn priority_requests_consumed_in_order() {
    let e = setup();
    deposit(e, e.alice, 0, 100);
    deposit(e, e.alice, 0, 200);
    let now = now_plus(e, 10);
    settle(e, e.operator, next_header(e, now, 1), now);
    let (_, _, _, _, cursor, count) = tip(e);
    assert((cursor, count) == (1, 2));
    let now2 = now_plus(e, 10);
    settle(e, e.operator, next_header(e, now2, 1), now2);
    let (_, _, _, _, cursor, _) = tip(e);
    assert(cursor == 2);
}

#[test(should_fail_with = "priority head end")]
unconstrained fn forged_priority_fold_rejected() {
    let e = setup();
    deposit(e, e.alice, 0, 100);
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 1);
    h.priority_head_end += 1;
    settle(e, e.operator, h, now);
}

#[test(should_fail_with = "priority head start")]
unconstrained fn forged_priority_head_start_rejected() {
    let e = setup();
    deposit(e, e.alice, 0, 100);
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 1);
    h.priority_head_start += 1;
    settle(e, e.operator, h, now);
}

#[test(should_fail_with = "priority start")]
unconstrained fn skipped_priority_request_rejected() {
    let e = setup();
    deposit(e, e.alice, 0, 100);
    deposit(e, e.alice, 0, 200);
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 2);
    let (head1, _, _) = e.env.view_public(L3XBridge::at(e.bridge).get_priority(1));
    h.priority_start = 1;
    h.priority_head_start = head1;
    settle(e, e.operator, h, now);
}

#[test(should_fail_with = "priority end")]
unconstrained fn consuming_unqueued_request_rejected() {
    let e = setup();
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 0);
    h.priority_end = 1;
    settle(e, e.operator, h, now);
}

#[test(should_fail_with = "priority request overdue")]
unconstrained fn overdue_request_blocks_settlement() {
    let e = setup();
    deposit(e, e.alice, 0, 100);
    let now = now_plus(e, T_FORCE + 10);
    settle(e, e.operator, next_header(e, now, 0), now);
}

#[test]
unconstrained fn request_within_deadline_may_wait() {
    let e = setup();
    deposit(e, e.alice, 0, 100);
    let now = now_plus(e, T_FORCE - 10);
    settle(e, e.operator, next_header(e, now, 0), now);
}

// ---- Time (SPEC.md §8.4) ----

#[test(should_fail_with = "batch time lags Aztec time")]
unconstrained fn lagging_batch_time_rejected() {
    let e = setup();
    let now = now_plus(e, T_LAG + 100);
    let mut h = next_header(e, now, 0);
    h.max_time = now - T_LAG - 1;
    h.market_data_hash = market_data_hash(PRICE, h.max_time);
    settle(e, e.operator, h, now);
}

#[test(should_fail_with = "batch time in the future")]
unconstrained fn future_batch_time_rejected() {
    let e = setup();
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 0);
    h.max_time = now + 1;
    h.market_data_hash = market_data_hash(PRICE, h.max_time);
    settle(e, e.operator, h, now);
}

#[test(should_fail_with = "time regressed")]
unconstrained fn time_regression_rejected() {
    let e = setup();
    let now = now_plus(e, 100);
    settle(e, e.operator, next_header(e, now, 0), now);
    let now2 = now_plus(e, 10);
    let mut h = next_header(e, now2, 0);
    h.min_time = now - 1;
    settle(e, e.operator, h, now2);
}

#[test]
unconstrained fn halt_resumes_with_one_catch_up_batch() {
    let e = setup();
    let now = now_plus(e, 10);
    settle(e, e.operator, next_header(e, now, 0), now);
    let later = now_plus(e, 24 * 60 * 60);
    settle(e, e.operator, next_header(e, later, 0), later);
    let (_, _, batch_number, last_time, _, _) = tip(e);
    assert((batch_number, last_time) == (2, later));
}

// ---- Withdrawals (SPEC.md §10.4) ----

unconstrained fn settle_withdrawal(e: Env, record: Field, amount: u64) {
    deposit(e, e.alice, 0, 1000);
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 1);
    let mut records: [Field; MAX_WD_BATCH] = [0; MAX_WD_BATCH];
    records[0] = record;
    h.withdrawals_root = withdrawals_root(records);
    h.withdrawals_count = 1;
    h.withdrawals_amount = amount;
    settle(e, e.operator, h, now);
}

#[test]
unconstrained fn settled_withdrawal_paid_once_to_its_recipient() {
    let e = setup();
    let record = withdrawal_record(e.bob.to_field(), 300, 5, 1, 0);
    settle_withdrawal(e, record, 300);
    // Anyone may submit the claim; only the recipient is paid.
    let _ = e.env.call_public(
        e.alice,
        L3XBridge::at(e.bridge).claim_withdrawal(1, 0, e.bob, 300, 5, single_record_path()),
    );
    assert(balance(e, e.bob) == 300);
    assert(balance(e, e.bridge) == 700);
}

#[test(should_fail_with = "already paid")]
unconstrained fn withdrawal_cannot_be_paid_twice() {
    let e = setup();
    settle_withdrawal(e, withdrawal_record(e.bob.to_field(), 300, 5, 1, 0), 300);
    let claim = L3XBridge::at(e.bridge).claim_withdrawal(1, 0, e.bob, 300, 5, single_record_path());
    let _ = e.env.call_public(e.bob, claim);
    let _ = e.env.call_public(e.bob, claim);
}

#[test(should_fail_with = "record not in the batch's withdrawals tree")]
unconstrained fn withdrawal_amount_cannot_be_changed() {
    let e = setup();
    settle_withdrawal(e, withdrawal_record(e.bob.to_field(), 300, 5, 1, 0), 300);
    let _ = e.env.call_public(
        e.bob,
        L3XBridge::at(e.bridge).claim_withdrawal(1, 0, e.bob, 900, 5, single_record_path()),
    );
}

#[test(should_fail_with = "record not in the batch's withdrawals tree")]
unconstrained fn withdrawal_recipient_cannot_be_redirected() {
    let e = setup();
    settle_withdrawal(e, withdrawal_record(e.bob.to_field(), 300, 5, 1, 0), 300);
    let _ = e.env.call_public(
        e.alice,
        L3XBridge::at(e.bridge).claim_withdrawal(1, 0, e.alice, 300, 5, single_record_path()),
    );
}

// ---- Desert mode (SPEC.md §12) ----

/// Alice holds an account at index 0 with `collateral` and a long position of `size` lots at
/// entry notional `entry`, settled in batch 1 at index price PRICE; then she deposits 50 more,
/// which the operator never processes.
unconstrained fn desert_world(collateral: i64, size: i64, entry: i64) -> (Env, AccountPub, AccountPriv, [Field; ACCOUNTS_HEIGHT]) {
    let e = setup();
    let pubv = AccountPub { owner: e.alice.to_field(), master_auth: master_auth_of(1, 2), enc_commitment: enc_commitment(3), class: CLASS_USER };
    let privv = AccountPriv { collateral, size, entry, blind: 0x77 };
    let (root, path) = single_account_tree(account_leaf(pubv, privv));
    deposit(e, e.alice, 0, 1000);
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 1);
    h.new_accounts_root = root;
    settle(e, e.operator, h, now);
    deposit(e, e.alice, 0, 50);
    (e, pubv, privv, path)
}

unconstrained fn activate(e: Env) {
    e.env.advance_next_block_timestamp_by(T_FORCE + 10);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).activate_desert());
}

unconstrained fn exit_register(e: Env, pubv: AccountPub, privv: AccountPriv, path: [Field; ACCOUNTS_HEIGHT], price: u64, time: u64) {
    let _ = e.env.call_public(
        e.bob,
        L3XBridge::at(e.bridge).exit_register(
            0,
            e.alice,
            pubv.master_auth,
            pubv.enc_commitment,
            pubv.class,
            (privv.collateral as u64) as Field,
            (privv.size as u64) as Field,
            (privv.entry as u64) as Field,
            privv.blind,
            path,
            price,
            time,
        ),
    );
}

#[test]
unconstrained fn desert_exit_from_the_frozen_root() {
    let (e, pubv, privv, path) = desert_world(1000, 0, 0);
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    // Unprocessed deposit: refunded in full.
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).desert_refund(1, 0, 50, e.alice));
    assert(balance(e, e.alice) == 9000);
    // Account claim, registered by anyone, paid to the owner after the window.
    exit_register(e, pubv, privv, path, PRICE, settled_time);
    e.env.advance_next_block_timestamp_by(T_CLAIM + 10);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).exit_withdraw(0));
    assert(balance(e, e.alice) == 10_000);
    assert(balance(e, e.bridge) == 0);
}

#[test]
unconstrained fn desert_values_positions_at_the_frozen_index() {
    // Collateral 400 and 100 lots long entered at notional 900: at index 10, equity is
    // 400 + 100 * 10 - 900 = 500.
    let (e, pubv, privv, path) = desert_world(400, 100, 900);
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    exit_register(e, pubv, privv, path, PRICE, settled_time);
    let (_, _, _, _, total) = e.env.view_public(L3XBridge::at(e.bridge).get_desert());
    assert(total == 500);
}

#[test]
unconstrained fn desert_clamps_negative_equity_to_zero() {
    let (e, pubv, privv, path) = desert_world(100, -100, -500);
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    // 100 + (-100) * 10 - (-500) = -400: clamps to 0.
    exit_register(e, pubv, privv, path, PRICE, settled_time);
    let (_, _, _, _, total) = e.env.view_public(L3XBridge::at(e.bridge).get_desert());
    assert(total == 0);
}

#[test(should_fail_with = "no priority request is overdue")]
unconstrained fn desert_needs_an_overdue_request() {
    let (e, _, _, _) = desert_world(1000, 0, 0);
    e.env.advance_next_block_timestamp_by(T_FORCE - 10);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).activate_desert());
}

#[test(should_fail_with = "not in the frozen accounts tree")]
unconstrained fn desert_rejects_an_inflated_opening() {
    let (e, pubv, privv, path) = desert_world(1000, 0, 0);
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    let mut forged = privv;
    forged.collateral = 5000;
    exit_register(e, pubv, forged, path, PRICE, settled_time);
}

#[test(should_fail_with = "market data")]
unconstrained fn desert_rejects_another_index_price() {
    let (e, pubv, privv, path) = desert_world(400, 100, 900);
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    exit_register(e, pubv, privv, path, PRICE * 2, settled_time);
}

#[test(should_fail_with = "already claimed")]
unconstrained fn desert_claim_registers_once() {
    let (e, pubv, privv, path) = desert_world(1000, 0, 0);
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    exit_register(e, pubv, privv, path, PRICE, settled_time);
    exit_register(e, pubv, privv, path, PRICE, settled_time);
}

#[test(should_fail_with = "claim window still open")]
unconstrained fn desert_pays_only_after_the_window() {
    let (e, pubv, privv, path) = desert_world(1000, 0, 0);
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    exit_register(e, pubv, privv, path, PRICE, settled_time);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).exit_withdraw(0));
}

#[test(should_fail_with = "desert mode")]
unconstrained fn desert_stops_new_requests() {
    let (e, _, _, _) = desert_world(1000, 0, 0);
    activate(e);
    deposit(e, e.alice, 0, 10);
}

#[test(should_fail_with = "desert mode")]
unconstrained fn desert_stops_settlement() {
    let (e, _, _, _) = desert_world(1000, 0, 0);
    activate(e);
    let now = now_plus(e, 10);
    settle(e, e.operator, next_header(e, now, 1), now);
}

#[test(should_fail_with = "request was processed")]
unconstrained fn desert_does_not_refund_processed_deposits() {
    let (e, _, _, _) = desert_world(1000, 0, 0);
    activate(e);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).desert_refund(0, 0, 1000, e.alice));
}

// ---- Configuration (SPEC.md §12) ----

unconstrained fn new_leaves() -> [Field; VK_TREE_LEAVES] {
    let mut leaves: [Field; VK_TREE_LEAVES] = [0; VK_TREE_LEAVES];
    leaves[24] = 0xabc;
    leaves[25] = 0xdef;
    leaves
}

#[test]
unconstrained fn upgrade_takes_effect_only_after_delay() {
    let e = setup();
    let new_config = config_hash(vk_tree_root_of(new_leaves()), 9);
    let _ = e.env.call_public(e.operator, L3XBridge::at(e.bridge).schedule_upgrade(new_leaves(), 9, 0x777));
    e.env.advance_next_block_timestamp_by(UPGRADE_DELAY - 60);
    e.env.mine_block();
    let (_, root_vk, config) = e.env.view_public(L3XBridge::at(e.bridge).get_config());
    assert((root_vk, config) == (ROOT_VK, CONFIG));
    let now = now_plus(e, 10);
    settle(e, e.operator, next_header(e, now, 0), now);
    e.env.advance_next_block_timestamp_by(120);
    e.env.mine_block();
    let (_, root_vk, config) = e.env.view_public(L3XBridge::at(e.bridge).get_config());
    assert((root_vk, config) == (0x777, new_config));
    let now2 = now_plus(e, 10);
    let mut h = next_header(e, now2, 0);
    h.config_hash = new_config;
    settle(e, e.operator, h, now2);
}

#[test(should_fail_with = "config mismatch")]
unconstrained fn scheduled_config_not_usable_early() {
    let e = setup();
    let new_config = config_hash(vk_tree_root_of(new_leaves()), 9);
    let _ = e.env.call_public(e.operator, L3XBridge::at(e.bridge).schedule_upgrade(new_leaves(), 9, 0x777));
    let now = now_plus(e, UPGRADE_DELAY - 60);
    let mut h = next_header(e, now, 0);
    h.config_hash = new_config;
    settle(e, e.operator, h, now);
}

#[test(should_fail_with = "config mismatch")]
unconstrained fn old_config_rejected_after_upgrade() {
    let e = setup();
    let _ = e.env.call_public(e.operator, L3XBridge::at(e.bridge).schedule_upgrade(new_leaves(), 9, 0x777));
    e.env.advance_next_block_timestamp_by(UPGRADE_DELAY + 60);
    e.env.mine_block();
    let now = now_plus(e, 10);
    settle(e, e.operator, next_header(e, now, 0), now);
}

#[test(should_fail_with = "not operator")]
unconstrained fn only_operator_schedules_upgrades() {
    let e = setup();
    let _ = e.env.call_public(e.alice, L3XBridge::at(e.bridge).schedule_upgrade(new_leaves(), 9, 0x777));
}

#[test]
unconstrained fn operator_change_is_delayed() {
    let e = setup();
    let _ = e.env.call_public(e.operator, L3XBridge::at(e.bridge).schedule_operator(e.bob));
    e.env.advance_next_block_timestamp_by(UPGRADE_DELAY + 60);
    e.env.mine_block();
    let (current, _, _) = e.env.view_public(L3XBridge::at(e.bridge).get_config());
    assert(current == e.bob);
    let now = now_plus(e, 10);
    settle(e, e.bob, next_header(e, now, 0), now);
}

#[test(should_fail_with = "not operator")]
unconstrained fn new_operator_cannot_settle_early() {
    let e = setup();
    let _ = e.env.call_public(e.operator, L3XBridge::at(e.bridge).schedule_operator(e.bob));
    let now = now_plus(e, UPGRADE_DELAY - 60);
    settle(e, e.bob, next_header(e, now, 0), now);
}
