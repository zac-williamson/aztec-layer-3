//! TXE tests for the Bridge's public checks (SPEC.md §10.2, §12, §17). TXE simulates private
//! functions without proving, so the root proof here is a dummy; the proof binding itself is
//! tested end to end in scripts/src/settle.ts against real proofs.
use crate::L3XBridge;
use aztec::{protocol::address::AztecAddress, test::helpers::test_environment::TestEnvironment};
use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof};
use l3x_types::{
    BatchHeader, config_hash, DA_MAX, da_hash_flat, genesis_state_root, merge::{VK_TREE_LEAVES, vk_tree_root_of},
};

global ROOT_VK: Field = 0x1234;
global CONFIG: Field = 0x5678;
global T_FORCE: u64 = 14 * 24 * 60 * 60;
global T_LAG: u64 = 15 * 60;
global UPGRADE_DELAY: u64 = 21 * 24 * 60 * 60;
global TEST_DA_LEN: u32 = 8;

unconstrained fn setup() -> (TestEnvironment, AztecAddress, AztecAddress, AztecAddress) {
    let mut env = TestEnvironment::new();
    let operator = env.create_light_account();
    let user = env.create_light_account();
    let bridge = env.deploy("L3XBridge").with_public_initializer(
        operator,
        L3XBridge::interface().constructor(operator, ROOT_VK, CONFIG),
    );
    (env, operator, user, bridge)
}

unconstrained fn payload() -> [Field; DA_MAX] {
    let mut p: [Field; DA_MAX] = [0; DA_MAX];
    for i in 0..TEST_DA_LEN {
        p[i] = (i + 1) as Field;
    }
    p
}

unconstrained fn tip(env: TestEnvironment, bridge: AztecAddress) -> (Field, Field, u64, u64, u64, u64) {
    env.view_public(L3XBridge::at(bridge).get_tip())
}

/// A header for the next batch that passes every check in _apply at time `now`, consuming the
/// first `consume` pending priority requests.
unconstrained fn next_header(env: TestEnvironment, bridge: AztecAddress, now: u64, consume: u64) -> BatchHeader {
    let (state_root, _, batch_number, last_time, cursor, _) = tip(env, bridge);
    let (head_start, _, _) = env.view_public(L3XBridge::at(bridge).get_priority(cursor));
    let (head_end, _, _) = env.view_public(L3XBridge::at(bridge).get_priority(cursor + consume));
    BatchHeader {
        prev_state_root: state_root,
        new_state_root: state_root + 1,
        new_accounts_root: 7,
        batch_number: batch_number + 1,
        min_time: last_time,
        max_time: now,
        priority_start: cursor,
        priority_end: cursor + consume,
        priority_head_start: head_start,
        priority_head_end: head_end,
        withdrawals_root: 0,
        withdrawals_count: 0,
        action_log_root: 0,
        da_hash: da_hash_flat(payload(), TEST_DA_LEN),
        market_data_hash: 0,
        config_hash: CONFIG,
    }
}

/// Settles `h` in a block at time `now`, with a dummy proof.
unconstrained fn settle(env: TestEnvironment, from: AztecAddress, bridge: AztecAddress, h: BatchHeader, now: u64) {
    env.set_next_block_timestamp(now);
    let proof: UltraHonkZKProof = [0; 458];
    let vk: UltraHonkVerificationKey = [0; 115];
    env.call_private(from, L3XBridge::at(bridge).settle(h.to_fields(), proof, vk, payload(), TEST_DA_LEN));
}

unconstrained fn now_plus(env: TestEnvironment, seconds: u64) -> u64 {
    env.last_block_timestamp() + seconds
}

#[test]
unconstrained fn genesis_tip() {
    let (env, _, _, bridge) = setup();
    let (state_root, accounts_root, batch_number, last_time, cursor, count) = tip(env, bridge);
    assert(state_root == genesis_state_root());
    assert((accounts_root, batch_number, last_time, cursor, count) == (0, 0, 0, 0, 0));
}

#[test]
unconstrained fn settle_applies_header() {
    let (env, operator, _, bridge) = setup();
    let now = now_plus(env, 10);
    let h = next_header(env, bridge, now, 0);
    settle(env, operator, bridge, h, now);
    let (state_root, accounts_root, batch_number, last_time, _, _) = tip(env, bridge);
    assert(state_root == h.new_state_root);
    assert(accounts_root == 7);
    assert(batch_number == 1);
    assert(last_time == now);
    // A second batch chains from the first.
    let now2 = now_plus(env, 10);
    settle(env, operator, bridge, next_header(env, bridge, now2, 0), now2);
    let (_, _, batch_number, _, _, _) = tip(env, bridge);
    assert(batch_number == 2);
}

#[test(should_fail_with = "stale state root")]
unconstrained fn replay_rejected() {
    let (env, operator, _, bridge) = setup();
    let now = now_plus(env, 10);
    let h = next_header(env, bridge, now, 0);
    settle(env, operator, bridge, h, now);
    settle(env, operator, bridge, h, now_plus(env, 10));
}

#[test(should_fail_with = "batch number")]
unconstrained fn skipped_batch_number_rejected() {
    let (env, operator, _, bridge) = setup();
    let now = now_plus(env, 10);
    let mut h = next_header(env, bridge, now, 0);
    h.batch_number = 2;
    settle(env, operator, bridge, h, now);
}

#[test(should_fail_with = "not operator")]
unconstrained fn non_operator_rejected() {
    let (env, _, user, bridge) = setup();
    let now = now_plus(env, 10);
    settle(env, user, bridge, next_header(env, bridge, now, 0), now);
}

#[test(should_fail_with = "config mismatch")]
unconstrained fn foreign_config_rejected() {
    let (env, operator, _, bridge) = setup();
    let now = now_plus(env, 10);
    let mut h = next_header(env, bridge, now, 0);
    h.config_hash = CONFIG + 1;
    settle(env, operator, bridge, h, now);
}

#[test(should_fail_with = "da hash")]
unconstrained fn da_mismatch_rejected() {
    let (env, operator, _, bridge) = setup();
    let now = now_plus(env, 10);
    let mut h = next_header(env, bridge, now, 0);
    h.da_hash = da_hash_flat(payload(), TEST_DA_LEN - 1);
    settle(env, operator, bridge, h, now);
}

#[test]
unconstrained fn priority_requests_consumed_in_order() {
    let (env, operator, user, bridge) = setup();
    let _ = env.call_public(user, L3XBridge::at(bridge).submit_request(11));
    let _ = env.call_public(user, L3XBridge::at(bridge).submit_request(22));
    let now = now_plus(env, 10);
    settle(env, operator, bridge, next_header(env, bridge, now, 1), now);
    let (_, _, _, _, cursor, count) = tip(env, bridge);
    assert((cursor, count) == (1, 2));
    let now2 = now_plus(env, 10);
    settle(env, operator, bridge, next_header(env, bridge, now2, 1), now2);
    let (_, _, _, _, cursor, _) = tip(env, bridge);
    assert(cursor == 2);
}

#[test(should_fail_with = "priority head end")]
unconstrained fn forged_priority_fold_rejected() {
    let (env, operator, user, bridge) = setup();
    let _ = env.call_public(user, L3XBridge::at(bridge).submit_request(11));
    let now = now_plus(env, 10);
    let mut h = next_header(env, bridge, now, 1);
    h.priority_head_end += 1;
    settle(env, operator, bridge, h, now);
}

#[test(should_fail_with = "priority head start")]
unconstrained fn forged_priority_head_start_rejected() {
    let (env, operator, user, bridge) = setup();
    let _ = env.call_public(user, L3XBridge::at(bridge).submit_request(11));
    let now = now_plus(env, 10);
    let mut h = next_header(env, bridge, now, 1);
    h.priority_head_start += 1;
    settle(env, operator, bridge, h, now);
}

#[test(should_fail_with = "priority start")]
unconstrained fn skipped_priority_request_rejected() {
    let (env, operator, user, bridge) = setup();
    let _ = env.call_public(user, L3XBridge::at(bridge).submit_request(11));
    let _ = env.call_public(user, L3XBridge::at(bridge).submit_request(22));
    let now = now_plus(env, 10);
    let mut h = next_header(env, bridge, now, 2);
    // Claim to start after the first request, skipping it.
    let (head1, _, _) = env.view_public(L3XBridge::at(bridge).get_priority(1));
    h.priority_start = 1;
    h.priority_head_start = head1;
    settle(env, operator, bridge, h, now);
}

#[test(should_fail_with = "priority end")]
unconstrained fn consuming_unqueued_request_rejected() {
    let (env, operator, _, bridge) = setup();
    let now = now_plus(env, 10);
    let mut h = next_header(env, bridge, now, 0);
    h.priority_end = 1;
    settle(env, operator, bridge, h, now);
}

#[test(should_fail_with = "priority request overdue")]
unconstrained fn overdue_request_blocks_settlement() {
    let (env, operator, user, bridge) = setup();
    let _ = env.call_public(user, L3XBridge::at(bridge).submit_request(11));
    let now = now_plus(env, T_FORCE + 10);
    settle(env, operator, bridge, next_header(env, bridge, now, 0), now);
}

#[test]
unconstrained fn request_within_deadline_may_wait() {
    let (env, operator, user, bridge) = setup();
    let _ = env.call_public(user, L3XBridge::at(bridge).submit_request(11));
    let now = now_plus(env, T_FORCE - 10);
    settle(env, operator, bridge, next_header(env, bridge, now, 0), now);
}

#[test(should_fail_with = "batch time lags Aztec time")]
unconstrained fn lagging_batch_time_rejected() {
    let (env, operator, _, bridge) = setup();
    let now = now_plus(env, T_LAG + 100);
    let mut h = next_header(env, bridge, now, 0);
    h.max_time = now - T_LAG - 1;
    settle(env, operator, bridge, h, now);
}

#[test(should_fail_with = "batch time in the future")]
unconstrained fn future_batch_time_rejected() {
    let (env, operator, _, bridge) = setup();
    let now = now_plus(env, 10);
    let mut h = next_header(env, bridge, now, 0);
    h.max_time = now + 1;
    settle(env, operator, bridge, h, now);
}

#[test(should_fail_with = "time regressed")]
unconstrained fn time_regression_rejected() {
    let (env, operator, _, bridge) = setup();
    let now = now_plus(env, 100);
    settle(env, operator, bridge, next_header(env, bridge, now, 0), now);
    let now2 = now_plus(env, 10);
    let mut h = next_header(env, bridge, now2, 0);
    h.min_time = now - 1;
    settle(env, operator, bridge, h, now2);
}

#[test]
unconstrained fn halt_resumes_with_one_catch_up_batch() {
    // SPEC.md §8.4, §12: after the operator stops settling for a day, one batch whose L3 time
    // jumps to the present is accepted (no request is pending).
    let (env, operator, _, bridge) = setup();
    let now = now_plus(env, 10);
    settle(env, operator, bridge, next_header(env, bridge, now, 0), now);
    let later = now_plus(env, 24 * 60 * 60);
    settle(env, operator, bridge, next_header(env, bridge, later, 0), later);
    let (_, _, batch_number, last_time, _, _) = tip(env, bridge);
    assert((batch_number, last_time) == (2, later));
}

unconstrained fn new_leaves() -> [Field; VK_TREE_LEAVES] {
    let mut leaves: [Field; VK_TREE_LEAVES] = [0; VK_TREE_LEAVES];
    leaves[24] = 0xabc;
    leaves[25] = 0xdef;
    leaves
}

#[test]
unconstrained fn upgrade_takes_effect_only_after_delay() {
    let (env, operator, _, bridge) = setup();
    let new_config = config_hash(vk_tree_root_of(new_leaves()), 9);
    let _ = env.call_public(operator, L3XBridge::at(bridge).schedule_upgrade(new_leaves(), 9, 0x777));

    // Before the delay the genesis configuration applies.
    env.advance_next_block_timestamp_by(UPGRADE_DELAY - 60);
    env.mine_block();
    let (_, root_vk, config) = env.view_public(L3XBridge::at(bridge).get_config());
    assert((root_vk, config) == (ROOT_VK, CONFIG));
    let now = now_plus(env, 10);
    settle(env, operator, bridge, next_header(env, bridge, now, 0), now);

    // After it, the new one does.
    env.advance_next_block_timestamp_by(120);
    env.mine_block();
    let (_, root_vk, config) = env.view_public(L3XBridge::at(bridge).get_config());
    assert((root_vk, config) == (0x777, new_config));
    let now2 = now_plus(env, 10);
    let mut h = next_header(env, bridge, now2, 0);
    h.config_hash = new_config;
    settle(env, operator, bridge, h, now2);
}

#[test(should_fail_with = "config mismatch")]
unconstrained fn scheduled_config_not_usable_early() {
    let (env, operator, _, bridge) = setup();
    let new_config = config_hash(vk_tree_root_of(new_leaves()), 9);
    let _ = env.call_public(operator, L3XBridge::at(bridge).schedule_upgrade(new_leaves(), 9, 0x777));
    let now = now_plus(env, UPGRADE_DELAY - 60);
    let mut h = next_header(env, bridge, now, 0);
    h.config_hash = new_config;
    settle(env, operator, bridge, h, now);
}

#[test(should_fail_with = "config mismatch")]
unconstrained fn old_config_rejected_after_upgrade() {
    let (env, operator, _, bridge) = setup();
    let _ = env.call_public(operator, L3XBridge::at(bridge).schedule_upgrade(new_leaves(), 9, 0x777));
    env.advance_next_block_timestamp_by(UPGRADE_DELAY + 60);
    env.mine_block();
    let now = now_plus(env, 10);
    settle(env, operator, bridge, next_header(env, bridge, now, 0), now);
}

#[test(should_fail_with = "not operator")]
unconstrained fn only_operator_schedules_upgrades() {
    let (env, _, user, bridge) = setup();
    let _ = env.call_public(user, L3XBridge::at(bridge).schedule_upgrade(new_leaves(), 9, 0x777));
}

#[test]
unconstrained fn operator_change_is_delayed() {
    let (env, operator, user, bridge) = setup();
    let _ = env.call_public(operator, L3XBridge::at(bridge).schedule_operator(user));
    env.advance_next_block_timestamp_by(UPGRADE_DELAY + 60);
    env.mine_block();
    let (current, _, _) = env.view_public(L3XBridge::at(bridge).get_config());
    assert(current == user);
    let now = now_plus(env, 10);
    settle(env, user, bridge, next_header(env, bridge, now, 0), now);
}

#[test(should_fail_with = "not operator")]
unconstrained fn new_operator_cannot_settle_early() {
    let (env, operator, user, bridge) = setup();
    let _ = env.call_public(operator, L3XBridge::at(bridge).schedule_operator(user));
    let now = now_plus(env, UPGRADE_DELAY - 60);
    settle(env, user, bridge, next_header(env, bridge, now, 0), now);
}
