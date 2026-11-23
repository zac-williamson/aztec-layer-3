//! TXE tests for the Bridge (SPEC.md §10, §12, §17). TXE simulates private functions without
//! proving, so the root proof here is a dummy and headers are built by hand; the proof binding is
//! tested end to end against real proofs in scripts/src.
use crate::L3XBridge;
use crate::L3XBridge::{CustodyConfig, DepositOpening, Payout, ReceiptConfig};
use std::embedded_curve_ops::EmbeddedCurveScalar;
use aztec::{
    protocol::{address::AztecAddress, traits::ToField},
    test::helpers::{authwit::add_private_authwit_from_call, test_environment::TestEnvironment},
};
use ctoken::{ConfidentialToken, Credit, credit_id};
use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof};
use l3x_exchange::{
    account::{account_leaf, AccountPriv, AccountPub, enc, enc_commitment, master_auth_of, Position},
    consts::{
        ACCOUNTS_HEIGHT, CLASS_INSURANCE, CLASS_USER, DS_ACCT_NODE, DS_WD_NODE, KIND_REKEY, MAX_WD_BATCH,
        PROTOCOL_ACCOUNTS, WD_HEIGHT,
    },
    state::{genesis_state_root, MARKET_DATA_LEN, market_data_hash},
    deposit_blind,
    request::payload_hash,
    tree::merkle_root,
    withdrawal_record, withdrawals_root,
};
use l3x_types::{
    BatchHeader, config_hash, DA_MAX, da_hash_flat, hash::hash, merge::{VK_TREE_LEAVES, vk_tree_root_of}, priority_entry,
    receipt_leaf, receipt_node,
};

global ROOT_VK: Field = 0x1234;
global CONFIG: Field = 0x5678;
global T_FORCE: u64 = 1000;
global T_CLAIM: u64 = 500;
global REQUEST_FEE: u128 = 25;
global T_REFRESH: u64 = 100_000;
global T_LATE: u64 = 300;
// Receipt key and two receipts signed with it (scripts/src/receipt_vectors.ts).
global RECEIPT_DOMAIN: Field = 0x1234abcd;
global RECEIPT_PK_X: Field = 0x227b763466c29a7bd8281d9357510eb4a09f28f77212e701a8022761cfff6a60;
global RECEIPT_PK_Y: Field = 0x0ac3c64095fd102f2c25c8033ed095ad808a8a2c5071635a5a93c10f6bfcdf5a;
global T_SETTLE: u64 = 100;
global T_RESP: u64 = 200;
global SLASH: u128 = 400;
global R1_MSG: Field = 0x5151;
global R1_SEQ: u64 = 7;
global R1_S: EmbeddedCurveScalar = EmbeddedCurveScalar { lo: 0xe95511a7b4b2ea512cbd5ac0fd5dca25, hi: 0x06c8a305607119b4f87613861f61650c };
global R1_E: EmbeddedCurveScalar = EmbeddedCurveScalar { lo: 0x83d843e1075da2becba8b31cdeae0839, hi: 0x01a4b9281a65ef34420cf9e016072a17 };
global R2_MSG: Field = 0x6262;
global R2_SEQ: u64 = 8;
global R2_S: EmbeddedCurveScalar = EmbeddedCurveScalar { lo: 0x56e91bdad1a1a1752f44a6ca2ecf81ff, hi: 0x102b2cd7fc8650ef72705699899909dc };
global R2_E: EmbeddedCurveScalar = EmbeddedCurveScalar { lo: 0xa2a5809e3c98a5cca1375a0f562bf4ce, hi: 0x2a1d389ec3cbe0b8085e17515f3dbbc3 };
global ISSUED: u64 = 1;
global T_LAG: u64 = 15 * 60;
global UPGRADE_DELAY: u64 = 21 * 24 * 60 * 60;
global TEST_DA_LEN: u32 = 8;
global PRICE: u64 = 10;
global T_DEP: u64 = 600;
global T_PAYOUT: u64 = 400;
global MIN_DEPOSIT: u128 = 10;

struct Env {
    env: TestEnvironment,
    operator: AztecAddress,
    alice: AztecAddress,
    bob: AztecAddress,
    token: AztecAddress,
    bridge: AztecAddress,
}

/// The protocol accounts' master authorizations and encryption-key commitments in these tests.
global PROTOCOL_MAUTH: [Field; PROTOCOL_ACCOUNTS] = [0x101, 0x102];
global PROTOCOL_ENC: [Field; PROTOCOL_ACCOUNTS] = [0x201, 0x202];

unconstrained fn protocol_pubs(operator: AztecAddress) -> [AccountPub; PROTOCOL_ACCOUNTS] {
    [
        AccountPub { owner: operator.to_field(), master_auth: PROTOCOL_MAUTH[0], enc_commitment: PROTOCOL_ENC[0], class: 0 },
        AccountPub { owner: operator.to_field(), master_auth: PROTOCOL_MAUTH[1], enc_commitment: PROTOCOL_ENC[1], class: 0 },
    ]
}

unconstrained fn setup() -> Env {
    let mut env = TestEnvironment::new();
    let operator = env.create_light_account();
    // Alice deposits, which needs an account contract to authorize the Bridge's token call.
    let alice = env.create_contract_account();
    let bob = env.create_light_account();
    let token = env.deploy("@ctoken/ConfidentialToken").with_public_initializer(
        operator,
        ConfidentialToken::interface().constructor(operator),
    );
    let bridge = env.deploy("L3XBridge").with_public_initializer(
        operator,
        L3XBridge::interface().constructor(
            operator,
            ROOT_VK,
            CONFIG,
            token,
            T_FORCE,
            T_CLAIM,
            T_REFRESH,
            T_LATE,
            REQUEST_FEE,
            ReceiptConfig {
                domain: RECEIPT_DOMAIN,
                pk_x: RECEIPT_PK_X,
                pk_y: RECEIPT_PK_Y,
                t_settle: T_SETTLE,
                t_resp: T_RESP,
                slash: SLASH,
            },
            CustodyConfig { t_dep: T_DEP, t_payout: T_PAYOUT, min_deposit: MIN_DEPOSIT },
            [operator, operator],
            PROTOCOL_MAUTH,
            PROTOCOL_ENC,
        ),
    );
    let _ = env.call_public(operator, ConfidentialToken::at(token).mint(alice, 10_000));
    let _ = env.call_public(alice, ConfidentialToken::at(token).approve(bridge, 10_000));
    Env { env, operator, alice, bob, token, bridge }
}

/// Public token balance; the Bridge's is the vault plus the bond and open challenges' fees.
unconstrained fn balance(e: Env, who: AztecAddress) -> u128 {
    e.env.view_public(ConfidentialToken::at(e.token).balance_of_public(who))
}

unconstrained fn shield(e: Env, who: AztecAddress, amount: u128, blind: Field) {
    let _: Field = e.env.call_private(who, ConfidentialToken::at(e.token).shield(amount, blind));
}

/// `from` shields `amount` into a credit and deposits it into `account`, refunding to `from`, under
/// its authorization of the Bridge's token call. Returns the opening the operator receives.
unconstrained fn deposit(e: Env, from: AztecAddress, account: Field, amount: u128, salt: Field) -> DepositOpening {
    let blind = salt + 0x5000;
    shield(e, from, amount, blind);
    let credits = [Credit { amount, blind }, Credit::empty()];
    let dblind = deposit_blind(account, from.to_field(), from.to_field(), salt);
    add_private_authwit_from_call(
        e.env,
        from,
        e.bridge,
        ConfidentialToken::at(e.token).transfer(from, e.bridge, amount, credits, dblind, 0, salt),
    );
    e.env.call_private(from, L3XBridge::at(e.bridge).deposit(account, amount, from, salt, credits, 0, salt));
    DepositOpening { account_index: account, amount, refund_to: from, depositor: from, salt }
}

unconstrained fn no_deposit() -> DepositOpening {
    DepositOpening { account_index: 0, amount: 0, refund_to: AztecAddress::zero(), depositor: AztecAddress::zero(), salt: 0 }
}

unconstrained fn no_payout() -> Payout {
    Payout { batch: 0, index: 0, recipient: AztecAddress::zero(), amount: 0, salt: 0, path: [0; WD_HEIGHT], blind: 0 }
}

unconstrained fn custody(e: Env, deposits: [DepositOpening; 4], n_deposits: u32, payouts: [Payout; 4], n_payouts: u32) {
    e.env.call_private(e.operator, L3XBridge::at(e.bridge).custody(deposits, n_deposits, payouts, n_payouts));
}

/// Custody sweeps one deposit into the vault and queues it.
unconstrained fn sweep(e: Env, d: DepositOpening) {
    custody(e, [d, no_deposit(), no_deposit(), no_deposit()], 1, [no_payout(); 4], 0);
}

/// A deposit custody has swept and queued.
unconstrained fn queue_deposit(e: Env, from: AztecAddress, account: Field, amount: u128, salt: Field) -> DepositOpening {
    let d = deposit(e, from, account, amount, salt);
    sweep(e, d);
    d
}

/// Custody pays record 0 of a single-record batch as a credit with blind `blind`.
unconstrained fn pay(batch: u64, recipient: AztecAddress, amount: u64, salt: Field, blind: Field) -> Payout {
    Payout { batch, index: 0, recipient, amount, salt, path: single_record_path(), blind }
}

/// `who` unshields its credit (`amount`, `blind`) into its public balance, proving it holds it.
unconstrained fn cash(e: Env, who: AztecAddress, amount: u128, blind: Field) {
    e.env.call_private(who, ConfidentialToken::at(e.token).unshield(who, amount, [Credit { amount, blind }, Credit::empty()], 0));
}

unconstrained fn payload() -> [Field; DA_MAX] {
    let mut p: [Field; DA_MAX] = [0; DA_MAX];
    for i in 0..TEST_DA_LEN {
        p[i] = (i + 1) as Field;
    }
    p
}

/// Market data with market 0 at index `price` (published at `time`, marked at the index) and
/// cumulative funding `cum`; the other markets unlisted.
unconstrained fn md(price: u64, time: u64, cum: i64) -> [Field; MARKET_DATA_LEN] {
    let mut d: [Field; MARKET_DATA_LEN] = [0; MARKET_DATA_LEN];
    d[0] = price as Field;
    d[1] = time as Field;
    d[2] = price as Field;
    d[3] = enc(cum);
    d
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
    let (cycle_start, _) = e.env.view_public(L3XBridge::at(e.bridge).get_refresh());
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
        action_log_root: 0,
        da_hash: da_hash_flat(payload(), TEST_DA_LEN),
        market_data_hash: market_data_hash(md(PRICE, now, 0)),
        config_hash: CONFIG,
        cycle_start,
        receipts_root: 0,
    }
}

/// Settles `h` in a block at time `now` with a dummy proof; the market data is md(PRICE, max_time, 0).
unconstrained fn settle(e: Env, from: AztecAddress, h: BatchHeader, now: u64) {
    settle_with(e, from, h, now, md(PRICE, h.max_time, 0));
}

unconstrained fn settle_with(e: Env, from: AztecAddress, h: BatchHeader, now: u64, data: [Field; MARKET_DATA_LEN]) {
    e.env.set_next_block_timestamp(now);
    let proof: UltraHonkZKProof = [0; 458];
    let vk: UltraHonkVerificationKey = [0; 115];
    e.env.call_private(
        from,
        L3XBridge::at(e.bridge).settle(h.to_fields(), proof, vk, payload(), TEST_DA_LEN, data),
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
    assert(state_root == genesis_state_root(protocol_pubs(e.operator)));
    let (owners, mauths, encs) = e.env.view_public(L3XBridge::at(e.bridge).get_protocol_accounts());
    assert((owners[0] == e.operator) & (mauths == PROTOCOL_MAUTH) & (encs == PROTOCOL_ENC));
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
    h.market_data_hash = market_data_hash(md(PRICE + 1, now, 0));
    settle(e, e.operator, h, now);
}

// ---- Priority queue (SPEC.md §12) ----

// ---- Custody (SPEC.md §10.3) ----

#[test]
unconstrained fn deposit_waits_for_custody_then_enters_the_vault_and_the_queue() {
    let e = setup();
    let d = deposit(e, e.alice, 0, 1000, 0x51);
    let credit = credit_id(e.bridge, 1000, deposit_blind(0, e.alice.to_field(), e.alice.to_field(), 0x51));
    let (state, _) = e.env.view_public(L3XBridge::at(e.bridge).get_deposit(credit));
    assert(state == 1);
    // The funds left Alice's public balance when she shielded them; the vault has not seen them.
    assert((balance(e, e.alice), balance(e, e.bridge)) == (9000, 0));
    let (_, _, _, _, _, count) = tip(e);
    assert(count == 0);
    sweep(e, d);
    let (state, _) = e.env.view_public(L3XBridge::at(e.bridge).get_deposit(credit));
    assert(state == 2);
    assert(balance(e, e.bridge) == 1000);
    let (_, _, _, _, cursor, count) = tip(e);
    assert((cursor, count) == (0, 1));
}

#[test(should_fail_with = "Unknown auth witness")]
unconstrained fn deposit_needs_the_depositors_authorization() {
    let e = setup();
    shield(e, e.alice, 100, 0x5051);
    e.env.call_private(
        e.alice,
        L3XBridge::at(e.bridge).deposit(0, 100, e.alice, 0x51, [Credit { amount: 100, blind: 0x5051 }, Credit::empty()], 0, 0x51),
    );
}

#[test(should_fail_with = "deposit amount out of range")]
unconstrained fn dust_deposit_rejected() {
    let e = setup();
    let _ = deposit(e, e.alice, 0, MIN_DEPOSIT - 1, 0x51);
}

#[test(should_fail_with = "not operator")]
unconstrained fn only_the_operator_runs_custody() {
    let e = setup();
    let d = deposit(e, e.alice, 0, 1000, 0x51);
    e.env.call_private(e.bob, L3XBridge::at(e.bridge).custody([d, no_deposit(), no_deposit(), no_deposit()], 1, [no_payout(); 4], 0));
}

#[test(should_fail)]
unconstrained fn a_deposit_is_swept_once() {
    let e = setup();
    let d = queue_deposit(e, e.alice, 0, 1000, 0x51);
    sweep(e, d);
}

#[test(should_fail)]
unconstrained fn custody_cannot_change_a_deposit() {
    let e = setup();
    let mut d = deposit(e, e.alice, 0, 1000, 0x51);
    // Another account, or another amount, opens no credit the Bridge holds.
    d.account_index = 1;
    sweep(e, d);
}

#[test]
unconstrained fn custody_nets_deposits_against_payouts() {
    let e = setup();
    // Batch 1 consumes a 1000 deposit and settles a 300 record for Bob.
    settle_withdrawal(e, withdrawal_record(e.bob.to_field(), 300, 5, 1, 0));
    let d1 = deposit(e, e.alice, 0, 250, 0x52);
    let d2 = deposit(e, e.alice, 0, 150, 0x53);
    custody(e, [d1, d2, no_deposit(), no_deposit()], 2, [pay(1, e.bob, 300, 5, 0xb0b), no_payout(), no_payout(), no_payout()], 1);
    // Net 250 + 150 - 300 = 100 into the vault; both deposits queued; Bob holds a 300 credit.
    assert(balance(e, e.bridge) == 1100);
    let (_, _, _, _, _, count) = tip(e);
    assert(count == 3);
    cash(e, e.bob, 300, 0xb0b);
    assert(balance(e, e.bob) == 300);
}

#[test]
unconstrained fn custody_pays_a_net_outflow_from_the_vault() {
    let e = setup();
    settle_withdrawal(e, withdrawal_record(e.bob.to_field(), 300, 5, 1, 0));
    custody(e, [no_deposit(); 4], 0, [pay(1, e.bob, 300, 5, 0xb0b), no_payout(), no_payout(), no_payout()], 1);
    assert(balance(e, e.bridge) == 700);
    cash(e, e.bob, 300, 0xb0b);
    assert(balance(e, e.bob) == 300);
}

#[test(should_fail_with = "already paid")]
unconstrained fn custody_pays_a_record_once() {
    let e = setup();
    settle_withdrawal(e, withdrawal_record(e.bob.to_field(), 300, 5, 1, 0));
    custody(e, [no_deposit(); 4], 0, [pay(1, e.bob, 300, 5, 0xb0b), no_payout(), no_payout(), no_payout()], 1);
    custody(e, [no_deposit(); 4], 0, [pay(1, e.bob, 300, 5, 0xb0c), no_payout(), no_payout(), no_payout()], 1);
}

#[test(should_fail_with = "record not in the batch's withdrawals tree")]
unconstrained fn custody_cannot_inflate_a_payout() {
    let e = setup();
    settle_withdrawal(e, withdrawal_record(e.bob.to_field(), 300, 5, 1, 0));
    custody(e, [no_deposit(); 4], 0, [pay(1, e.bob, 900, 5, 0xb0b), no_payout(), no_payout(), no_payout()], 1);
}

#[test(should_fail_with = "record not in the batch's withdrawals tree")]
unconstrained fn custody_cannot_redirect_a_payout() {
    let e = setup();
    settle_withdrawal(e, withdrawal_record(e.bob.to_field(), 300, 5, 1, 0));
    custody(e, [no_deposit(); 4], 0, [pay(1, e.operator, 300, 5, 0xb0b), no_payout(), no_payout(), no_payout()], 1);
}

#[test(should_fail_with = "vault short")]
unconstrained fn custody_never_pays_from_the_bond() {
    let e = setup();
    // A record the vault does not cover (headers are hand-built here), with a bond in escrow.
    let _ = e.env.call_public(e.operator, ConfidentialToken::at(e.token).mint(e.operator, 700));
    let _ = e.env.call_public(e.operator, ConfidentialToken::at(e.token).approve(e.bridge, 700));
    let _ = e.env.call_public(e.operator, L3XBridge::at(e.bridge).post_bond(700));
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 0);
    let mut records: [Field; MAX_WD_BATCH] = [0; MAX_WD_BATCH];
    records[0] = withdrawal_record(e.bob.to_field(), 300, 5, 1, 0);
    h.withdrawals_root = withdrawals_root(records);
    h.withdrawals_count = 1;
    settle(e, e.operator, h, now);
    custody(e, [no_deposit(); 4], 0, [pay(1, e.bob, 300, 5, 0xb0b), no_payout(), no_payout(), no_payout()], 1);
}

#[test(should_fail_with = "deposit not yet reclaimable")]
unconstrained fn reclaim_waits_for_t_dep() {
    let e = setup();
    let d = deposit(e, e.alice, 0, 1000, 0x51);
    e.env.call_private(e.bob, L3XBridge::at(e.bridge).reclaim_deposit(d, 0xa11));
}

#[test]
unconstrained fn unswept_deposit_returns_to_its_refund_address() {
    let e = setup();
    let d = deposit(e, e.alice, 0, 1000, 0x51);
    e.env.advance_next_block_timestamp_by(T_DEP + 10);
    // Anyone holding the opening may reclaim; the funds go only to refund_to.
    e.env.call_private(e.bob, L3XBridge::at(e.bridge).reclaim_deposit(d, 0xa11));
    let credit = credit_id(e.bridge, 1000, deposit_blind(0, e.alice.to_field(), e.alice.to_field(), 0x51));
    let (state, _) = e.env.view_public(L3XBridge::at(e.bridge).get_deposit(credit));
    assert(state == 3);
    cash(e, e.alice, 1000, 0xa11);
    assert(balance(e, e.alice) == 10_000);
}

#[test(should_fail)]
unconstrained fn a_swept_deposit_cannot_be_reclaimed() {
    let e = setup();
    let d = queue_deposit(e, e.alice, 0, 1000, 0x51);
    e.env.advance_next_block_timestamp_by(T_DEP + 10);
    e.env.call_private(e.bob, L3XBridge::at(e.bridge).reclaim_deposit(d, 0xa11));
}

#[test(should_fail)]
unconstrained fn a_reclaimed_deposit_cannot_be_swept() {
    let e = setup();
    let d = deposit(e, e.alice, 0, 1000, 0x51);
    e.env.advance_next_block_timestamp_by(T_DEP + 10);
    e.env.call_private(e.bob, L3XBridge::at(e.bridge).reclaim_deposit(d, 0xa11));
    sweep(e, d);
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

// ---- Rekey (SPEC.md §7.3) ----

#[test]
unconstrained fn rekey_pays_the_fee_and_queues_the_new_keys_with_the_caller() {
    let e = setup();
    let k_enc = 0xcafe;
    let (auth, commitment) = (master_auth_of(3, 4), enc_commitment(k_enc));
    e.env.call_private(e.alice, L3XBridge::at(e.bridge).rekey(2, auth, commitment, k_enc));
    let (_, _, _, _, cursor, count) = tip(e);
    assert((cursor == 0) & (count == 1));
    // The circuit applies it only if the caller owns account 2 (seg_priority `republish`).
    let (_, entry, time) = e.env.view_public(L3XBridge::at(e.bridge).get_priority(0));
    assert(entry == priority_entry(payload_hash(KIND_REKEY, 2, auth, commitment), e.alice.to_field(), time));
    assert(balance(e, e.operator) == REQUEST_FEE);
    assert(balance(e, e.alice) == 10_000 - REQUEST_FEE);
}

#[test(should_fail_with = "k_enc does not open the commitment")]
unconstrained fn rekey_rejects_a_key_the_operator_could_not_use() {
    let e = setup();
    e.env.call_private(e.alice, L3XBridge::at(e.bridge).rekey(2, master_auth_of(3, 4), enc_commitment(0xcafe), 0xcafd));
}

#[test(should_fail)]
unconstrained fn rekey_needs_the_request_fee() {
    let e = setup();
    // Bob holds no tokens, so he cannot pay the fee.
    e.env.call_private(e.bob, L3XBridge::at(e.bridge).rekey(3, master_auth_of(3, 4), enc_commitment(0xcafe), 0xcafe));
}

#[test(should_fail_with = "priority request overdue")]
unconstrained fn an_unprocessed_rekey_blocks_settlement() {
    let e = setup();
    e.env.call_private(e.alice, L3XBridge::at(e.bridge).rekey(2, master_auth_of(3, 4), enc_commitment(0xcafe), 0xcafe));
    let now = now_plus(e, T_FORCE + 10);
    settle(e, e.operator, next_header(e, now, 0), now);
}

#[test]
unconstrained fn priority_requests_consumed_in_order() {
    let e = setup();
    let _ = queue_deposit(e, e.alice, 0, 100, 0x101);
    let _ = queue_deposit(e, e.alice, 0, 200, 0x102);
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
    let _ = queue_deposit(e, e.alice, 0, 100, 0x103);
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 1);
    h.priority_head_end += 1;
    settle(e, e.operator, h, now);
}

#[test(should_fail_with = "priority head start")]
unconstrained fn forged_priority_head_start_rejected() {
    let e = setup();
    let _ = queue_deposit(e, e.alice, 0, 100, 0x104);
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 1);
    h.priority_head_start += 1;
    settle(e, e.operator, h, now);
}

#[test(should_fail_with = "priority start")]
unconstrained fn skipped_priority_request_rejected() {
    let e = setup();
    let _ = queue_deposit(e, e.alice, 0, 100, 0x105);
    let _ = queue_deposit(e, e.alice, 0, 200, 0x106);
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
    let _ = queue_deposit(e, e.alice, 0, 100, 0x107);
    let now = now_plus(e, T_FORCE + 10);
    settle(e, e.operator, next_header(e, now, 0), now);
}

#[test]
unconstrained fn request_within_deadline_may_wait() {
    let e = setup();
    let _ = queue_deposit(e, e.alice, 0, 100, 0x108);
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
    h.market_data_hash = market_data_hash(md(PRICE, h.max_time, 0));
    settle(e, e.operator, h, now);
}

#[test(should_fail_with = "batch time in the future")]
unconstrained fn future_batch_time_rejected() {
    let e = setup();
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 0);
    h.max_time = now + 1;
    h.market_data_hash = market_data_hash(md(PRICE, h.max_time, 0));
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

/// Batch 1 consumes a queued 1000 deposit and settles `record` alone in its withdrawals tree.
unconstrained fn settle_withdrawal(e: Env, record: Field) {
    let _ = queue_deposit(e, e.alice, 0, 1000, 0x109);
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 1);
    let mut records: [Field; MAX_WD_BATCH] = [0; MAX_WD_BATCH];
    records[0] = record;
    h.withdrawals_root = withdrawals_root(records);
    h.withdrawals_count = 1;
    settle(e, e.operator, h, now);
}

#[test]
unconstrained fn settled_withdrawal_paid_once_to_its_recipient() {
    let e = setup();
    let record = withdrawal_record(e.bob.to_field(), 300, 5, 1, 0);
    settle_withdrawal(e, record);
    // Custody did not pay it within t_payout. Anyone may submit the claim; only the recipient is
    // paid, from the vault, and the amount becomes public.
    e.env.advance_next_block_timestamp_by(T_PAYOUT + 10);
    e.env.call_private(e.alice, L3XBridge::at(e.bridge).claim_withdrawal(1, 0, e.bob, 300, 5, single_record_path()),
    );
    assert(balance(e, e.bob) == 300);
    assert(balance(e, e.bridge) == 700);
}

#[test(should_fail_with = "payout window still open")]
unconstrained fn claim_waits_for_t_payout() {
    let e = setup();
    settle_withdrawal(e, withdrawal_record(e.bob.to_field(), 300, 5, 1, 0));
    e.env.call_private(e.bob, L3XBridge::at(e.bridge).claim_withdrawal(1, 0, e.bob, 300, 5, single_record_path()));
}

#[test(should_fail_with = "already paid")]
unconstrained fn record_paid_by_custody_cannot_be_claimed() {
    let e = setup();
    settle_withdrawal(e, withdrawal_record(e.bob.to_field(), 300, 5, 1, 0));
    custody(e, [no_deposit(); 4], 0, [pay(1, e.bob, 300, 5, 0xb0b), no_payout(), no_payout(), no_payout()], 1);
    e.env.advance_next_block_timestamp_by(T_PAYOUT + 10);
    e.env.call_private(e.bob, L3XBridge::at(e.bridge).claim_withdrawal(1, 0, e.bob, 300, 5, single_record_path()));
}

#[test(should_fail_with = "already paid")]
unconstrained fn withdrawal_cannot_be_paid_twice() {
    let e = setup();
    settle_withdrawal(e, withdrawal_record(e.bob.to_field(), 300, 5, 1, 0));
    e.env.advance_next_block_timestamp_by(T_PAYOUT + 10);
    let claim = L3XBridge::at(e.bridge).claim_withdrawal(1, 0, e.bob, 300, 5, single_record_path());
    e.env.call_private(e.bob, claim);
    e.env.call_private(e.bob, claim);
}

#[test(should_fail_with = "record not in the batch's withdrawals tree")]
unconstrained fn withdrawal_amount_cannot_be_changed() {
    let e = setup();
    settle_withdrawal(e, withdrawal_record(e.bob.to_field(), 300, 5, 1, 0));
    e.env.call_private(e.bob, L3XBridge::at(e.bridge).claim_withdrawal(1, 0, e.bob, 900, 5, single_record_path()),
    );
}

#[test(should_fail_with = "record not in the batch's withdrawals tree")]
unconstrained fn withdrawal_recipient_cannot_be_redirected() {
    let e = setup();
    settle_withdrawal(e, withdrawal_record(e.bob.to_field(), 300, 5, 1, 0));
    e.env.call_private(e.alice, L3XBridge::at(e.bridge).claim_withdrawal(1, 0, e.alice, 300, 5, single_record_path()),
    );
}

// ---- Forced requests (SPEC.md §7.3, §12) ----

#[test]
unconstrained fn forced_request_pays_the_fee_and_queues() {
    let e = setup();
    let _ = e.env.call_public(e.alice, L3XBridge::at(e.bridge).submit_forced(3, 2, e.alice.to_field(), 0));
    let (_, _, _, _, cursor, count) = tip(e);
    assert((cursor == 0) & (count == 1));
    assert(balance(e, e.operator) == REQUEST_FEE);
    assert(balance(e, e.alice) == 10_000 - REQUEST_FEE);
}

#[test(should_fail_with = "not a forced request")]
unconstrained fn forced_request_kind_checked() {
    let e = setup();
    let _ = e.env.call_public(e.alice, L3XBridge::at(e.bridge).submit_forced(2, 2, 1000, 0));
}

#[test(should_fail_with = "priority request overdue")]
unconstrained fn unprocessed_forced_request_blocks_settlement() {
    let e = setup();
    let _ = e.env.call_public(e.alice, L3XBridge::at(e.bridge).submit_forced(5, 2, 0, 0));
    let now = now_plus(e, T_FORCE + 10);
    settle(e, e.operator, next_header(e, now, 0), now);
}

// ---- Receipts and accountability (SPEC.md §11) ----

/// Settles a batch whose receipts root holds receipt 1's leaf at depth 1 (its sibling is empty),
/// then challenges receipt 1 as Bob, past t_settle.
unconstrained fn receipt_world() -> Env {
    let e = setup();
    let _ = e.env.call_public(e.operator, ConfidentialToken::at(e.token).mint(e.bob, 1000));
    let _ = e.env.call_public(e.bob, ConfidentialToken::at(e.token).approve(e.bridge, 1000));
    let now = now_plus(e, T_SETTLE + 10);
    let mut h = next_header(e, now, 0);
    h.receipts_root = receipt_node(receipt_leaf(R1_SEQ, R1_MSG), 0);
    settle(e, e.operator, h, now);
    e
}

unconstrained fn challenge(e: Env, msg: Field, seq: u64, s: EmbeddedCurveScalar, ee: EmbeddedCurveScalar) {
    e.env.call_private(e.bob, L3XBridge::at(e.bridge).challenge(msg, seq, ISSUED, s, ee));
}

#[test]
unconstrained fn answered_challenge_pays_the_fee_to_the_operator() {
    let e = receipt_world();
    challenge(e, R1_MSG, R1_SEQ, R1_S, R1_E);
    assert(balance(e, e.bob) == 1000 - REQUEST_FEE);
    let id = receipt_leaf(R1_SEQ, R1_MSG);
    let mut path: [Field; 24] = [0; 24];
    path[0] = 0;
    let before = balance(e, e.operator);
    e.env.call_private(e.operator, L3XBridge::at(e.bridge).answer(R1_MSG, R1_SEQ, 1, 1, 0, path));
    let (open, done, _, _) = e.env.view_public(L3XBridge::at(e.bridge).get_challenge(id));
    assert(!open & done);
    assert(balance(e, e.operator) == before + REQUEST_FEE);
}

#[test(should_fail_with = "receipt not in the batch")]
unconstrained fn wrong_receipt_path_rejected() {
    let e = receipt_world();
    challenge(e, R1_MSG, R1_SEQ, R1_S, R1_E);
    let mut path: [Field; 24] = [0; 24];
    path[0] = 5;
    e.env.call_private(e.operator, L3XBridge::at(e.bridge).answer(R1_MSG, R1_SEQ, 1, 1, 0, path));
}

#[test]
unconstrained fn unanswered_challenge_slashes_the_bond() {
    let e = receipt_world();
    let _ = e.env.call_public(e.operator, ConfidentialToken::at(e.token).mint(e.operator, 1000));
    let _ = e.env.call_public(e.operator, ConfidentialToken::at(e.token).approve(e.bridge, 1000));
    let _ = e.env.call_public(e.operator, L3XBridge::at(e.bridge).post_bond(1000));
    // Receipt 2 was signed but its action never settled.
    challenge(e, R2_MSG, R2_SEQ, R2_S, R2_E);
    e.env.advance_next_block_timestamp_by(T_RESP + 10);
    let _ = e.env.call_public(e.alice, L3XBridge::at(e.bridge).slash(receipt_leaf(R2_SEQ, R2_MSG)));
    assert(balance(e, e.bob) == 1000 + SLASH);
    let (_, done, _, bond) = e.env.view_public(L3XBridge::at(e.bridge).get_challenge(receipt_leaf(R2_SEQ, R2_MSG)));
    assert(done & (bond == 1000 - SLASH));
}

#[test(should_fail_with = "challenge still open")]
unconstrained fn slash_waits_for_the_deadline() {
    let e = receipt_world();
    challenge(e, R2_MSG, R2_SEQ, R2_S, R2_E);
    let _ = e.env.call_public(e.alice, L3XBridge::at(e.bridge).slash(receipt_leaf(R2_SEQ, R2_MSG)));
}

#[test(should_fail)]
unconstrained fn forged_receipt_rejected() {
    let e = receipt_world();
    // Receipt 1's signature over receipt 2's message.
    challenge(e, R2_MSG, R2_SEQ, R1_S, R1_E);
}

#[test(should_fail_with = "receipt too recent to challenge")]
unconstrained fn recent_receipt_cannot_be_challenged() {
    let e = setup();
    let _ = e.env.call_public(e.operator, ConfidentialToken::at(e.token).mint(e.bob, 1000));
    let _ = e.env.call_public(e.bob, ConfidentialToken::at(e.token).approve(e.bridge, 1000));
    let (_, deployed) = e.env.view_public(L3XBridge::at(e.bridge).get_refresh());
    // The vectors are issued at time 1; a deployment within t_settle of it is too early.
    if deployed + 5 < ISSUED + T_SETTLE {
        challenge(e, R1_MSG, R1_SEQ, R1_S, R1_E);
    } else {
        assert(false, "receipt too recent to challenge");
    }
}

#[test(should_fail_with = "receipt already challenged")]
unconstrained fn receipt_challenged_once() {
    let e = receipt_world();
    challenge(e, R1_MSG, R1_SEQ, R1_S, R1_E);
    let mut path: [Field; 24] = [0; 24];
    path[0] = 0;
    e.env.call_private(e.operator, L3XBridge::at(e.bridge).answer(R1_MSG, R1_SEQ, 1, 1, 0, path));
    challenge(e, R1_MSG, R1_SEQ, R1_S, R1_E);
}

// ---- Desert mode (SPEC.md §12) ----

/// Alice holds an account at index 0 with `collateral` and a position in market 0 of `size` lots
/// at entry notional `entry`, settled in batch 1 at index price PRICE; then she deposits 50 more
/// (salt QUEUED_SALT), which custody queues but no batch processes.
unconstrained fn desert_world(collateral: i64, size: i64, entry: i64) -> (Env, AccountPub, AccountPriv, [Field; ACCOUNTS_HEIGHT]) {
    desert_world_with(collateral, Position { size, entry, funding: 0 }, CLASS_USER, 0)
}

/// As desert_world, with a full market-0 position, an account class, and market 0's cumulative
/// funding index at the freeze.
unconstrained fn desert_world_with(collateral: i64, pos: Position, class: Field, cum: i64) -> (Env, AccountPub, AccountPriv, [Field; ACCOUNTS_HEIGHT]) {
    let e = setup();
    let pubv = AccountPub { owner: e.alice.to_field(), master_auth: master_auth_of(1, 2), enc_commitment: enc_commitment(3), class };
    let mut privv = AccountPriv::empty(0x77);
    privv.collateral = collateral;
    privv.positions[0] = pos;
    let (root, path) = single_account_tree(account_leaf(pubv, privv));
    let _ = queue_deposit(e, e.alice, 0, 1000, PROCESSED_SALT);
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 1);
    h.new_accounts_root = root;
    let data = md(PRICE, now, cum);
    h.market_data_hash = market_data_hash(data);
    settle_with(e, e.operator, h, now, data);
    let _ = queue_deposit(e, e.alice, 0, 50, QUEUED_SALT);
    (e, pubv, privv, path)
}

global PROCESSED_SALT: Field = 0xd1;
global QUEUED_SALT: Field = 0xd2;

/// Desert refund of a queued deposit, by Bob: the opening and the time its entry was queued.
unconstrained fn desert_refund(e: Env, index: u64, amount: u128, salt: Field) {
    let (_, _, time) = e.env.view_public(L3XBridge::at(e.bridge).get_priority(index));
    e.env.call_private(e.bob, L3XBridge::at(e.bridge).desert_refund(index, 0, amount, salt, e.alice, e.alice, time));
}

/// Desert refund of desert_world's queued deposit (queue index 1), to Alice.
unconstrained fn refund_queued(e: Env) {
    desert_refund(e, 1, 50, QUEUED_SALT);
}

unconstrained fn activate(e: Env) {
    e.env.advance_next_block_timestamp_by(T_FORCE + 10);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).activate_desert());
}

unconstrained fn exit_register(e: Env, pubv: AccountPub, privv: AccountPriv, path: [Field; ACCOUNTS_HEIGHT], price: u64, time: u64) {
    exit_register_with(e, pubv, privv, path, md(price, time, 0));
}

unconstrained fn exit_register_with(e: Env, pubv: AccountPub, privv: AccountPriv, path: [Field; ACCOUNTS_HEIGHT], data: [Field; MARKET_DATA_LEN]) {
    e.env.call_private(
        e.bob,
        L3XBridge::at(e.bridge).exit_register(
            0,
            e.alice,
            pubv.master_auth,
            pubv.enc_commitment,
            pubv.class,
            privv.plaintext(),
            path,
            data,
        ),
    );
}

#[test]
unconstrained fn desert_exit_from_the_frozen_root() {
    let (e, pubv, privv, path) = desert_world(1000, 0, 0);
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    // Unprocessed deposit: refunded in full.
    refund_queued(e);
    assert(balance(e, e.alice) == 9000);
    // Account claim, registered by anyone, paid to the owner after the window.
    exit_register(e, pubv, privv, path, PRICE, settled_time);
    e.env.advance_next_block_timestamp_by(T_CLAIM + 10);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).exit_withdraw(0));
    assert(balance(e, e.alice) == 10_000);
    assert(balance(e, e.bridge) == 0);
}

#[test]
unconstrained fn desert_payouts_exclude_the_bond() {
    let (e, pubv, privv, path) = desert_world(1000, 0, 0);
    let _ = e.env.call_public(e.operator, ConfidentialToken::at(e.token).mint(e.operator, 700));
    let _ = e.env.call_public(e.operator, ConfidentialToken::at(e.token).approve(e.bridge, 700));
    let _ = e.env.call_public(e.operator, L3XBridge::at(e.bridge).post_bond(700));
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    refund_queued(e);
    exit_register(e, pubv, privv, path, PRICE, settled_time);
    e.env.advance_next_block_timestamp_by(T_CLAIM + 10);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).exit_withdraw(0));
    // Alice gets her 1000, not a share of the bond; the bond stays in escrow.
    assert(balance(e, e.alice) == 10_000);
    assert(balance(e, e.bridge) == 700);
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

#[test]
unconstrained fn desert_accrues_funding_to_the_freeze() {
    // Long 100 lots entered at notional 900 with funding snapshot 0; market 0's cumulative funding
    // at the freeze is 2.5 per lot, so the position owes 250: 400 + 100 * 10 - 900 - 250 = 250.
    let (e, pubv, privv, path) = desert_world_with(400, Position { size: 100, entry: 900, funding: 0 }, CLASS_USER, 2_500_000);
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    exit_register_with(e, pubv, privv, path, md(PRICE, settled_time, 2_500_000));
    let (_, _, _, _, total) = e.env.view_public(L3XBridge::at(e.bridge).get_desert());
    assert(total == 250);
}

#[test(should_fail_with = "protocol accounts are paid after t_late")]
unconstrained fn desert_defers_protocol_accounts() {
    let (e, pubv, privv, path) = desert_world_with(1000, Position::empty(), CLASS_INSURANCE, 0);
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    exit_register(e, pubv, privv, path, PRICE, settled_time);
    e.env.advance_next_block_timestamp_by(T_CLAIM + 10);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).exit_withdraw(0));
}

#[test]
unconstrained fn desert_pays_protocol_accounts_after_t_late() {
    let (e, pubv, privv, path) = desert_world_with(1000, Position::empty(), CLASS_INSURANCE, 0);
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    refund_queued(e);
    exit_register(e, pubv, privv, path, PRICE, settled_time);
    e.env.advance_next_block_timestamp_by(T_CLAIM + T_LATE + 10);
    let before = balance(e, e.alice);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).exit_withdraw(0));
    // The protocol account's claim is paid from the residual: here the whole vault.
    assert(balance(e, e.alice) == before + 1000);
    assert(balance(e, e.bridge) == 0);
}

#[test]
unconstrained fn desert_late_claim_paid_from_the_residual() {
    let (e, pubv, privv, path) = desert_world(1000, 0, 0);
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    // Registered after the window: no window claims, so the ratio is 1 and the residual pays it.
    // The queued deposit's refund, claimed after that, takes what is left.
    e.env.advance_next_block_timestamp_by(T_CLAIM + 10);
    exit_register(e, pubv, privv, path, PRICE, settled_time);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).exit_withdraw(0));
    assert(balance(e, e.alice) == 10_000 - 1050 + 1000);
    assert(balance(e, e.bridge) == 50);
    refund_queued(e);
    assert((balance(e, e.alice), balance(e, e.bridge)) == (10_000, 0));
}

#[test]
unconstrained fn desert_refund_in_the_window_is_paid_in_full() {
    // The vault holds 1050 but Alice's account claims 1040 (hand-built state). The queued
    // deposit's refund, claimed in the window, is senior: paid in full before the ratio is fixed,
    // so the window claim gets the rest (1000 of 1040).
    let (e, pubv, privv, path) = desert_world(1040, 0, 0);
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    refund_queued(e);
    exit_register(e, pubv, privv, path, PRICE, settled_time);
    e.env.advance_next_block_timestamp_by(T_CLAIM + 10);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).exit_withdraw(0));
    assert((balance(e, e.alice), balance(e, e.bridge)) == (10_000, 0));
}

#[test]
unconstrained fn desert_refund_after_the_ratio_is_junior_to_window_claims() {
    // The same, with the refund claimed only after the window claim was paid: the window claim took
    // its 1040 in full (the ratio is 1), leaving the refund the residual 10.
    let (e, pubv, privv, path) = desert_world(1040, 0, 0);
    let (_, _, _, settled_time, _, _) = tip(e);
    activate(e);
    exit_register(e, pubv, privv, path, PRICE, settled_time);
    e.env.advance_next_block_timestamp_by(T_CLAIM + 10);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).exit_withdraw(0));
    refund_queued(e);
    assert((balance(e, e.alice), balance(e, e.bridge)) == (10_000 - 1050 + 1040 + 10, 0));
}

#[test]
unconstrained fn desert_late_claim_waits_for_window_claims() {
    // Alice (index 0, 1000) claims in the window; Bob (index 1, 500) registers late and withdraws
    // first. The window claim reserves its 1000 of the vault's 1050, so Bob gets only the residual
    // 50; the queued deposit, never claimed in the window, gets nothing.
    let e = setup();
    let alice_pub = AccountPub { owner: e.alice.to_field(), master_auth: master_auth_of(1, 2), enc_commitment: enc_commitment(3), class: CLASS_USER };
    let bob_pub = AccountPub { owner: e.bob.to_field(), master_auth: master_auth_of(4, 5), enc_commitment: enc_commitment(6), class: CLASS_USER };
    let mut alice_priv = AccountPriv::empty(0x77);
    alice_priv.collateral = 1000;
    let mut bob_priv = AccountPriv::empty(0x78);
    bob_priv.collateral = 500;
    let leaf0 = account_leaf(alice_pub, alice_priv);
    let leaf1 = account_leaf(bob_pub, bob_priv);
    let mut path0: [Field; ACCOUNTS_HEIGHT] = [0; ACCOUNTS_HEIGHT];
    let mut empty = 0;
    for i in 0..ACCOUNTS_HEIGHT {
        path0[i] = empty;
        empty = hash([DS_ACCT_NODE, empty, empty]);
    }
    let mut path1 = path0;
    path0[0] = leaf1;
    path1[0] = leaf0;
    let root = merkle_root(DS_ACCT_NODE, leaf0, 0, path0);
    let _ = queue_deposit(e, e.alice, 0, 1000, PROCESSED_SALT);
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 1);
    h.new_accounts_root = root;
    settle(e, e.operator, h, now);
    let _ = queue_deposit(e, e.alice, 0, 50, QUEUED_SALT);
    activate(e);
    let data = md(PRICE, now, 0);
    e.env.call_private(
        e.bob,
        L3XBridge::at(e.bridge).exit_register(0, e.alice, alice_pub.master_auth, alice_pub.enc_commitment, CLASS_USER, alice_priv.plaintext(), path0, data),
    );
    e.env.advance_next_block_timestamp_by(T_CLAIM + 10);
    e.env.call_private(
        e.bob,
        L3XBridge::at(e.bridge).exit_register(1, e.bob, bob_pub.master_auth, bob_pub.enc_commitment, CLASS_USER, bob_priv.plaintext(), path1, data),
    );
    let bob_before = balance(e, e.bob);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).exit_withdraw(1));
    assert(balance(e, e.bob) == bob_before + 50);
    let alice_before = balance(e, e.alice);
    let _ = e.env.call_public(e.bob, L3XBridge::at(e.bridge).exit_withdraw(0));
    assert(balance(e, e.alice) == alice_before + 1000);
    refund_queued(e);
    assert(balance(e, e.alice) == alice_before + 1000);
}

// ---- Refresh deadline (SPEC.md §9.5) ----

#[test(should_fail_with = "refresh overdue")]
unconstrained fn refresh_overdue_blocks_settlement() {
    let e = setup();
    let now = now_plus(e, T_REFRESH + 10);
    settle(e, e.operator, next_header(e, now, 0), now);
}

#[test]
unconstrained fn completing_the_refresh_cycle_restarts_the_clock() {
    let e = setup();
    let now = now_plus(e, 10);
    settle(e, e.operator, next_header(e, now, 0), now);
    // Past the deadline, a batch whose refresh cursor wraps settles and restarts the clock at the
    // L3 time of the wrap.
    let later = now_plus(e, T_REFRESH + 10);
    let mut h = next_header(e, later, 0);
    h.cycle_start = later;
    settle(e, e.operator, h, later);
    let (start, _) = e.env.view_public(L3XBridge::at(e.bridge).get_refresh());
    assert(start == later);
    // The next batch is inside the new window.
    let next = now_plus(e, 10);
    settle(e, e.operator, next_header(e, next, 0), next);
}

#[test(should_fail_with = "refresh cycle starts after its batch")]
unconstrained fn refresh_cycle_cannot_start_after_its_batch() {
    let e = setup();
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 0);
    h.cycle_start = now + 1;
    settle(e, e.operator, h, now);
}

#[test(should_fail_with = "refresh cycle regressed")]
unconstrained fn refresh_cycle_cannot_regress() {
    let e = setup();
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 0);
    h.cycle_start = now;
    settle(e, e.operator, h, now);
    let later = now_plus(e, 10);
    let mut g = next_header(e, later, 0);
    g.cycle_start = now - 5;
    settle(e, e.operator, g, later);
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
    let _ = queue_deposit(e, e.alice, 0, 10, 0x10e);
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
    desert_refund(e, 0, 1000, PROCESSED_SALT);
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
    // Past the refresh window, the first batch must complete a refresh cycle.
    let now = now_plus(e, 10);
    let mut first = next_header(e, now, 0);
    first.cycle_start = now;
    settle(e, e.operator, first, now);
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
    // Past the refresh window, the first batch must complete a refresh cycle.
    let now = now_plus(e, 10);
    let mut h = next_header(e, now, 0);
    h.cycle_start = now;
    settle(e, e.bob, h, now);
}

#[test(should_fail_with = "not operator")]
unconstrained fn new_operator_cannot_settle_early() {
    let e = setup();
    let _ = e.env.call_public(e.operator, L3XBridge::at(e.bridge).schedule_operator(e.bob));
    let now = now_plus(e, UPGRADE_DELAY - 60);
    settle(e, e.bob, next_header(e, now, 0), now);
}
