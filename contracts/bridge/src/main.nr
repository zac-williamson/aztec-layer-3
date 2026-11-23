mod test;

use aztec::macros::aztec;

/// L3X settlement contract (SPEC.md §10, §12):
/// - registration with constrained delivery of the account's encryption key to the operator;
/// - C1 custody over the D7 confidential token (§10.3–10.5): a deposit moves into a credit the
///   Bridge holds, with its opening delivered to the operator; the operator's custody transactions
///   sweep deposits into the vault (the Bridge's public balance) and pay settled withdrawals as new
///   credits, so only each transaction's net is public; unswept deposits return to their refund
///   address after t_dep, and unpaid withdrawals are claimable from the vault after t_payout;
/// - settlement: state root, header binding, replay protection, priority deadlines, time bounds,
///   Mode R DA as one public log per batch, market data;
/// - delayed configuration: the operator, root VK hash and configuration hash change only
///   UPGRADE_DELAY after a change is scheduled, and the contract cannot change its own class;
/// - desert mode: once a priority request is overdue, anyone can freeze the exchange; unprocessed
///   deposits are refunded, settled withdrawals stay payable, and accounts exit from the frozen
///   accounts root at the frozen index prices with funding accrued to the freeze, pro rata if the
///   vault falls short.
/// The genesis state holds the protocol accounts (insurance and fee) with zero balances; the
/// contract computes it from their public parts, so no deployer can seed balances.
#[aztec]
pub contract L3XBridge {
    use aztec::{
        macros::{
            events::event, functions::{external, initializer, internal, only_self, view}, storage::storage,
        },
        messages::delivery::MessageDelivery,
        oracle::avm,
        protocol::{address::AztecAddress, traits::{Deserialize, Packable, Serialize, ToField}},
        state_vars::{DelayedPublicMutable, Map, PublicImmutable, PublicMutable},
    };
    use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
    use l3x_exchange::{
        account::{account_leaf, AccountPub, enc_commitment, from_plaintext},
        consts::{
            ACCOUNTS_HEIGHT, CLASS_USER, DS_ACCT_NODE, DS_RECEIPT_SIG, DS_WD_NODE, KIND_DEPOSIT,
            KIND_FORCED_CANCEL_ALL, KIND_FORCED_CLOSE, KIND_FORCED_WITHDRAW, KIND_REGISTER, KIND_REKEY, MAX_DEPOSIT,
            PLAINTEXT_LEN, PROTOCOL_ACCOUNTS, RECEIPT_DEPTH, WD_HEIGHT,
        },
        deposit_blind, deposit_commitment,
        sig::{assert_signed, Signature},
        request::payload_hash,
        state::{genesis_state_root, index_and_funding, MARKET_DATA_LEN, market_data_hash},
        trade::equity_at,
        tree::merkle_root,
        withdrawal_record,
    };
    use ctoken::{
        ConfidentialToken, Credit, credit_id, Output, SETTLE_INPUTS, SETTLE_OUTPUTS, TRANSFER_INPUTS,
    };
    use l3x_types::{
        BatchHeader, config_hash as config_hash_of, DA_MAX, da_hash_flat, hash::hash, HEADER_LEN,
        merge::{VK_TREE_LEAVES, vk_tree_root_of}, priority_entry, priority_next_head, receipt_leaf, receipt_node,
    };
    use std::embedded_curve_ops::EmbeddedCurveScalar;

    global T_LAG: u64 = 15 * 60;
    /// SPEC.md §12. Must exceed T_force + T_payout plus a margin, so users can exit before a change
    /// applies. No function can change it: schedule_delay_change is never called.
    global UPGRADE_DELAY: u64 = 21 * 24 * 60 * 60;
    /// Tag at fields[0] of the DA log ("l3x.da.v1"), so indexers can find settlement payloads.
    global DA_LOG_TAG: Field = 0x6c33782e64612e7631;
    /// Flows one custody transaction can carry: deposits it sweeps and records it pays.
    global CUSTODY_DEPOSITS: u32 = SETTLE_INPUTS;
    global CUSTODY_PAYOUTS: u32 = SETTLE_OUTPUTS;
    /// Pending-deposit states.
    global PENDING: u8 = 1;
    global SWEPT: u8 = 2;
    global RECLAIMED: u8 = 3;

    #[event]
    struct PriorityRequested {
        index: u64,
        entry: Field,
        kind: Field,
        a: Field,
        b: Field,
        c: Field,
        sender: AztecAddress,
        time: u64,
    }

    /// The batch's market data and DA payload are in a separate public log:
    /// [DA_LOG_TAG, batch_number, market_data..., payload...].
    #[event]
    struct BatchSettled {
        batch_number: u64,
        new_state_root: Field,
        new_accounts_root: Field,
        priority_end: u64,
        da_len: u32,
        withdrawals_count: u64,
    }

    /// Private event that delivers a new account's encryption key to the operator.
    #[event]
    struct KeyDelivered {
        enc_commitment: Field,
        k_enc: Field,
    }

    /// Private event that delivers a deposit's opening to the operator, who needs it to sweep and
    /// queue the deposit. The credit is credit_id(bridge, amount, deposit_blind(...)).
    #[event]
    struct DepositDelivered {
        account_index: Field,
        amount: u128,
        refund_to: AztecAddress,
        depositor: AztecAddress,
        salt: Field,
    }

    /// A deposit's credit is held by the Bridge, awaiting custody. The amount is hidden.
    #[event]
    struct DepositPending {
        credit: Field,
        account_index: Field,
        refund_to: AztecAddress,
        depositor: AztecAddress,
        time: u64,
    }

    #[event]
    struct DepositReclaimed {
        credit: Field,
    }

    /// Emitted once, at deployment: the protocol accounts' public parts, from which exit clients
    /// rebuild the genesis accounts tree (SPEC.md §12).
    #[event]
    struct ProtocolAccounts {
        owners: [AztecAddress; PROTOCOL_ACCOUNTS],
        master_auths: [Field; PROTOCOL_ACCOUNTS],
        enc_commitments: [Field; PROTOCOL_ACCOUNTS],
    }

    #[event]
    struct UpgradeScheduled {
        config_hash: Field,
        vk_tree_root: Field,
        params_hash: Field,
        vk_tree_leaves: [Field; VK_TREE_LEAVES],
        root_vk_hash: Field,
        effective_at: u64,
    }

    #[event]
    struct OperatorScheduled {
        operator: AztecAddress,
        effective_at: u64,
    }

    /// A record paid from the vault directly, after t_payout or in desert mode; the amount is public.
    #[event]
    struct WithdrawalPaid {
        batch: u64,
        index: u32,
        recipient: AztecAddress,
        amount: u128,
    }

    /// A queued deposit no batch processed, refunded from the vault in desert mode.
    #[event]
    struct DepositRefunded {
        index: u64,
        refund_to: AztecAddress,
        amount: u128,
    }

    #[event]
    struct DesertActivated {
        accounts_root: Field,
        market_data_hash: Field,
        claim_close: u64,
    }

    #[event]
    struct ReceiptChallenged {
        id: Field,
        challenger: AztecAddress,
        msg: Field,
        seq: u64,
        deadline: u64,
    }

    #[event]
    struct ChallengeResolved {
        id: Field,
        answered: bool,
        payout: u128,
    }

    #[event]
    struct ExitClaimed {
        account_index: u32,
        owner: AztecAddress,
        equity: u128,
    }

    /// The operator's receipt key and the accountability rules (SPEC.md §11): a challenge is
    /// accepted t_settle after the receipt was issued, the operator answers within t_resp, and an
    /// unanswered challenge pays the challenger `slash` from the bond.
    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct ReceiptConfig {
        pub domain: Field,
        pub pk_x: Field,
        pub pk_y: Field,
        pub t_settle: u64,
        pub t_resp: u64,
        pub slash: u128,
    }

    /// Custody rules (SPEC.md §10.3, §10.4): an unswept deposit is reclaimable t_dep after it was
    /// made; a settled record custody has not paid is claimable from the vault t_payout after its
    /// batch settled; deposits below min_deposit are refused, so dust cannot burden custody.
    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct CustodyConfig {
        pub t_dep: u64,
        pub t_payout: u64,
        pub min_deposit: u128,
    }

    /// A pending deposit's opening, as its depositor delivered it to the operator.
    #[derive(Deserialize, Eq, Serialize)]
    pub struct DepositOpening {
        pub account_index: Field,
        pub amount: u128,
        pub refund_to: AztecAddress,
        pub depositor: AztecAddress,
        pub salt: Field,
    }

    /// A settled withdrawal or refund record for custody to pay, its path in its batch's
    /// withdrawals tree, and the blind of the recipient's new credit.
    #[derive(Deserialize, Eq, Serialize)]
    pub struct Payout {
        pub batch: u64,
        pub index: u32,
        pub recipient: AztecAddress,
        pub amount: u64,
        pub salt: Field,
        pub path: [Field; WD_HEIGHT],
        pub blind: Field,
    }

    /// A deposit's credit as the Bridge tracks it: PENDING from the deposit until custody sweeps it
    /// (SWEPT) or it is reclaimed (RECLAIMED).
    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct PendingDeposit {
        state: u8,
        time: u64,
    }

    /// Fixed at deployment, including the public parts of the protocol accounts (insurance at
    /// index 0, fee at index 1), which exit clients need to rebuild the genesis accounts tree.
    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct Config {
        genesis_operator: AztecAddress,
        genesis_root_vk_hash: Field,
        genesis_config_hash: Field,
        token: AztecAddress,
        t_force: u64,
        t_claim: u64,
        t_refresh: u64,
        t_late: u64,
        request_fee: u128,
        deployed_at: u64,
        receipts: ReceiptConfig,
        custody: CustodyConfig,
        protocol_owners: [AztecAddress; PROTOCOL_ACCOUNTS],
        protocol_master_auths: [Field; PROTOCOL_ACCOUNTS],
        protocol_enc_commitments: [Field; PROTOCOL_ACCOUNTS],
    }

    /// The exchange tip, the priority cursor and count, and the L3 time at which the current
    /// refresh cycle began.
    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct Tip {
        state_root: Field,
        accounts_root: Field,
        batch_number: u64,
        last_time: u64,
        market_data_hash: Field,
        priority_cursor: u64,
        priority_count: u64,
        cycle_start: u64,
    }

    /// Priority queue slot n: the hash-chain head after n entries (zero for n = 0), entry n and its
    /// time.
    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct Slot {
        head: Field,
        entry: Field,
        time: u64,
    }

    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct Settled {
        withdrawals_root: Field,
        receipts_root: Field,
        time: u64,
    }

    /// Tokens the Bridge holds outside the vault: the operator's bond and open challenges' fees.
    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct Escrow {
        bond: u128,
        fees: u128,
    }

    /// A receipt challenge, keyed by the receipt's leaf. `done` once answered or slashed.
    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct Challenge {
        open: bool,
        done: bool,
        challenger: AztecAddress,
        deadline: u64,
        fee: u128,
        msg: Field,
        seq: u64,
    }

    /// Desert mode (SPEC.md §12): frozen values, the claim window, the total of claims registered
    /// in the window, the payout ratio payout_num / payout_den fixed at the first payout after the
    /// window closes, and what the window's claims are still owed at that ratio.
    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct Desert {
        active: bool,
        accounts_root: Field,
        market_data_hash: Field,
        claim_close: u64,
        total_claims: u128,
        payout_num: u128,
        payout_den: u128,
        window_owed: u128,
    }

    /// An account's exit claim. `late` claims were registered after the window; `protocol`
    /// claims belong to the insurance or fee account.
    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct Claim {
        registered: bool,
        paid: bool,
        late: bool,
        protocol: bool,
        equity: u128,
        owner: AztecAddress,
    }

    #[storage]
    struct Storage<Context> {
        config: PublicImmutable<Config, Context>,
        // Scheduled replacements of the genesis operator, root VK hash and configuration hash.
        // They read as zero until one takes effect: a DelayedPublicMutable cannot be initialized
        // without its delay.
        operator: DelayedPublicMutable<AztecAddress, UPGRADE_DELAY, Context>,
        root_vk_hash: DelayedPublicMutable<Field, UPGRADE_DELAY, Context>,
        config_hash: DelayedPublicMutable<Field, UPGRADE_DELAY, Context>,
        tip: PublicMutable<Tip, Context>,
        desert: PublicMutable<Desert, Context>,
        slots: Map<u64, PublicMutable<Slot, Context>, Context>,
        settled: Map<u64, PublicMutable<Settled, Context>, Context>,
        withdrawal_paid: Map<Field, PublicMutable<bool, Context>, Context>,
        refunded: Map<u64, PublicMutable<bool, Context>, Context>,
        claims: Map<u32, PublicMutable<Claim, Context>, Context>,
        escrow: PublicMutable<Escrow, Context>,
        challenges: Map<Field, PublicMutable<Challenge, Context>, Context>,
        deposits: Map<Field, PublicMutable<PendingDeposit, Context>, Context>,
    }

    #[external("public")]
    #[initializer]
    fn constructor(
        operator: AztecAddress,
        root_vk_hash: Field,
        config_hash: Field,
        token: AztecAddress,
        t_force: u64,
        t_claim: u64,
        t_refresh: u64,
        t_late: u64,
        request_fee: u128,
        receipts: ReceiptConfig,
        custody: CustodyConfig,
        protocol_owners: [AztecAddress; PROTOCOL_ACCOUNTS],
        protocol_master_auths: [Field; PROTOCOL_ACCOUNTS],
        protocol_enc_commitments: [Field; PROTOCOL_ACCOUNTS],
    ) {
        self.storage.config.initialize(
            Config {
                genesis_operator: operator,
                genesis_root_vk_hash: root_vk_hash,
                genesis_config_hash: config_hash,
                token,
                t_force,
                t_claim,
                t_refresh,
                t_late,
                request_fee,
                deployed_at: self.context.timestamp(),
                receipts,
                custody,
                protocol_owners,
                protocol_master_auths,
                protocol_enc_commitments,
            },
        );
        // The Bridge computes the genesis state itself, so no deployer can seed balances.
        let mut protocol = [AccountPub { owner: 0, master_auth: 0, enc_commitment: 0, class: 0 }; PROTOCOL_ACCOUNTS];
        for i in 0..PROTOCOL_ACCOUNTS {
            protocol[i] = AccountPub {
                owner: protocol_owners[i].to_field(),
                master_auth: protocol_master_auths[i],
                enc_commitment: protocol_enc_commitments[i],
                class: 0,
            };
        }
        self.emit(
            ProtocolAccounts {
                owners: protocol_owners,
                master_auths: protocol_master_auths,
                enc_commitments: protocol_enc_commitments,
            },
        );
        self.storage.tip.write(
            Tip {
                state_root: genesis_state_root(protocol),
                accounts_root: 0,
                batch_number: 0,
                last_time: 0,
                market_data_hash: 0,
                priority_cursor: 0,
                priority_count: 0,
                cycle_start: 0,
            },
        );
    }

    // ---- Priority requests (SPEC.md §7.3, §10.1) ----

    /// Registers an account owned by the caller. The encryption key never appears in public: it
    /// is checked against its commitment here and delivered to the operator by constrained
    /// on-chain delivery, so the operator can always process the request.
    #[external("private")]
    fn register(master_auth: Field, enc_key_commitment: Field, k_enc: Field) {
        assert(enc_commitment(k_enc) == enc_key_commitment, "k_enc does not open the commitment");
        let operator = self.storage.operator.get_current_value();
        let operator =
            if operator.is_zero() { self.storage.config.read().genesis_operator } else { operator };
        self.emit(KeyDelivered { enc_commitment: enc_key_commitment, k_enc }).deliver_to(
            operator,
            MessageDelivery::onchain_constrained(),
        );
        self.enqueue_self._queue(KIND_REGISTER, master_auth, enc_key_commitment, 0, self.msg_sender());
    }

    /// Queues a rekey (SPEC.md §7.3) on behalf of the caller, who must own the account for it to
    /// take effect: the account's master authorization and encryption key are replaced, every
    /// session key is revoked and every order cancelled. As at registration, the new encryption key
    /// is checked against its commitment here and delivered to the operator by constrained on-chain
    /// delivery. It pays `request_fee` to the operator, as a forced request does. This is how an owner
    /// recovers an account whose master key is lost or compromised.
    #[external("private")]
    fn rekey(account_index: Field, master_auth: Field, enc_key_commitment: Field, k_enc: Field) {
        assert(enc_commitment(k_enc) == enc_key_commitment, "k_enc does not open the commitment");
        let config = self.storage.config.read();
        let operator = self.storage.operator.get_current_value();
        let operator = if operator.is_zero() { config.genesis_operator } else { operator };
        self.emit(KeyDelivered { enc_commitment: enc_key_commitment, k_enc }).deliver_to(
            operator,
            MessageDelivery::onchain_constrained(),
        );
        let sender = self.msg_sender();
        if config.request_fee > 0 {
            self.enqueue(ConfidentialToken::at(config.token).transfer_public_from(sender, operator, config.request_fee));
        }
        self.enqueue_self._queue(KIND_REKEY, account_index, master_auth, enc_key_commitment, sender);
    }

    /// Queues a forced request (SPEC.md §7.3, §12) on behalf of the caller, who must own the account
    /// for it to take effect. It pays `request_fee` to the operator, so the queue cannot be flooded
    /// for free; like every priority request it must be processed within t_force.
    ///   ForcedWithdraw:  b = recipient
    ///   ForcedClose:     b = market, c = worst price
    ///   ForcedCancelAll: no fields
    #[external("public")]
    fn submit_forced(kind: Field, account_index: Field, b: Field, c: Field) {
        assert(
            (kind == KIND_FORCED_WITHDRAW) | (kind == KIND_FORCED_CLOSE) | (kind == KIND_FORCED_CANCEL_ALL),
            "not a forced request",
        );
        let sender = self.msg_sender();
        let config = self.storage.config.read();
        if config.request_fee > 0 {
            let operator = self.internal.current_operator();
            self.call(ConfidentialToken::at(config.token).transfer_public_from(sender, operator, config.request_fee));
        }
        self.internal.queue_entry(kind, account_index, b, c, sender);
    }

    // ---- Custody (SPEC.md §10.3, C1) ----

    /// Deposits `amount` into account `account_index`. The amount moves from the caller's credits
    /// into a credit the Bridge holds, under the caller's authorization of that token call; only the
    /// depositor and the operator learn it, the operator by constrained delivery of the opening.
    /// The credit's blind binds the account, `refund_to` and the depositor, so the opening fixes
    /// them. Custody later sweeps the credit into the vault and queues the deposit; until then,
    /// after t_dep or in desert mode, anyone holding the opening can return it to `refund_to`.
    #[external("private")]
    fn deposit(
        account_index: Field,
        amount: u128,
        refund_to: AztecAddress,
        salt: Field,
        credits: [Credit; TRANSFER_INPUTS],
        change_blind: Field,
        authwit_nonce: Field,
    ) {
        let config = self.storage.config.read();
        assert(
            (amount > 0) & (amount >= config.custody.min_deposit) & (amount < MAX_DEPOSIT as u128),
            "deposit amount out of range",
        );
        let depositor = self.msg_sender();
        let blind = deposit_blind(account_index, refund_to.to_field(), depositor.to_field(), salt);
        let credit = self.call(
            ConfidentialToken::at(config.token).transfer(
                depositor,
                self.address,
                amount,
                credits,
                blind,
                change_blind,
                authwit_nonce,
            ),
        );
        let operator = self.storage.operator.get_current_value();
        let operator = if operator.is_zero() { config.genesis_operator } else { operator };
        self.emit(DepositDelivered { account_index, amount, refund_to, depositor, salt }).deliver_to(
            operator,
            MessageDelivery::onchain_constrained(),
        );
        self.enqueue_self._record_deposit(credit, account_index, refund_to, depositor);
    }

    #[external("public")]
    #[only_self]
    fn _record_deposit(credit: Field, account_index: Field, refund_to: AztecAddress, depositor: AztecAddress) {
        assert(!self.storage.desert.read().active, "desert mode");
        let time = self.context.timestamp();
        self.storage.deposits.at(credit).write(PendingDeposit { state: PENDING, time });
        self.emit(DepositPending { credit, account_index, refund_to, depositor, time });
    }

    /// The operator's custody transaction. It sweeps up to CUSTODY_DEPOSITS pending deposits,
    /// queueing each with its amount committed, and pays up to CUSTODY_PAYOUTS settled records as
    /// new credits of their recipients, delivered by constrained delivery. One token settlement
    /// nets the flows against the vault, so only the net is public; the operator SHOULD include at
    /// least k_min flows [D2]. Each payout is checked here against its path; the public phase
    /// checks the path's root against its batch and pays each record once.
    #[external("private")]
    fn custody(
        deposits: [DepositOpening; CUSTODY_DEPOSITS],
        n_deposits: u32,
        payouts: [Payout; CUSTODY_PAYOUTS],
        n_payouts: u32,
    ) {
        let config = self.storage.config.read();
        let operator = self.storage.operator.get_current_value();
        let operator = if operator.is_zero() { config.genesis_operator } else { operator };
        assert(self.msg_sender() == operator, "not operator");
        assert((n_deposits <= CUSTODY_DEPOSITS) & (n_payouts <= CUSTODY_PAYOUTS), "too many flows");

        let mut credits = [Credit::empty(); SETTLE_INPUTS];
        let mut ids = [0; CUSTODY_DEPOSITS];
        let mut accounts = [0; CUSTODY_DEPOSITS];
        let mut commitments = [0; CUSTODY_DEPOSITS];
        let mut refund_tos = [AztecAddress::zero(); CUSTODY_DEPOSITS];
        let mut depositors = [AztecAddress::zero(); CUSTODY_DEPOSITS];
        let mut swept: u128 = 0;
        for i in 0..CUSTODY_DEPOSITS {
            if i < n_deposits {
                let d = deposits[i];
                let blind = deposit_blind(d.account_index, d.refund_to.to_field(), d.depositor.to_field(), d.salt);
                credits[i] = Credit { amount: d.amount, blind };
                ids[i] = credit_id(self.address, d.amount, blind);
                accounts[i] = d.account_index;
                commitments[i] = deposit_commitment(d.amount as Field, d.salt);
                refund_tos[i] = d.refund_to;
                depositors[i] = d.depositor;
                swept += d.amount;
            }
        }

        let mut outputs = [Output::empty(); SETTLE_OUTPUTS];
        let mut records = [0; CUSTODY_PAYOUTS];
        let mut batches = [0; CUSTODY_PAYOUTS];
        let mut roots = [0; CUSTODY_PAYOUTS];
        let mut paid: u128 = 0;
        for j in 0..CUSTODY_PAYOUTS {
            if j < n_payouts {
                let p = payouts[j];
                assert(p.amount > 0, "empty payout");
                records[j] = withdrawal_record(p.recipient.to_field(), p.amount, p.salt, p.batch, p.index);
                batches[j] = p.batch;
                roots[j] = merkle_root(DS_WD_NODE, records[j], p.index, p.path);
                outputs[j] = Output { to: p.recipient, amount: p.amount as u128, blind: p.blind };
                paid += p.amount as u128;
            }
        }

        let net_in = if swept > paid { swept - paid } else { 0 };
        let net_out = if paid > swept { paid - swept } else { 0 };
        let _ = self.call(ConfidentialToken::at(config.token).settle(credits, outputs, net_out, net_in));
        self.enqueue_self._custody(
            ids,
            accounts,
            commitments,
            refund_tos,
            depositors,
            n_deposits,
            records,
            batches,
            roots,
            n_payouts,
        );
    }

    #[external("public")]
    #[only_self]
    fn _custody(
        ids: [Field; CUSTODY_DEPOSITS],
        accounts: [Field; CUSTODY_DEPOSITS],
        commitments: [Field; CUSTODY_DEPOSITS],
        refund_tos: [AztecAddress; CUSTODY_DEPOSITS],
        depositors: [AztecAddress; CUSTODY_DEPOSITS],
        n_deposits: u32,
        records: [Field; CUSTODY_PAYOUTS],
        batches: [u64; CUSTODY_PAYOUTS],
        roots: [Field; CUSTODY_PAYOUTS],
        n_payouts: u32,
    ) {
        assert(!self.storage.desert.read().active, "desert mode");
        for i in 0..CUSTODY_DEPOSITS {
            if i < n_deposits {
                let slot = self.storage.deposits.at(ids[i]);
                let mut d = slot.read();
                assert(d.state == PENDING, "deposit not pending");
                d.state = SWEPT;
                slot.write(d);
                // The queue holds only funded deposits, with their amounts committed.
                self.internal.queue_entry(KIND_DEPOSIT, accounts[i], commitments[i], refund_tos[i].to_field(), depositors[i]);
            }
        }
        for j in 0..CUSTODY_PAYOUTS {
            if j < n_payouts {
                assert(
                    roots[j] == self.storage.settled.at(batches[j]).read().withdrawals_root,
                    "record not in the batch's withdrawals tree",
                );
                assert(!self.storage.withdrawal_paid.at(records[j]).read(), "already paid");
                self.storage.withdrawal_paid.at(records[j]).write(true);
            }
        }
        // A net outflow comes from the vault, never from the bond or open challenges' fees. The
        // net itself is public in the token's PublicTransfer event.
        let token = self.storage.config.read().token;
        let e = self.storage.escrow.read();
        assert(self.view(ConfidentialToken::at(token).balance_of_public(self.address)) >= e.bond + e.fees, "vault short");
    }

    /// Returns a deposit custody has not swept to its refund address, as a new credit delivered by
    /// constrained delivery: after t_dep, or at any time in desert mode. Anyone holding the opening
    /// may call it; the funds go only to `refund_to`. A concurrent sweep and reclaim are resolved by
    /// the credit's spent nullifier: whichever lands first wins.
    #[external("private")]
    fn reclaim_deposit(deposit: DepositOpening, blind: Field) {
        let token = self.storage.config.read().token;
        let dblind = deposit_blind(
            deposit.account_index,
            deposit.refund_to.to_field(),
            deposit.depositor.to_field(),
            deposit.salt,
        );
        let mut credits = [Credit::empty(); SETTLE_INPUTS];
        credits[0] = Credit { amount: deposit.amount, blind: dblind };
        let mut outputs = [Output::empty(); SETTLE_OUTPUTS];
        outputs[0] = Output { to: deposit.refund_to, amount: deposit.amount, blind };
        let _ = self.call(ConfidentialToken::at(token).settle(credits, outputs, 0, 0));
        self.enqueue_self._reclaim(credit_id(self.address, deposit.amount, dblind));
    }

    #[external("public")]
    #[only_self]
    fn _reclaim(credit: Field) {
        let slot = self.storage.deposits.at(credit);
        let mut d = slot.read();
        assert(d.state == PENDING, "deposit not pending");
        let t_dep = self.storage.config.read().custody.t_dep;
        assert(
            self.storage.desert.read().active | (self.context.timestamp() >= d.time + t_dep),
            "deposit not yet reclaimable",
        );
        d.state = RECLAIMED;
        slot.write(d);
        self.emit(DepositReclaimed { credit });
    }

    #[external("public")]
    #[only_self]
    fn _queue(kind: Field, a: Field, b: Field, c: Field, sender: AztecAddress) {
        self.internal.queue_entry(kind, a, b, c, sender);
    }

    #[internal("public")]
    fn queue_entry(kind: Field, a: Field, b: Field, c: Field, sender: AztecAddress) {
        assert(!self.storage.desert.read().active, "desert mode");
        let mut tip = self.storage.tip.read();
        let index = tip.priority_count;
        let time = self.context.timestamp();
        let entry = priority_entry(payload_hash(kind, a, b, c), sender.to_field(), time);
        let mut slot = self.storage.slots.at(index).read();
        slot.entry = entry;
        slot.time = time;
        self.storage.slots.at(index).write(slot);
        let mut next = self.storage.slots.at(index + 1).read();
        next.head = priority_next_head(slot.head, entry);
        self.storage.slots.at(index + 1).write(next);
        tip.priority_count = index + 1;
        self.storage.tip.write(tip);
        self.emit(PriorityRequested { index, entry, kind, a, b, c, sender, time });
    }

    // ---- Settlement (SPEC.md §10.1–10.2) ----

    /// Verifies a root proof over H(header) in the private phase, then applies the header's state
    /// transition in the public phase. The DA hash and market data are checked here: the enqueued
    /// call's calldata is bound to these arguments, so _apply receives exactly what was checked.
    #[external("private")]
    fn settle(
        header: [Field; HEADER_LEN],
        proof: UltraHonkZKProof,
        vk: UltraHonkVerificationKey,
        da_payload: [Field; DA_MAX],
        da_len: u32,
        market_data: [Field; MARKET_DATA_LEN],
    ) {
        let genesis = self.storage.config.read();
        let operator = self.storage.operator.get_current_value();
        let operator = if operator.is_zero() { genesis.genesis_operator } else { operator };
        assert(self.msg_sender() == operator, "not operator");

        // Reading a DelayedPublicMutable caps this transaction's expiration before any scheduled
        // change, so the values checked here are still current when the transaction lands.
        let config = self.storage.config_hash.get_current_value();
        let config = if config == 0 { genesis.genesis_config_hash } else { config };
        let root_vk = self.storage.root_vk_hash.get_current_value();
        let root_vk = if root_vk == 0 { genesis.genesis_root_vk_hash } else { root_vk };

        let h = BatchHeader::from_fields(header);
        assert(h.config_hash == config, "config mismatch");
        assert(da_hash_flat(da_payload, da_len) == h.da_hash, "da hash");
        assert(market_data_hash(market_data) == h.market_data_hash, "market data");
        verify_honk_proof(vk, proof, [h.hash()], root_vk);
        self.enqueue_self._apply(header, da_payload, da_len, market_data);
    }

    #[external("public")]
    #[only_self]
    fn _apply(
        header: [Field; HEADER_LEN],
        da_payload: [Field; DA_MAX],
        da_len: u32,
        market_data: [Field; MARKET_DATA_LEN],
    ) {
        let h = BatchHeader::from_fields(header);
        let now = self.context.timestamp();
        assert(!self.storage.desert.read().active, "desert mode");
        let mut tip = self.storage.tip.read();

        // 1. Chain continuity and replay protection.
        assert(h.prev_state_root == tip.state_root, "stale state root");
        let batch_number = tip.batch_number + 1;
        assert(h.batch_number == batch_number, "batch number");

        // 2. The consumed priority range starts at the cursor and its fold matches stored heads.
        assert(h.priority_start == tip.priority_cursor, "priority start");
        assert(h.priority_end <= tip.priority_count, "priority end");
        assert(self.storage.slots.at(h.priority_start).read().head == h.priority_head_start, "priority head start");
        let end_slot = self.storage.slots.at(h.priority_end).read();
        assert(end_slot.head == h.priority_head_end, "priority head end");

        // 3. No request older than T_force may be left behind.
        if h.priority_end < tip.priority_count {
            assert(end_slot.time + self.storage.config.read().t_force >= now, "priority request overdue");
        }

        // 4. L3 time is monotone and within T_lag of Aztec time.
        assert(tip.last_time <= h.min_time, "time regressed");
        assert(h.min_time <= h.max_time, "time order");
        assert(h.max_time <= now, "batch time in the future");
        assert(h.max_time + T_LAG >= now, "batch time lags Aztec time");

        // 5. Refresh (SPEC.md §9.5): every batch ends within t_refresh of the current refresh
        // cycle's start, the L3 time the refresh cursor last wrapped (the deployment, before the
        // first wrap). An operator who falls behind must complete a cycle in its next batch.
        assert(h.cycle_start >= tip.cycle_start, "refresh cycle regressed");
        assert(h.cycle_start <= h.max_time, "refresh cycle starts after its batch");
        let config = self.storage.config.read();
        let cycle_start = if h.cycle_start > config.deployed_at { h.cycle_start } else { config.deployed_at };
        assert(h.max_time <= cycle_start + config.t_refresh, "refresh overdue");
        tip.cycle_start = h.cycle_start;

        tip.state_root = h.new_state_root;
        tip.accounts_root = h.new_accounts_root;
        tip.batch_number = batch_number;
        tip.last_time = h.max_time;
        tip.priority_cursor = h.priority_end;
        tip.market_data_hash = h.market_data_hash;
        self.storage.tip.write(tip);
        self.storage.settled.at(batch_number).write(
            Settled { withdrawals_root: h.withdrawals_root, receipts_root: h.receipts_root, time: now },
        );

        // 6. Mode R DA (SPEC.md §9.5) and market data (§8.4), in one public log:
        // [DA_LOG_TAG, batch_number, market_data, payload[0..da_len]].
        let mut log = [DA_LOG_TAG, batch_number as Field].as_vector();
        for i in 0..MARKET_DATA_LEN {
            log = log.push_back(market_data[i]);
        }
        for i in 0..da_len {
            log = log.push_back(da_payload[i]);
        }
        // Safety: the AVM constrains EMITPUBLICLOG; the payload is bound to the proof via da_hash.
        unsafe { avm::emit_public_log(log) };
        self.emit(
            BatchSettled {
                batch_number,
                new_state_root: h.new_state_root,
                new_accounts_root: h.new_accounts_root,
                priority_end: h.priority_end,
                da_len,
                withdrawals_count: h.withdrawals_count,
            },
        );
    }

    // ---- Withdrawals (SPEC.md §10.4) ----

    /// Pays a settled withdrawal or refund record that custody has not paid t_payout after its
    /// batch settled, from the vault into the recipient's public balance; the amount becomes
    /// public. Anyone may call it, once per record. In desert mode it needs no wait, and is senior
    /// to exit claims only until the payout ratio is fixed (SPEC.md §12). The record's path is
    /// folded here, in the private phase, which keeps the hashing out of the published public
    /// bytecode; the public phase compares the root with the batch's.
    #[external("private")]
    fn claim_withdrawal(
        batch: u64,
        index: u32,
        recipient: AztecAddress,
        amount: u64,
        salt: Field,
        path: [Field; WD_HEIGHT],
    ) {
        let record = withdrawal_record(recipient.to_field(), amount, salt, batch, index);
        let root = merkle_root(DS_WD_NODE, record, index, path);
        self.enqueue_self._claim_withdrawal(batch, index, record, root, recipient, amount);
    }

    #[external("public")]
    #[only_self]
    fn _claim_withdrawal(batch: u64, index: u32, record: Field, root: Field, recipient: AztecAddress, amount: u64) {
        let settled = self.storage.settled.at(batch).read();
        assert(root == settled.withdrawals_root, "record not in the batch's withdrawals tree");
        assert(!self.storage.withdrawal_paid.at(record).read(), "already paid");
        let config = self.storage.config.read();
        assert(
            self.storage.desert.read().active | (self.context.timestamp() > settled.time + config.custody.t_payout),
            "payout window still open",
        );
        self.storage.withdrawal_paid.at(record).write(true);
        let pay = self.internal.senior_payment(amount as u128);
        self.call(ConfidentialToken::at(config.token).transfer_public(recipient, pay));
        self.emit(WithdrawalPaid { batch, index, recipient, amount: pay });
    }

    /// What a senior obligation (a settled record, or the refund of a queued deposit) is paid.
    /// Outside desert mode, in full: custody moves every deposit in and every payout out, so the
    /// vault covers every record (SPEC.md §8.8). In desert mode, in full until the payout ratio is
    /// fixed, and afterwards from what the window's claims are not owed.
    #[internal("public")]
    fn senior_payment(amount: u128) -> u128 {
        let vault = self.internal.vault_balance();
        let d = self.storage.desert.read();
        if !d.active {
            assert(amount <= vault, "vault short");
            amount
        } else {
            let available = if d.payout_den == 0 {
                vault
            } else if vault > d.window_owed {
                vault - d.window_owed
            } else {
                0
            };
            if amount < available { amount } else { available }
        }
    }

    // ---- Desert mode (SPEC.md §12) ----

    /// Anyone may freeze the exchange once the oldest pending priority request is older than
    /// t_force. Settlement and new requests stop for good.
    #[external("public")]
    fn activate_desert() {
        let mut d = self.storage.desert.read();
        assert(!d.active, "desert mode already active");
        let tip = self.storage.tip.read();
        assert(tip.priority_cursor < tip.priority_count, "no pending priority request");
        let config = self.storage.config.read();
        let now = self.context.timestamp();
        let pending = self.storage.slots.at(tip.priority_cursor).read();
        assert(pending.time + config.t_force < now, "no priority request is overdue");
        d.active = true;
        d.accounts_root = tip.accounts_root;
        d.market_data_hash = tip.market_data_hash;
        d.claim_close = now + config.t_claim;
        self.storage.desert.write(d);
        self.emit(
            DesertActivated {
                accounts_root: d.accounts_root,
                market_data_hash: d.market_data_hash,
                claim_close: d.claim_close,
            },
        );
    }

    /// Refunds a deposit custody queued but no batch processed, to its refund address, from the
    /// vault; the opening makes the amount public. A senior obligation (see senior_payment). The
    /// entry is rebuilt here, in the private phase, from the opening and the time the queue gave
    /// it; the public phase compares it with the stored entry.
    #[external("private")]
    fn desert_refund(
        index: u64,
        account_index: Field,
        amount: u128,
        salt: Field,
        refund_to: AztecAddress,
        depositor: AztecAddress,
        time: u64,
    ) {
        let entry = priority_entry(
            payload_hash(KIND_DEPOSIT, account_index, deposit_commitment(amount as Field, salt), refund_to.to_field()),
            depositor.to_field(),
            time,
        );
        self.enqueue_self._desert_refund(index, entry, amount, refund_to);
    }

    #[external("public")]
    #[only_self]
    fn _desert_refund(index: u64, entry: Field, amount: u128, refund_to: AztecAddress) {
        assert(self.storage.desert.read().active, "not in desert mode");
        assert(index >= self.storage.tip.read().priority_cursor, "request was processed");
        assert(entry == self.storage.slots.at(index).read().entry, "not this deposit");
        assert(!self.storage.refunded.at(index).read(), "already refunded");
        self.storage.refunded.at(index).write(true);
        let pay = self.internal.senior_payment(amount);
        self.call(ConfidentialToken::at(self.storage.config.read().token).transfer_public(refund_to, pay));
        self.emit(DepositRefunded { index, refund_to, amount: pay });
    }

    /// Registers an account's exit claim from its leaf in the frozen accounts root (SPEC.md §12).
    /// Positions are valued at the frozen index prices, with funding accrued to the frozen
    /// cumulative indices; negative equity counts as zero. The claim pays only the leaf's owner.
    /// The opening comes from the account's DA entries (SPEC.md §9.5) and the market data from the
    /// last BatchSettled event. A user claim registered within the window shares the vault pro
    /// rata; a later one, and any protocol account's, is paid from the residual.
    ///
    /// The leaf's root and the claim's value are computed here, in the private phase, which keeps
    /// the arithmetic out of the published public bytecode; the public phase checks them against the
    /// frozen accounts root and market data.
    #[external("private")]
    fn exit_register(
        account_index: u32,
        owner: AztecAddress,
        master_auth: Field,
        enc_key_commitment: Field,
        class: Field,
        plaintext: [Field; PLAINTEXT_LEN],
        path: [Field; ACCOUNTS_HEIGHT],
        market_data: [Field; MARKET_DATA_LEN],
    ) {
        let pubv = AccountPub { owner: owner.to_field(), master_auth, enc_commitment: enc_key_commitment, class };
        let privv = from_plaintext(plaintext);
        let root = merkle_root(DS_ACCT_NODE, account_leaf(pubv, privv), account_index, path);
        let (prices, cums) = index_and_funding(market_data);
        let equity = equity_at(privv, prices, cums);
        let value: u128 = if equity > 0 { (equity as u64) as u128 } else { 0 };
        self.enqueue_self._register_claim(account_index, owner, class != CLASS_USER, value, root, market_data_hash(market_data));
    }

    #[external("public")]
    #[only_self]
    fn _register_claim(account_index: u32, owner: AztecAddress, protocol: bool, value: u128, root: Field, market_data: Field) {
        let mut d = self.storage.desert.read();
        assert(d.active, "not in desert mode");
        assert(market_data == d.market_data_hash, "market data");
        assert(root == d.accounts_root, "not in the frozen accounts tree");
        assert(!self.storage.claims.at(account_index).read().registered, "already claimed");
        let late = self.context.timestamp() > d.claim_close;
        self.storage.claims.at(account_index).write(
            Claim { registered: true, paid: false, late, protocol, equity: value, owner },
        );
        if !late & !protocol {
            d.total_claims += value;
            self.storage.desert.write(d);
        }
        self.emit(ExitClaimed { account_index, owner, equity: value });
    }

    /// After the claim window, pays a registered claim to its owner (SPEC.md §12).
    /// - A window claim gets min(1, V/U) of its equity, where V is the vault when the ratio is
    ///   fixed, at the first payout, and U the window's total claims. Senior obligations (unpaid
    ///   records, queued deposits) claimed before then were already paid from the vault; their
    ///   amounts are hidden until claimed, so they cannot be reserved.
    /// - A late claim gets the same ratio at best, paid from the residual: the vault less what the
    ///   window's claims are still owed.
    /// - A protocol account's claim is paid the same way, and only t_late after the window, so
    ///   triggering desert mode cannot profit the operator.
    #[external("public")]
    fn exit_withdraw(account_index: u32) {
        let mut d = self.storage.desert.read();
        assert(d.active, "not in desert mode");
        let now = self.context.timestamp();
        assert(now > d.claim_close, "claim window still open");
        let mut claim = self.storage.claims.at(account_index).read();
        assert(claim.registered, "no claim");
        assert(!claim.paid, "already paid");
        let config = self.storage.config.read();
        if claim.protocol {
            assert(now > d.claim_close + config.t_late, "protocol accounts are paid after t_late");
        }
        let token = config.token;
        let vault = self.internal.vault_balance();
        if d.payout_den == 0 {
            // ratio = min(1, V/U), and 1 when no claim was registered in the window.
            if d.total_claims == 0 {
                d.payout_num = 1;
                d.payout_den = 1;
            } else {
                d.payout_num = if vault < d.total_claims { vault } else { d.total_claims };
                d.payout_den = d.total_claims;
            }
            d.window_owed = d.total_claims * d.payout_num / d.payout_den;
        }
        let pay = claim.equity * d.payout_num / d.payout_den;
        let amount = if !claim.late & !claim.protocol {
            d.window_owed = if d.window_owed > pay { d.window_owed - pay } else { 0 };
            pay
        } else {
            let residual = if vault > d.window_owed { vault - d.window_owed } else { 0 };
            if pay < residual { pay } else { residual }
        };
        self.storage.desert.write(d);
        claim.paid = true;
        self.storage.claims.at(account_index).write(claim);
        self.call(ConfidentialToken::at(token).transfer_public(claim.owner, amount));
    }

    // ---- Receipts and accountability (SPEC.md §11) ----

    /// Adds to the operator's bond, which unanswered receipt challenges are paid from.
    #[external("public")]
    fn post_bond(amount: u128) {
        let token = self.storage.config.read().token;
        self.call(ConfidentialToken::at(token).transfer_public_from(self.msg_sender(), self.address, amount));
        let mut e = self.storage.escrow.read();
        e.bond += amount;
        self.storage.escrow.write(e);
    }

    /// Challenges a receipt the operator signed for an action (SPEC.md §11): the operator must
    /// show the action's leaf in a settled batch's receipts root within t_resp. The receipt's
    /// signature is checked here, in the private phase, which keeps the curve arithmetic out of
    /// the published public bytecode; the public phase requires the receipt to be at least
    /// t_settle old, so the operator had time to settle it, and takes `request_fee` from the
    /// challenger, returned if the operator fails to answer.
    #[external("private")]
    fn challenge(msg: Field, seq: u64, issued_at: u64, sig_s: EmbeddedCurveScalar, sig_e: EmbeddedCurveScalar) {
        let rc = self.storage.config.read().receipts;
        let receipt = hash([DS_RECEIPT_SIG, rc.domain, msg, seq as Field, issued_at as Field]);
        assert_signed(rc.pk_x, rc.pk_y, Signature { s: sig_s, e: sig_e }, receipt);
        self.enqueue_self._open_challenge(msg, seq, issued_at, self.msg_sender());
    }

    #[external("public")]
    #[only_self]
    fn _open_challenge(msg: Field, seq: u64, issued_at: u64, challenger: AztecAddress) {
        let config = self.storage.config.read();
        let now = self.context.timestamp();
        assert(issued_at + config.receipts.t_settle <= now, "receipt too recent to challenge");
        let id = receipt_leaf(seq, msg);
        let existing = self.storage.challenges.at(id).read();
        assert(!existing.open & !existing.done, "receipt already challenged");
        if config.request_fee > 0 {
            self.call(ConfidentialToken::at(config.token).transfer_public_from(challenger, self.address, config.request_fee));
        }
        let mut e = self.storage.escrow.read();
        e.fees += config.request_fee;
        self.storage.escrow.write(e);
        let deadline = now + config.receipts.t_resp;
        self.storage.challenges.at(id).write(
            Challenge { open: true, done: false, challenger, deadline, fee: config.request_fee, msg, seq },
        );
        self.emit(ReceiptChallenged { id, challenger, msg, seq, deadline });
    }

    /// Answers a challenge with the path of the receipt's leaf in a settled batch's receipts
    /// root; `bits` gives, level by level from the leaf, whether the node is the right child. The
    /// path is folded here, in the private phase; the public phase compares the result with the
    /// batch's receipts root and pays the challenge fee to the operator.
    #[external("private")]
    fn answer(msg: Field, seq: u64, batch: u64, depth: u32, bits: u32, path: [Field; RECEIPT_DEPTH]) {
        assert(depth <= RECEIPT_DEPTH, "path too long");
        let id = receipt_leaf(seq, msg);
        let mut node = id;
        for i in 0..RECEIPT_DEPTH {
            if i < depth {
                node = if ((bits >> i) & 1) == 1 { receipt_node(path[i], node) } else { receipt_node(node, path[i]) };
            }
        }
        self.enqueue_self._resolve_challenge(id, batch, node);
    }

    #[external("public")]
    #[only_self]
    fn _resolve_challenge(id: Field, batch: u64, root: Field) {
        let mut c = self.storage.challenges.at(id).read();
        assert(c.open, "no open challenge");
        assert(root == self.storage.settled.at(batch).read().receipts_root, "receipt not in the batch");
        c.open = false;
        c.done = true;
        self.storage.challenges.at(id).write(c);
        let mut e = self.storage.escrow.read();
        e.fees -= c.fee;
        self.storage.escrow.write(e);
        if c.fee > 0 {
            let config = self.storage.config.read();
            self.call(ConfidentialToken::at(config.token).transfer_public(self.internal.current_operator(), c.fee));
        }
        self.emit(ChallengeResolved { id, answered: true, payout: c.fee });
    }

    /// Settles a challenge the operator did not answer in time: the challenger gets its fee back
    /// and `slash` from the bond, as far as the bond goes.
    #[external("public")]
    fn slash(id: Field) {
        let mut c = self.storage.challenges.at(id).read();
        assert(c.open, "no open challenge");
        assert(self.context.timestamp() > c.deadline, "challenge still open");
        let config = self.storage.config.read();
        let mut e = self.storage.escrow.read();
        let penalty = if e.bond < config.receipts.slash { e.bond } else { config.receipts.slash };
        e.bond -= penalty;
        e.fees -= c.fee;
        self.storage.escrow.write(e);
        c.open = false;
        c.done = true;
        self.storage.challenges.at(id).write(c);
        self.call(ConfidentialToken::at(config.token).transfer_public(c.challenger, penalty + c.fee));
        self.emit(ChallengeResolved { id, answered: false, payout: penalty + c.fee });
    }

    /// The vault: the Bridge's token balance less the bond and open challenges' fees.
    #[internal("public")]
    fn vault_balance() -> u128 {
        let token = self.storage.config.read().token;
        let balance = self.view(ConfidentialToken::at(token).balance_of_public(self.address));
        let e = self.storage.escrow.read();
        let held = e.bond + e.fees;
        if balance > held { balance - held } else { 0 }
    }

    // ---- Configuration (SPEC.md §12) ----

    /// Schedules a new configuration and root VK together. The preimage, including every VK tree
    /// leaf, is checked here and published. Takes effect after UPGRADE_DELAY; scheduling again
    /// before then replaces the pending change.
    #[external("public")]
    fn schedule_upgrade(
        vk_tree_leaves: [Field; VK_TREE_LEAVES],
        params_hash: Field,
        root_vk_hash: Field,
    ) {
        assert(self.msg_sender() == self.internal.current_operator(), "not operator");
        assert(root_vk_hash != 0, "zero root VK hash");
        let vk_tree_root = vk_tree_root_of(vk_tree_leaves);
        let config_hash = config_hash_of(vk_tree_root, params_hash);
        self.storage.config_hash.schedule_value_change(config_hash);
        self.storage.root_vk_hash.schedule_value_change(root_vk_hash);
        let effective_at = self.context.timestamp() + UPGRADE_DELAY;
        self.emit(
            UpgradeScheduled {
                config_hash,
                vk_tree_root,
                params_hash,
                vk_tree_leaves,
                root_vk_hash,
                effective_at,
            },
        );
    }

    #[external("public")]
    fn schedule_operator(operator: AztecAddress) {
        assert(self.msg_sender() == self.internal.current_operator(), "not operator");
        assert(!operator.is_zero(), "zero operator");
        self.storage.operator.schedule_value_change(operator);
        self.emit(OperatorScheduled { operator, effective_at: self.context.timestamp() + UPGRADE_DELAY });
    }

    // ---- Views ----

    /// (state root, accounts root, batch number, last time, priority cursor, priority count).
    #[external("public")]
    #[view]
    fn get_tip() -> (Field, Field, u64, u64, u64, u64) {
        let t = self.storage.tip.read();
        (t.state_root, t.accounts_root, t.batch_number, t.last_time, t.priority_cursor, t.priority_count)
    }

    /// (head after `index` entries, entry `index`, its time).
    #[external("public")]
    #[view]
    fn get_priority(index: u64) -> (Field, Field, u64) {
        let s = self.storage.slots.at(index).read();
        (s.head, s.entry, s.time)
    }

    /// The configuration in force now: (operator, root VK hash, configuration hash).
    #[external("public")]
    #[view]
    fn get_config() -> (AztecAddress, Field, Field) {
        let genesis = self.storage.config.read();
        let root_vk = self.storage.root_vk_hash.get_current_value();
        let config = self.storage.config_hash.get_current_value();
        (
            self.internal.current_operator(),
            if root_vk == 0 { genesis.genesis_root_vk_hash } else { root_vk },
            if config == 0 { genesis.genesis_config_hash } else { config },
        )
    }

    /// (L3 time the current refresh cycle began, deployment time).
    #[external("public")]
    #[view]
    fn get_refresh() -> (u64, u64) {
        (self.storage.tip.read().cycle_start, self.storage.config.read().deployed_at)
    }

    /// (active, frozen accounts root, frozen market data hash, claim close, total claims).
    #[external("public")]
    #[view]
    fn get_desert() -> (bool, Field, Field, u64, u128) {
        let d = self.storage.desert.read();
        (d.active, d.accounts_root, d.market_data_hash, d.claim_close, d.total_claims)
    }

    /// The protocol accounts' public parts: (owners, master authorizations, encryption-key
    /// commitments), insurance first.
    #[external("public")]
    #[view]
    fn get_protocol_accounts() -> ([AztecAddress; PROTOCOL_ACCOUNTS], [Field; PROTOCOL_ACCOUNTS], [Field; PROTOCOL_ACCOUNTS]) {
        let c = self.storage.config.read();
        (c.protocol_owners, c.protocol_master_auths, c.protocol_enc_commitments)
    }

    /// (open, done, deadline) of the challenge for a receipt leaf, and the bond.
    #[external("public")]
    #[view]
    fn get_challenge(id: Field) -> (bool, bool, u64, u128) {
        let c = self.storage.challenges.at(id).read();
        (c.open, c.done, c.deadline, self.storage.escrow.read().bond)
    }

    /// (state, time) of a deposit's credit: 0 unknown, 1 pending, 2 swept, 3 reclaimed.
    #[external("public")]
    #[view]
    fn get_deposit(credit: Field) -> (u8, u64) {
        let d = self.storage.deposits.at(credit).read();
        (d.state, d.time)
    }

    #[internal("public")]
    fn current_operator() -> AztecAddress {
        let operator = self.storage.operator.get_current_value();
        if operator.is_zero() { self.storage.config.read().genesis_operator } else { operator }
    }
}
