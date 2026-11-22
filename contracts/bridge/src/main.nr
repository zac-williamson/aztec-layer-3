mod test;

use aztec::macros::aztec;

/// L3X settlement contract, the subset of SPEC.md §10 and §12 built so far (P1, and P2.1):
/// - registration with constrained delivery of the account's encryption key to the operator;
/// - C0 custody: deposits move into the Bridge's public token balance (the vault) and queue a
///   priority request; withdrawals are paid from the vault on proof of inclusion;
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
            ACCOUNTS_HEIGHT, CLASS_USER, DS_ACCT_NODE, DS_WD_NODE, KIND_DEPOSIT, KIND_FORCED_CANCEL_ALL,
            KIND_FORCED_CLOSE, KIND_FORCED_WITHDRAW, KIND_REGISTER, MAX_DEPOSIT, PLAINTEXT_LEN, PROTOCOL_ACCOUNTS,
            WD_HEIGHT,
        },
        request::payload_hash,
        state::{genesis_state_root, index_and_funding, MARKET_DATA_LEN, market_data_hash},
        trade::equity_at,
        tree::merkle_root,
        withdrawal_record,
    };
    use l3x_token::L3XToken;
    use l3x_types::{
        BatchHeader, config_hash as config_hash_of, DA_MAX, da_hash_flat, HEADER_LEN,
        merge::{VK_TREE_LEAVES, vk_tree_root_of}, priority_entry, priority_next_head,
    };

    global T_LAG: u64 = 15 * 60;
    /// SPEC.md §12. Must exceed T_force + T_payout plus a margin, so users can exit before a change
    /// applies. No function can change it: schedule_delay_change is never called.
    global UPGRADE_DELAY: u64 = 21 * 24 * 60 * 60;
    /// Tag at fields[0] of the DA log ("l3x.da.v1"), so indexers can find settlement payloads.
    global DA_LOG_TAG: Field = 0x6c33782e64612e7631;

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

    /// The batch's DA payload is in a separate public log: [DA_LOG_TAG, batch_number, payload...].
    #[event]
    struct BatchSettled {
        batch_number: u64,
        new_state_root: Field,
        new_accounts_root: Field,
        priority_end: u64,
        da_len: u32,
        withdrawals_count: u64,
        withdrawals_amount: u64,
        market_data: [Field; MARKET_DATA_LEN],
    }

    /// Private event that delivers a new account's encryption key to the operator.
    #[event]
    struct KeyDelivered {
        enc_commitment: Field,
        k_enc: Field,
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

    #[event]
    struct WithdrawalPaid {
        batch: u64,
        index: u32,
        recipient: AztecAddress,
        amount: u64,
    }

    #[event]
    struct DesertActivated {
        accounts_root: Field,
        market_data_hash: Field,
        claim_close: u64,
        refunds_owed: u128,
    }

    #[event]
    struct ExitClaimed {
        account_index: u32,
        owner: AztecAddress,
        equity: u128,
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
        protocol_owners: [AztecAddress; PROTOCOL_ACCOUNTS],
        protocol_master_auths: [Field; PROTOCOL_ACCOUNTS],
        protocol_enc_commitments: [Field; PROTOCOL_ACCOUNTS],
    }

    /// The exchange tip, the priority cursor and count, settled but unpaid withdrawals, and the L3
    /// time at which the current refresh cycle began.
    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct Tip {
        state_root: Field,
        accounts_root: Field,
        batch_number: u64,
        last_time: u64,
        market_data_hash: Field,
        priority_cursor: u64,
        priority_count: u64,
        withdrawals_owed: u128,
        cycle_start: u64,
    }

    /// Priority queue slot n: the hash-chain head after n entries (zero for n = 0), entry n and its
    /// time, and the total deposited by entries before n.
    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct Slot {
        head: Field,
        entry: Field,
        time: u64,
        deposit_prefix: u128,
    }

    #[derive(Deserialize, Eq, Packable, Serialize)]
    pub struct Settled {
        withdrawals_root: Field,
        time: u64,
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
        refunds_owed: u128,
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
                withdrawals_owed: 0,
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
        self.enqueue_self._queue(KIND_REGISTER, master_auth, enc_key_commitment, self.msg_sender());
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
            self.call(L3XToken::at(config.token).transfer_from(sender, operator, config.request_fee));
        }
        self.internal.queue_entry(kind, account_index, b, c, sender);
    }

    /// Deposits into an account (C0): the funds move into the vault now, and the request credits
    /// the account when processed, or refunds the caller if the account does not exist.
    #[external("public")]
    fn deposit(account_index: Field, amount: u128) {
        assert((amount > 0) & (amount < MAX_DEPOSIT as u128), "deposit amount out of range");
        let sender = self.msg_sender();
        let token = self.storage.config.read().token;
        self.call(L3XToken::at(token).transfer_from(sender, self.address, amount));
        self.internal.queue_entry(KIND_DEPOSIT, account_index, amount as Field, 0, sender);
    }

    #[external("public")]
    #[only_self]
    fn _queue(kind: Field, a: Field, b: Field, sender: AztecAddress) {
        self.internal.queue_entry(kind, a, b, 0, sender);
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
        let deposited = if kind == KIND_DEPOSIT { b as u128 } else { 0 };
        let mut next = self.storage.slots.at(index + 1).read();
        next.head = priority_next_head(slot.head, entry);
        next.deposit_prefix = slot.deposit_prefix + deposited;
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
        tip.withdrawals_owed += h.withdrawals_amount as u128;
        self.storage.tip.write(tip);
        self.storage.settled.at(batch_number).write(Settled { withdrawals_root: h.withdrawals_root, time: now });

        // 6. Mode R DA (SPEC.md §9.5): [DA_LOG_TAG, batch_number, payload[0..da_len]].
        let mut log = [DA_LOG_TAG, batch_number as Field].as_vector();
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
                withdrawals_amount: h.withdrawals_amount,
                market_data,
            },
        );
    }

    // ---- Withdrawals (SPEC.md §10.4, C0 profile) ----

    /// Pays a settled withdrawal or refund record from the vault, once, to its recipient. Anyone
    /// may call it; it works in desert mode too.
    #[external("public")]
    fn claim_withdrawal(
        batch: u64,
        index: u32,
        recipient: AztecAddress,
        amount: u64,
        salt: Field,
        path: [Field; WD_HEIGHT],
    ) {
        let record = withdrawal_record(recipient.to_field(), amount, salt, batch, index);
        assert(
            merkle_root(DS_WD_NODE, record, index, path) == self.storage.settled.at(batch).read().withdrawals_root,
            "record not in the batch's withdrawals tree",
        );
        assert(!self.storage.withdrawal_paid.at(record).read(), "already paid");
        self.storage.withdrawal_paid.at(record).write(true);
        let mut tip = self.storage.tip.read();
        tip.withdrawals_owed -= amount as u128;
        self.storage.tip.write(tip);
        self.call(L3XToken::at(self.storage.config.read().token).transfer(recipient, amount as u128));
        self.emit(WithdrawalPaid { batch, index, recipient, amount });
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
        d.refunds_owed =
            self.storage.slots.at(tip.priority_count).read().deposit_prefix - pending.deposit_prefix;
        self.storage.desert.write(d);
        self.emit(
            DesertActivated {
                accounts_root: d.accounts_root,
                market_data_hash: d.market_data_hash,
                claim_close: d.claim_close,
                refunds_owed: d.refunds_owed,
            },
        );
    }

    /// Refunds a deposit the exchange never processed, to its depositor, in full.
    #[external("public")]
    fn desert_refund(index: u64, account_index: Field, amount: u128, depositor: AztecAddress) {
        let mut d = self.storage.desert.read();
        assert(d.active, "not in desert mode");
        assert(index >= self.storage.tip.read().priority_cursor, "request was processed");
        let slot = self.storage.slots.at(index).read();
        let entry = priority_entry(
            payload_hash(KIND_DEPOSIT, account_index, amount as Field, 0),
            depositor.to_field(),
            slot.time,
        );
        assert(entry == slot.entry, "not this deposit");
        assert(!self.storage.refunded.at(index).read(), "already refunded");
        self.storage.refunded.at(index).write(true);
        d.refunds_owed -= amount;
        self.storage.desert.write(d);
        self.call(L3XToken::at(self.storage.config.read().token).transfer(depositor, amount));
    }

    /// Registers an account's exit claim from its leaf in the frozen accounts root (SPEC.md §12).
    /// Positions are valued at the frozen index prices, with funding accrued to the frozen
    /// cumulative indices; negative equity counts as zero. The claim pays only the leaf's owner.
    /// The opening comes from the account's DA entries (SPEC.md §9.5) and the market data from the
    /// last BatchSettled event. A user claim registered within the window shares the vault pro
    /// rata; a later one, and any protocol account's, is paid from the residual.
    #[external("public")]
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
        let mut d = self.storage.desert.read();
        assert(d.active, "not in desert mode");
        assert(market_data_hash(market_data) == d.market_data_hash, "market data");
        let late = self.context.timestamp() > d.claim_close;
        let protocol = class != CLASS_USER;
        let pubv = AccountPub { owner: owner.to_field(), master_auth, enc_commitment: enc_key_commitment, class };
        let privv = from_plaintext(plaintext);
        assert(
            merkle_root(DS_ACCT_NODE, account_leaf(pubv, privv), account_index, path) == d.accounts_root,
            "not in the frozen accounts tree",
        );
        assert(!self.storage.claims.at(account_index).read().registered, "already claimed");
        let (prices, cums) = index_and_funding(market_data);
        let equity = equity_at(privv, prices, cums);
        let value: u128 = if equity > 0 { (equity as u64) as u128 } else { 0 };
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
    /// - A window claim gets min(1, V/U) of its equity, where V is the vault less the senior
    ///   obligations (unpaid withdrawals and refunds) when the ratio is fixed, at the first payout,
    ///   and U the window's total claims.
    /// - A late claim gets the same ratio at best, paid from the residual: the vault less the
    ///   senior obligations and what the window's claims are still owed.
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
        let vault = self.view(L3XToken::at(token).balance_of(self.address));
        let senior = self.storage.tip.read().withdrawals_owed + d.refunds_owed;
        if d.payout_den == 0 {
            // ratio = min(1, V/U), and 1 when no claim was registered in the window.
            let v = if vault > senior { vault - senior } else { 0 };
            if d.total_claims == 0 {
                d.payout_num = 1;
                d.payout_den = 1;
            } else {
                d.payout_num = if v < d.total_claims { v } else { d.total_claims };
                d.payout_den = d.total_claims;
            }
            d.window_owed = d.total_claims * d.payout_num / d.payout_den;
        }
        let pay = claim.equity * d.payout_num / d.payout_den;
        let amount = if !claim.late & !claim.protocol {
            d.window_owed = if d.window_owed > pay { d.window_owed - pay } else { 0 };
            pay
        } else {
            let reserved = senior + d.window_owed;
            let residual = if vault > reserved { vault - reserved } else { 0 };
            if pay < residual { pay } else { residual }
        };
        self.storage.desert.write(d);
        claim.paid = true;
        self.storage.claims.at(account_index).write(claim);
        self.call(L3XToken::at(token).transfer(claim.owner, amount));
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

    #[external("public")]
    #[view]
    fn get_withdrawals_root(batch: u64) -> Field {
        self.storage.settled.at(batch).read().withdrawals_root
    }

    #[internal("public")]
    fn current_operator() -> AztecAddress {
        let operator = self.storage.operator.get_current_value();
        if operator.is_zero() { self.storage.config.read().genesis_operator } else { operator }
    }
}
