mod test;

use aztec::macros::aztec;

/// L3X settlement contract, the P0 subset of SPEC.md §10:
/// - state root, batch-header binding and replay protection;
/// - priority queue with the T_force deadline;
/// - time bounds against Aztec time;
/// - Mode R DA as one public log per batch;
/// - delayed configuration (§12): the operator, root VK hash and configuration hash change only
///   UPGRADE_DELAY after a change is scheduled, and the contract cannot change its own class.
/// Custody (§10.3), withdrawals (§10.4) and desert mode (§12) come in later phases.
#[aztec]
pub contract L3XBridge {
    use aztec::{
        macros::{
            events::event, functions::{external, initializer, internal, only_self, view}, storage::storage,
        },
        oracle::avm,
        protocol::{address::AztecAddress, traits::ToField},
        state_vars::{DelayedPublicMutable, Map, PublicImmutable, PublicMutable},
    };
    use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
    use l3x_types::{
        BatchHeader, config_hash as config_hash_of, DA_MAX, da_hash_flat, genesis_state_root,
        HEADER_LEN, merge::{VK_TREE_LEAVES, vk_tree_root_of}, priority_entry, priority_next_head,
    };

    global T_FORCE: u64 = 14 * 24 * 60 * 60;
    global T_LAG: u64 = 15 * 60;
    /// SPEC.md §12. Must exceed T_force + T_payout (24 h) plus a margin, so users can exit before
    /// a change applies. No function can change it: schedule_delay_change is never called.
    global UPGRADE_DELAY: u64 = 21 * 24 * 60 * 60;
    /// Tag at fields[0] of the DA log ("l3x.da.v1"), so indexers can find settlement payloads.
    global DA_LOG_TAG: Field = 0x6c33782e64612e7631;

    #[event]
    struct PriorityRequested {
        index: u64,
        entry: Field,
        payload_hash: Field,
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
    }

    /// Publishes the full preimage of a scheduled configuration (SPEC.md §6.2, §10.1).
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

    #[storage]
    struct Storage<Context> {
        // Configuration at deployment.
        genesis_operator: PublicImmutable<AztecAddress, Context>,
        genesis_root_vk_hash: PublicImmutable<Field, Context>,
        genesis_config_hash: PublicImmutable<Field, Context>,
        // Scheduled replacements. A value of zero means none has taken effect yet, so the genesis
        // value applies. A DelayedPublicMutable cannot be initialized without its delay, hence the
        // split.
        operator: DelayedPublicMutable<AztecAddress, UPGRADE_DELAY, Context>,
        root_vk_hash: DelayedPublicMutable<Field, UPGRADE_DELAY, Context>,
        config_hash: DelayedPublicMutable<Field, UPGRADE_DELAY, Context>,
        // Exchange tip.
        state_root: PublicMutable<Field, Context>,
        accounts_root: PublicMutable<Field, Context>,
        batch_number: PublicMutable<u64, Context>,
        last_time: PublicMutable<u64, Context>,
        priority_cursor: PublicMutable<u64, Context>,
        priority_count: PublicMutable<u64, Context>,
        // priority_head[n] is the hash-chain head after n entries; priority_head[0] == 0.
        priority_head: Map<u64, PublicMutable<Field, Context>, Context>,
        priority_entry: Map<u64, PublicMutable<Field, Context>, Context>,
        priority_time: Map<u64, PublicMutable<u64, Context>, Context>,
        withdrawals_root: Map<u64, PublicMutable<Field, Context>, Context>,
        settled_time: Map<u64, PublicMutable<u64, Context>, Context>,
    }

    #[external("public")]
    #[initializer]
    fn constructor(operator: AztecAddress, root_vk_hash: Field, config_hash: Field) {
        self.storage.genesis_operator.initialize(operator);
        self.storage.genesis_root_vk_hash.initialize(root_vk_hash);
        self.storage.genesis_config_hash.initialize(config_hash);
        self.storage.state_root.write(genesis_state_root());
    }

    /// Queues a priority request (SPEC.md §12). P0 carries an opaque payload hash; the entry
    /// binds the submitter and Aztec time.
    #[external("public")]
    fn submit_request(payload_hash: Field) {
        let index = self.storage.priority_count.read();
        let time = self.context.timestamp();
        let sender = self.msg_sender();
        let entry = priority_entry(payload_hash, sender.to_field(), time);
        let head = self.storage.priority_head.at(index).read();
        self.storage.priority_entry.at(index).write(entry);
        self.storage.priority_time.at(index).write(time);
        self.storage.priority_head.at(index + 1).write(priority_next_head(head, entry));
        self.storage.priority_count.write(index + 1);
        self.emit(PriorityRequested { index, entry, payload_hash, sender, time });
    }

    /// Verifies a root proof over H(header) in the private phase, then applies the header's state
    /// transition in the public phase (SPEC.md §10.1–10.2).
    ///
    /// The DA hash is checked here rather than in _apply: the enqueued call's calldata is bound
    /// to this function's arguments, so _apply receives exactly the payload checked here, and
    /// hashing up to 4,080 fields costs client-proving gates instead of public gas.
    #[external("private")]
    fn settle(
        header: [Field; HEADER_LEN],
        proof: UltraHonkZKProof,
        vk: UltraHonkVerificationKey,
        da_payload: [Field; DA_MAX],
        da_len: u32,
    ) {
        let operator = self.storage.operator.get_current_value();
        let operator =
            if operator.is_zero() { self.storage.genesis_operator.read() } else { operator };
        assert(self.msg_sender() == operator, "not operator");

        // Reading a DelayedPublicMutable caps this transaction's expiration before any scheduled
        // change, so the values checked here are still current when the transaction lands.
        let config = self.storage.config_hash.get_current_value();
        let config = if config == 0 { self.storage.genesis_config_hash.read() } else { config };
        let root_vk = self.storage.root_vk_hash.get_current_value();
        let root_vk = if root_vk == 0 { self.storage.genesis_root_vk_hash.read() } else { root_vk };

        let h = BatchHeader::from_fields(header);
        assert(h.config_hash == config, "config mismatch");
        assert(da_hash_flat(da_payload, da_len) == h.da_hash, "da hash");
        verify_honk_proof(vk, proof, [h.hash()], root_vk);
        self.enqueue_self._apply(header, da_payload, da_len);
    }

    #[external("public")]
    #[only_self]
    fn _apply(header: [Field; HEADER_LEN], da_payload: [Field; DA_MAX], da_len: u32) {
        let h = BatchHeader::from_fields(header);
        let now = self.context.timestamp();

        // 1. Chain continuity and replay protection.
        assert(h.prev_state_root == self.storage.state_root.read(), "stale state root");
        let batch_number = self.storage.batch_number.read() + 1;
        assert(h.batch_number == batch_number, "batch number");

        // 2. The consumed priority range starts at the cursor and its fold matches stored heads.
        let count = self.storage.priority_count.read();
        assert(h.priority_start == self.storage.priority_cursor.read(), "priority start");
        assert(h.priority_end <= count, "priority end");
        assert(
            self.storage.priority_head.at(h.priority_start).read() == h.priority_head_start,
            "priority head start",
        );
        assert(
            self.storage.priority_head.at(h.priority_end).read() == h.priority_head_end,
            "priority head end",
        );

        // 3. No request older than T_force may be left behind.
        if h.priority_end < count {
            assert(
                self.storage.priority_time.at(h.priority_end).read() + T_FORCE >= now,
                "priority request overdue",
            );
        }

        // 4. L3 time is monotone and within T_lag of Aztec time.
        assert(self.storage.last_time.read() <= h.min_time, "time regressed");
        assert(h.min_time <= h.max_time, "time order");
        assert(h.max_time <= now, "batch time in the future");
        assert(h.max_time + T_LAG >= now, "batch time lags Aztec time");

        self.storage.state_root.write(h.new_state_root);
        self.storage.accounts_root.write(h.new_accounts_root);
        self.storage.batch_number.write(batch_number);
        self.storage.last_time.write(h.max_time);
        self.storage.priority_cursor.write(h.priority_end);
        self.storage.withdrawals_root.at(batch_number).write(h.withdrawals_root);
        self.storage.settled_time.at(batch_number).write(now);

        // 5. Mode R DA (SPEC.md §9.5): [DA_LOG_TAG, batch_number, payload[0..da_len]].
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
            },
        );
    }

    /// Schedules a new configuration and root VK together (SPEC.md §12). The preimage, including
    /// every VK tree leaf, is checked here and published. Takes effect after UPGRADE_DELAY;
    /// scheduling again before then replaces the pending change.
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

    #[external("public")]
    #[view]
    fn get_tip() -> (Field, Field, u64, u64, u64, u64) {
        (
            self.storage.state_root.read(),
            self.storage.accounts_root.read(),
            self.storage.batch_number.read(),
            self.storage.last_time.read(),
            self.storage.priority_cursor.read(),
            self.storage.priority_count.read(),
        )
    }

    #[external("public")]
    #[view]
    fn get_priority(index: u64) -> (Field, Field, u64) {
        (
            self.storage.priority_head.at(index).read(),
            self.storage.priority_entry.at(index).read(),
            self.storage.priority_time.at(index).read(),
        )
    }

    /// The configuration in force now: (operator, root VK hash, configuration hash).
    #[external("public")]
    #[view]
    fn get_config() -> (AztecAddress, Field, Field) {
        let root_vk = self.storage.root_vk_hash.get_current_value();
        let config = self.storage.config_hash.get_current_value();
        (
            self.internal.current_operator(),
            if root_vk == 0 { self.storage.genesis_root_vk_hash.read() } else { root_vk },
            if config == 0 { self.storage.genesis_config_hash.read() } else { config },
        )
    }

    #[internal("public")]
    fn current_operator() -> AztecAddress {
        let operator = self.storage.operator.get_current_value();
        if operator.is_zero() { self.storage.genesis_operator.read() } else { operator }
    }
}
