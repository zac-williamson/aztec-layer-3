use aztec::macros::aztec;

/// L3X settlement contract, P0 subset of SPEC.md §10: state root, batch-header binding, priority
/// queue with deadline, time bounds, DA hash, replay protection. Custody (§10.3), withdrawals
/// (§10.4) and desert mode (§12) come in later phases. P0 stores the operator, root VK hash and
/// configuration hash as PublicImmutable; the specified DelayedPublicMutable upgrade path is
/// deferred.
#[aztec]
pub contract L3XBridge {
    use aztec::{
        macros::{events::event, functions::{external, initializer, only_self, view}, storage::storage},
        protocol::{address::AztecAddress, traits::ToField},
        state_vars::{Map, PublicImmutable, PublicMutable},
    };
    use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
    use l3x_types::{
        BatchHeader, DA_LEN, HEADER_LEN, da_hash, genesis_state_root, priority_entry,
        priority_next_head,
    };

    global T_FORCE: u64 = 14 * 24 * 60 * 60;
    global T_LAG: u64 = 15 * 60;

    #[event]
    struct PriorityRequested {
        index: u64,
        entry: Field,
        payload_hash: Field,
        sender: AztecAddress,
        time: u64,
    }

    #[event]
    struct BatchSettled {
        batch_number: u64,
        new_state_root: Field,
        new_accounts_root: Field,
        priority_end: u64,
        da_payload: [Field; DA_LEN],
    }

    #[storage]
    struct Storage<Context> {
        operator: PublicImmutable<AztecAddress, Context>,
        root_vk_hash: PublicImmutable<Field, Context>,
        config_hash: PublicImmutable<Field, Context>,
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
        self.storage.operator.initialize(operator);
        self.storage.root_vk_hash.initialize(root_vk_hash);
        self.storage.config_hash.initialize(config_hash);
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

    /// Verifies a root proof over H(header) in the private phase, then applies the header's
    /// state transition in the public phase (SPEC.md §10.1–10.2).
    #[external("private")]
    fn settle(
        header: [Field; HEADER_LEN],
        proof: UltraHonkZKProof,
        vk: UltraHonkVerificationKey,
        da_payload: [Field; DA_LEN],
    ) {
        assert(self.msg_sender() == self.storage.operator.read(), "not operator");
        let h = BatchHeader::from_fields(header);
        assert(h.config_hash == self.storage.config_hash.read(), "config mismatch");
        verify_honk_proof(vk, proof, [h.hash()], self.storage.root_vk_hash.read());
        self.enqueue_self._apply(header, da_payload);
    }

    #[external("public")]
    #[only_self]
    fn _apply(header: [Field; HEADER_LEN], da_payload: [Field; DA_LEN]) {
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

        // 5. The published payload is the one the proof committed to.
        assert(da_hash(da_payload) == h.da_hash, "da hash");

        self.storage.state_root.write(h.new_state_root);
        self.storage.accounts_root.write(h.new_accounts_root);
        self.storage.batch_number.write(batch_number);
        self.storage.last_time.write(h.max_time);
        self.storage.priority_cursor.write(h.priority_end);
        self.storage.withdrawals_root.at(batch_number).write(h.withdrawals_root);
        self.storage.settled_time.at(batch_number).write(now);
        self.emit(
            BatchSettled {
                batch_number,
                new_state_root: h.new_state_root,
                new_accounts_root: h.new_accounts_root,
                priority_end: h.priority_end,
                da_payload,
            },
        );
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
}
