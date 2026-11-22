pub mod hash;
pub mod merge;

use hash::hash;

// Recursive proof types. Values from Aztec v6.0.0 noir-protocol-circuits types/src/constants.nr.
pub global PROOF_TYPE_OINK: u32 = 1;
pub global PROOF_TYPE_HN: u32 = 2;
pub global PROOF_TYPE_HN_FINAL: u32 = 7;
pub global PROOF_TYPE_CHONK: u32 = 8;

// Verification-key and proof sizes, same source.
pub global MEGA_APP_VK_LENGTH: u32 = 151;
pub global MEGA_KERNEL_VK_LENGTH: u32 = 151;
pub global CHONK_VK_LENGTH: u32 = 119;
// 48 hiding oink + 28 hiding-kernel IO + 41 merge + 556 ECCVM + 70 triple IPA + 478 joint.
pub global CHONK_PROOF_LENGTH: u32 = 1221;

// Shape parameters.
pub global MAX_CLIENT_PROOFS: u32 = 10;
pub global CLIENT_PUBLIC_INPUTS: u32 = 3;
pub global MAX_PRIORITY: u32 = 8;
pub global HEADER_LEN: u32 = 19;
/// DA fields one settlement carries. Aztec allows FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH = 4096 fields of
/// public logs per transaction, each log costing 2 header fields. The Bridge emits the DA log
/// (2 + tag + payload) and the BatchSettled event (2 + tag + 5), leaving 4085; 4080 keeps slack.
pub global DA_MAX: u32 = 4080;
/// DA fields one P0 X-segment can absorb (enough for a full payload, so M5 needs one segment).
pub global X_DA_MAX: u32 = 4080;

// Domain separators.
pub global DS_AUTH: Field = 1;
pub global DS_AGG: Field = 2;
pub global DS_PRIORITY: Field = 3;
pub global DS_PRIORITY_ENTRY: Field = 4;
pub global DS_ACCOUNTS: Field = 5;
pub global DS_STATE: Field = 6;
pub global DS_HEADER: Field = 7;
pub global DS_DA: Field = 8;
pub global DS_CONFIG: Field = 9;
pub global DS_TREES: Field = 10;
pub global DS_ACTION_LOG: Field = 11;
pub global DS_VK_NODE: Field = 12;
pub global DS_DA_SPONGE: Field = 13;
pub global DS_RECEIPT: Field = 14;
pub global DS_RECEIPT_NODE: Field = 15;

/// Carried through the Chonk IVC on the databus: app return_data -> kernel call_data -> ...
/// The hiding kernel exposes it as its public output; the tube consumes it.
pub struct AggOutput {
    pub actions_hash: Field,
    pub count: u32,
}

impl AggOutput {
    pub fn to_fields(self) -> [Field; 2] {
        [self.actions_hash, self.count as Field]
    }
}

/// Running values a segment carries from its first action to its last (SPEC.md §9.1). Merges
/// require `left.end == right.start`, so a batch is one unbroken chain of segments.
pub struct Running {
    /// Commitment to the exchange trees: trees(accounts_root, other_root).
    pub state: Field,
    /// Hash chain over executed actions; zero at the start of every batch.
    pub action_log: Field,
    /// Priority-queue hash-chain head, and the absolute index of the next unconsumed entry.
    pub priority_head: Field,
    pub priority_cursor: u64,
    /// DA sponge state and number of DA fields absorbed (da_iv() and 0 at the start of a batch).
    pub da: [Field; 4],
    pub da_len: u32,
    /// Hash chain over withdrawal records, their count and total amount; zero at the start of
    /// every batch.
    pub withdrawals: Field,
    pub withdrawals_count: u32,
    pub withdrawals_amount: u64,
    /// Number of the batch being proved. No segment changes it, so chaining makes it uniform
    /// across the batch, and the root checks it against the header.
    pub batch: u64,
    /// L3 time of the latest block.
    pub time: u64,
}

pub global RUNNING_LEN: u32 = 14;

impl Running {
    pub fn to_fields(self) -> [Field; RUNNING_LEN] {
        [
            self.state,
            self.action_log,
            self.priority_head,
            self.priority_cursor as Field,
            self.da[0],
            self.da[1],
            self.da[2],
            self.da[3],
            self.da_len as Field,
            self.withdrawals,
            self.withdrawals_count as Field,
            self.withdrawals_amount as Field,
            self.batch as Field,
            self.time as Field,
        ]
    }
}

impl Eq for Running {
    fn eq(self, other: Self) -> bool {
        self.to_fields() == other.to_fields()
    }
}

/// The public output of every merge-tree node: segments (tube, X-segment, padding) and merges.
/// A uniform layout lets a merge verify any child without knowing its kind; the VK tree role
/// decides which kinds are allowed (SPEC.md §9.3). `receipts_root` commits to the receipted
/// actions beneath the node (SPEC.md §11): a trade segment's root over its actions' receipt leaves,
/// zero for other segments, and for a merge the receipt node of its children's roots, so the
/// batch's receipts tree has the merge tree's shape.
pub struct NodeOutput {
    pub config_hash: Field,
    pub start: Running,
    pub end: Running,
    pub receipts_root: Field,
}

pub global NODE_OUTPUT_LEN: u32 = 2 + 2 * RUNNING_LEN;

/// A receipted action's leaf: the sequencer's number for it and its signed message (SPEC.md §11).
pub fn receipt_leaf(seq: u64, msg: Field) -> Field {
    hash([DS_RECEIPT, seq as Field, msg])
}

pub fn receipt_node(left: Field, right: Field) -> Field {
    hash([DS_RECEIPT_NODE, left, right])
}

impl NodeOutput {
    pub fn to_fields(self) -> [Field; NODE_OUTPUT_LEN] {
        let s = self.start.to_fields();
        let e = self.end.to_fields();
        let mut out: [Field; NODE_OUTPUT_LEN] = [0; NODE_OUTPUT_LEN];
        out[0] = self.config_hash;
        for i in 0..RUNNING_LEN {
            out[1 + i] = s[i];
            out[1 + RUNNING_LEN + i] = e[i];
        }
        out[1 + 2 * RUNNING_LEN] = self.receipts_root;
        out
    }
}

/// The exchange trees, as one commitment carried in Running.state. P0 has only an accounts root;
/// `other_root` stands for the activity tree, markets tree and refresh cursor (SPEC.md §6.2).
pub fn trees(accounts_root: Field, other_root: Field) -> Field {
    hash([DS_TREES, accounts_root, other_root])
}

/// The configuration a batch proves against (SPEC.md §6.2): the role-partitioned VK tree root and
/// a hash of every other parameter.
pub fn config_hash(vk_tree_root: Field, params_hash: Field) -> Field {
    hash([DS_CONFIG, vk_tree_root, params_hash])
}

/// SPEC.md §9.4. The root proof's single public input is `hash()` of this header; the Bridge
/// recomputes it from the same fields before verifying.
pub struct BatchHeader {
    pub prev_state_root: Field,
    pub new_state_root: Field,
    pub new_accounts_root: Field,
    pub batch_number: u64,
    pub min_time: u64,
    pub max_time: u64,
    pub priority_start: u64,
    pub priority_end: u64,
    pub priority_head_start: Field,
    pub priority_head_end: Field,
    pub withdrawals_root: Field,
    pub withdrawals_count: u64,
    pub withdrawals_amount: u64,
    pub action_log_root: Field,
    pub da_hash: Field,
    pub market_data_hash: Field,
    pub config_hash: Field,
    /// L3 time at which the current refresh cycle began, the last time the refresh cursor wrapped
    /// (SPEC.md §9.5). The Bridge requires every batch to end within the refresh window of it.
    pub cycle_start: u64,
    /// Root of the batch's receipts tree (SPEC.md §11): the operator answers a receipt challenge
    /// with a path to the action's leaf.
    pub receipts_root: Field,
}

fn to_u64_checked(x: Field) -> u64 {
    let y = x as u64;
    assert(y as Field == x, "header integer out of range");
    y
}

impl BatchHeader {
    pub fn to_fields(self) -> [Field; HEADER_LEN] {
        [
            self.prev_state_root,
            self.new_state_root,
            self.new_accounts_root,
            self.batch_number as Field,
            self.min_time as Field,
            self.max_time as Field,
            self.priority_start as Field,
            self.priority_end as Field,
            self.priority_head_start,
            self.priority_head_end,
            self.withdrawals_root,
            self.withdrawals_count as Field,
            self.withdrawals_amount as Field,
            self.action_log_root,
            self.da_hash,
            self.market_data_hash,
            self.config_hash,
            self.cycle_start as Field,
            self.receipts_root,
        ]
    }

    pub fn from_fields(f: [Field; HEADER_LEN]) -> Self {
        BatchHeader {
            prev_state_root: f[0],
            new_state_root: f[1],
            new_accounts_root: f[2],
            batch_number: to_u64_checked(f[3]),
            min_time: to_u64_checked(f[4]),
            max_time: to_u64_checked(f[5]),
            priority_start: to_u64_checked(f[6]),
            priority_end: to_u64_checked(f[7]),
            priority_head_start: f[8],
            priority_head_end: f[9],
            withdrawals_root: f[10],
            withdrawals_count: to_u64_checked(f[11]),
            withdrawals_amount: to_u64_checked(f[12]),
            action_log_root: f[13],
            da_hash: f[14],
            market_data_hash: f[15],
            config_hash: f[16],
            cycle_start: to_u64_checked(f[17]),
            receipts_root: f[18],
        }
    }

    pub fn hash(self) -> Field {
        let f = self.to_fields();
        hash(
            [
                DS_HEADER, f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], f[11],
                f[12], f[13], f[14], f[15], f[16], f[17], f[18],
            ],
        )
    }
}

/// State root (SPEC.md §6.2): exchange trees, priority cursor, batch number, last time.
pub fn state_root(trees: Field, priority_cursor: u64, batch_number: u64, last_time: u64) -> Field {
    hash([DS_STATE, trees, priority_cursor as Field, batch_number as Field, last_time as Field])
}

/// Priority queue (SPEC.md §10.1): entry binds payload, submitter and time; heads chain entries.
pub fn priority_entry(payload_hash: Field, sender: Field, time: u64) -> Field {
    hash([DS_PRIORITY_ENTRY, payload_hash, sender, time as Field])
}

pub fn priority_next_head(head: Field, entry: Field) -> Field {
    hash([DS_PRIORITY, head, entry])
}

/// DA hash (SPEC.md §9.5). A Poseidon2 sponge of rate 3 runs over the batch's DA fields in order;
/// segments carry its state in Running.da so the payload can be split anywhere between segments.
/// The Bridge recomputes the same value from the flat payload.
pub fn da_iv() -> [Field; 4] {
    [0, 0, 0, DS_DA_SPONGE]
}

pub fn da_absorb(da: [Field; 4], len: u32, x: Field) -> ([Field; 4], u32) {
    let pos = len % 3;
    let mut s = da;
    s[pos] += x;
    if pos == 2 {
        s = std::hash::poseidon2_permutation(s);
    }
    (s, len + 1)
}

/// Binds the length, so payloads that differ only by trailing zeros hash differently.
pub fn da_finalize(da: [Field; 4], len: u32) -> Field {
    let mut s = da;
    if len % 3 != 0 {
        s = std::hash::poseidon2_permutation(s);
    }
    hash([DS_DA, s[0], len as Field])
}

/// The same hash over a flat payload of `len <= N` fields, absorbing three fields per
/// permutation. Fields at index >= len are ignored. Used by the Bridge.
pub fn da_hash_flat<let N: u32>(payload: [Field; N], len: u32) -> Field {
    assert(len <= N, "DA payload too long");
    let mut s = da_iv();
    for g in 0..(N + 2) / 3 {
        if g * 3 < len {
            for j in 0..3 {
                let i = g * 3 + j;
                if (i < N) & (i < len) {
                    s[j] += payload[i];
                }
            }
            s = std::hash::poseidon2_permutation(s);
        }
    }
    hash([DS_DA, s[0], len as Field])
}

#[test]
fn test_header_roundtrip() {
    let h = BatchHeader {
        prev_state_root: 1,
        new_state_root: 2,
        new_accounts_root: 3,
        batch_number: 4,
        min_time: 5,
        max_time: 6,
        priority_start: 7,
        priority_end: 8,
        priority_head_start: 9,
        priority_head_end: 10,
        withdrawals_root: 11,
        withdrawals_count: 12,
        withdrawals_amount: 17,
        action_log_root: 13,
        da_hash: 14,
        market_data_hash: 15,
        config_hash: 16,
        cycle_start: 18,
        receipts_root: 19,
    };
    let g = BatchHeader::from_fields(h.to_fields());
    assert(g.hash() == h.hash());
}

#[test(should_fail_with = "header integer out of range")]
fn test_header_rejects_wide_integers() {
    let mut f: [Field; HEADER_LEN] = [0; HEADER_LEN];
    f[3] = 18446744073709551616; // 2^64
    let _ = BatchHeader::from_fields(f);
}

#[test]
fn test_da_incremental_matches_flat() {
    let payload: [Field; 10] = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3];
    for len in 0..11 {
        let mut s = da_iv();
        let mut n: u32 = 0;
        // Split the absorption across two "segments" at an arbitrary point.
        for i in 0..10 {
            if i < len {
                let (s2, n2) = da_absorb(s, n, payload[i]);
                s = s2;
                n = n2;
            }
        }
        assert(da_finalize(s, n) == da_hash_flat(payload, len));
    }
}

#[test]
fn test_da_length_bound() {
    let a: [Field; 2] = [7, 0];
    assert(da_hash_flat(a, 1) != da_hash_flat(a, 2));
}
