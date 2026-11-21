pub mod hash;

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

// P0 shape parameters.
pub global MAX_CLIENT_PROOFS: u32 = 10;
pub global CLIENT_PUBLIC_INPUTS: u32 = 3;
pub global MAX_PRIORITY: u32 = 8;
pub global DA_LEN: u32 = 64;
pub global HEADER_LEN: u32 = 16;

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

/// Carried through the Chonk IVC on the databus: app return_data -> kernel call_data -> ...
/// The hiding kernel exposes it as its public output, and the tube re-exposes it.
pub struct AggOutput {
    pub actions_hash: Field,
    pub count: u32,
}

impl AggOutput {
    pub fn to_fields(self) -> [Field; 2] {
        [self.actions_hash, self.count as Field]
    }
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
    pub action_log_root: Field,
    pub da_hash: Field,
    pub market_data_hash: Field,
    pub config_hash: Field,
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
            self.action_log_root,
            self.da_hash,
            self.market_data_hash,
            self.config_hash,
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
            action_log_root: f[12],
            da_hash: f[13],
            market_data_hash: f[14],
            config_hash: f[15],
        }
    }

    pub fn hash(self) -> Field {
        let f = self.to_fields();
        hash(
            [
                DS_HEADER, f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], f[11],
                f[12], f[13], f[14], f[15],
            ],
        )
    }
}

/// P0 state root (SPEC.md §6.2, reduced): accounts root, priority cursor, batch number, last time.
pub fn state_root(accounts_root: Field, priority_cursor: u64, batch_number: u64, last_time: u64) -> Field {
    hash([DS_STATE, accounts_root, priority_cursor as Field, batch_number as Field, last_time as Field])
}

pub fn genesis_state_root() -> Field {
    state_root(0, 0, 0, 0)
}

/// Priority queue (SPEC.md §10.1): entry binds payload, submitter and time; heads chain entries.
pub fn priority_entry(payload_hash: Field, sender: Field, time: u64) -> Field {
    hash([DS_PRIORITY_ENTRY, payload_hash, sender, time as Field])
}

pub fn priority_next_head(head: Field, entry: Field) -> Field {
    hash([DS_PRIORITY, head, entry])
}

pub fn da_hash(payload: [Field; DA_LEN]) -> Field {
    let mut buf: [Field; DA_LEN + 1] = [0; DA_LEN + 1];
    buf[0] = DS_DA;
    for i in 0..DA_LEN {
        buf[i + 1] = payload[i];
    }
    hash(buf)
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
        action_log_root: 13,
        da_hash: 14,
        market_data_hash: 15,
        config_hash: 16,
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
