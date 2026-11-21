// Tree heights.
pub global ACCOUNTS_HEIGHT: u32 = 32;
pub global BOOK_HEIGHT: u32 = 80;
/// Withdrawal records per batch: a tree of height 4 (16 leaves) built by the root.
pub global WD_HEIGHT: u32 = 4;
pub global MAX_WD_BATCH: u32 = 16;

// Domain separators (l3x_types uses 1–13).
pub global DS_ACCT: Field = 20;
pub global DS_ACCT_PUB: Field = 21;
pub global DS_ACCT_PRIV: Field = 22;
pub global DS_MAUTH: Field = 23;
pub global DS_ENC: Field = 24;
pub global DS_BLIND: Field = 25;
pub global DS_ACTV: Field = 26;
pub global DS_ACCT_NODE: Field = 27;
pub global DS_ACTV_NODE: Field = 28;
pub global DS_BOOK: Field = 29;
pub global DS_ORDER: Field = 30;
pub global DS_MKT: Field = 31;
pub global DS_OTHER: Field = 32;
pub global DS_ACTION: Field = 33;
pub global DS_KS: Field = 34;
pub global DS_DANONCE: Field = 35;
pub global DS_WD: Field = 36;
pub global DS_WDSALT: Field = 37;
pub global DS_REQ: Field = 38;
pub global DS_MARKET_DATA: Field = 39;
pub global DS_WD_NODE: Field = 40;
pub global DS_PARAMS: Field = 41;
pub global DS_ORACLE: Field = 42;
pub global DS_WD_CHAIN: Field = 43;
pub global DS_BLOCK: Field = 44;
pub global DS_DOMAIN: Field = 45;

// Priority request kinds (SPEC.md §7.3).
pub global KIND_REGISTER: Field = 1;
pub global KIND_DEPOSIT: Field = 2;

// Action-log entry kinds.
pub global LOG_PRIORITY: Field = 1;
pub global LOG_BLOCK: Field = 2;
pub global LOG_ORACLE: Field = 3;
pub global LOG_SIGNED: Field = 4;

// DA entries (SPEC.md §9.5). Every entry starts with its tag and has a fixed length.
pub global TAG_SEG: Field = 1; // [tag, da_nonce]: opens a segment's encryption context
pub global TAG_CHANGE: Field = 2; // [tag, index, leaf, owner, master_auth, enc_commitment, class, ct × 4]
pub global TAG_REFRESH: Field = 3; // same layout as TAG_CHANGE; the leaf is unchanged
pub global TAG_WD: Field = 4; // [tag, record]
pub global SEG_HEADER_LEN: u32 = 2;
pub global ACCOUNT_ENTRY_LEN: u32 = 11;
pub global WD_ENTRY_LEN: u32 = 2;
/// Encrypted plaintext of an account entry: collateral, size, entry notional, blind.
pub global PLAINTEXT_LEN: u32 = 4;

pub global CLASS_USER: Field = 0;
pub global PPM: u64 = 1_000_000;

/// P1 bounds that keep position arithmetic inside i64: price and lots below 2^24, so a notional
/// is below 2^48; |size| below 2^32 and |entry| below 2^56; deposits below 2^62.
pub global MAX_PRICE: u64 = 0x1000000;
pub global MAX_LOTS: u64 = 0x1000000;
pub global MAX_SIZE: u64 = 0x100000000;
pub global MAX_DEPOSIT: u64 = 0x4000000000000000;
