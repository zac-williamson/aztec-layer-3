// Tree heights.
pub global ACCOUNTS_HEIGHT: u32 = 32;
pub global BOOK_HEIGHT: u32 = 80;
/// Session-key slots per account: a tree of height 8 (256 slots) in the activity leaf (SPEC.md §6.4).
pub global KEYS_HEIGHT: u32 = 8;
pub global KEY_SLOTS: u32 = 256;
/// The key id an action uses when the master key signs it.
pub global MASTER_KEY: u32 = 256;
/// Withdrawal records per batch: a tree of height 4 (16 leaves) built by the root.
pub global WD_HEIGHT: u32 = 4;
pub global MAX_WD_BATCH: u32 = 16;

/// Listed markets. Every account has one position slot per market, so the slot is the market id
/// and the DA, which always encrypts every slot, never reveals which market changed (SPEC.md §4).
pub global MARKETS: u32 = 4;
/// Oracle publishers; an index update needs signatures from `oracle_k` of them (SPEC.md §8.4).
pub global N_ORACLES: u32 = 3;

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
pub global DS_MKTS: Field = 46;
pub global DS_MKT_PARAMS: Field = 47;
pub global DS_LIQ: Field = 48;
pub global DS_KEY: Field = 49;
pub global DS_KEY_NODE: Field = 50;
pub global DS_RECEIPT_SIG: Field = 51;
pub global DS_MAUTH_P: Field = 52;
pub global DS_CLEAN: Field = 53;
/// A queued deposit's amount commitment, H(DS_DEPAMT, amount, salt) (SPEC.md §10.3).
pub global DS_DEPAMT: Field = 54;
/// A deposit's credit blind, H(DS_DEP, account index, refund_to, depositor, salt) (SPEC.md §10.3).
pub global DS_DEP: Field = 55;
/// A trigger's leaf, and a trigger firing's log message (SPEC.md §6.5).
pub global DS_TRIGGER: Field = 56;
pub global DS_FIRE: Field = 57;
/// A fee-tier change, logged as H(DS_TIER, account, tier) (SPEC.md §8.6).
pub global DS_TIER: Field = 58;
/// Depth bound of a receipt path: two levels in the trade segment and the root, plus the merge
/// tree's depth (SPEC.md §11).
pub global RECEIPT_DEPTH: u32 = 24;

// Priority request kinds (SPEC.md §7.3). Forced requests carry the account index in `a`.
pub global KIND_REGISTER: Field = 1;
pub global KIND_DEPOSIT: Field = 2;
/// b = recipient: withdraw all free collateral.
pub global KIND_FORCED_WITHDRAW: Field = 3;
/// b = market, c = worst price: close the position against the book, no worse than c.
pub global KIND_FORCED_CLOSE: Field = 4;
/// Cancel up to FORCED_CANCELS of the account's orders.
pub global KIND_FORCED_CANCEL_ALL: Field = 5;
/// The owner's rekey: b = new master authorization, c = new encryption-key commitment. The Bridge
/// delivered the new key to the operator; the rekey revokes every session key and cancels every
/// order.
pub global KIND_REKEY: Field = 6;

// Action-log entry kinds.
pub global LOG_PRIORITY: Field = 1;
pub global LOG_BLOCK: Field = 2;
pub global LOG_ORACLE: Field = 3;
pub global LOG_SIGNED: Field = 4;
pub global LOG_LIQUIDATE: Field = 5;
pub global LOG_CLEANUP: Field = 6;
/// A trigger firing (SPEC.md §6.5), logged as H(DS_FIRE, market, index).
pub global LOG_TRIGGER: Field = 7;
/// A fee-tier change by the operator (SPEC.md §8.6).
pub global LOG_TIER: Field = 8;
/// Fee tiers (SPEC.md §8.6). Tier 0 is every new account's.
pub global FEE_TIERS: u32 = 4;

// DA entries (SPEC.md §9.5). Every entry starts with its tag and has a fixed length.
pub global TAG_SEG: Field = 1; // [tag, da_nonce]: opens a segment's encryption context
pub global TAG_CHANGE: Field = 2; // [tag, index, leaf, ct × PLAINTEXT_LEN]: public part unchanged
pub global TAG_REFRESH: Field = 3; // [tag, index, leaf, owner, master_auth, enc_commitment, class, ct × PLAINTEXT_LEN]
pub global TAG_WD: Field = 4; // [tag, record]
pub global TAG_FULL: Field = 5; // TAG_REFRESH's layout for a new leaf: registration
/// [tag, (market·2 + side)·2^80 + price·2^48 + seq, lots]: a displayed order's resting lots, in
/// clear, whenever they change; zero when it leaves the book (SPEC.md §8.4, [D1]).
pub global TAG_DISPLAY: Field = 6;
pub global SEG_HEADER_LEN: u32 = 2;
/// Encrypted plaintext of an account entry: collateral, one packed position per market, blind.
pub global PLAINTEXT_LEN: u32 = 2 + MARKETS;
pub global CHANGE_ENTRY_LEN: u32 = 3 + PLAINTEXT_LEN;
pub global FULL_ENTRY_LEN: u32 = 7 + PLAINTEXT_LEN;
pub global WD_ENTRY_LEN: u32 = 2;

// Account classes (SPEC.md §6.3). The protocol accounts exist from genesis at fixed indices.
pub global CLASS_USER: Field = 0;
pub global CLASS_INSURANCE: Field = 1;
pub global CLASS_FEE: Field = 2;
pub global INSURANCE_INDEX: u32 = 0;
pub global FEE_INDEX: u32 = 1;
pub global PROTOCOL_ACCOUNTS: u32 = 2;

pub global PPM: u64 = 1_000_000;
/// Funding indices and funding remainders are kept in micro-units of collateral (SPEC.md §6.1).
pub global MICRO: u64 = 1_000_000;
pub global MAX_OPEN_ORDERS: u32 = 1000;

/// Bounds that keep position arithmetic inside i64: price and lots below 2^24, so a notional is
/// below 2^48; |size| below 2^32, so |size · price| and |entry| stay below 2^56; collateral and
/// deposits below 2^62; cumulative funding below 2^60 micro-units per lot; an unrealized funding
/// amount below 2^58. Together they keep an account's equity below 2^63.
pub global MAX_PRICE: u64 = 0x1000000;
pub global MAX_LOTS: u64 = 0x1000000;
pub global MAX_SIZE: u64 = 0x100000000;
pub global MAX_DEPOSIT: u64 = 0x4000000000000000;
pub global MAX_COLLATERAL: u64 = 0x4000000000000000;
pub global MAX_CUM_FUNDING: u64 = 0x1000000000000000;
pub global MAX_FUNDING_CREDIT: u64 = 0x400000000000000;
pub global MAX_FEES: u64 = 0x4000000000000000;

// Funding formula (SPEC.md §8.4), in ppm: rate = clamp(P + clamp(R − P, ±R_CLAMP), ±CAP) / DIV per
// interval, which caps funding at 0.5% per hour.
pub global FUNDING_R: i64 = 100;
pub global FUNDING_R_CLAMP: i64 = 500;
pub global FUNDING_CAP: i64 = 40_000;
pub global FUNDING_DIV: i64 = 8;
