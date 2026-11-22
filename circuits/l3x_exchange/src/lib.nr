//! Exchange state and rules shared by the segment circuits, the root and the Bridge
//! (SPEC.md §6–§10; the P1 and P2 profiles in §15).
pub mod consts;
pub mod tree;
pub mod account;
pub mod state;
pub mod da;
pub mod params;
pub mod request;
pub mod sig;
pub mod book;
pub mod trade;
pub mod mark;
pub mod matching;
pub mod liq;
pub mod trigger;

pub fn book_empty_root() -> Field {
    book::empty_root()
}

use consts::{DS_DEP, DS_DEPAMT, DS_ORACLE, DS_WD, DS_WD_NODE, MAX_WD_BATCH, WD_HEIGHT};
use l3x_types::hash::hash;

/// A queued deposit's amount commitment (SPEC.md §10.3): the priority entry carries this, never
/// the amount. The salt is the depositor's secret.
pub fn deposit_commitment(amount: Field, salt: Field) -> Field {
    hash([DS_DEPAMT, amount, salt])
}

/// The blind of the credit a deposit moves into the Bridge (SPEC.md §10.3). It binds the deposit's
/// account, refund address and depositor, so the credit's opening fixes all of them.
pub fn deposit_blind(account_index: Field, refund_to: Field, depositor: Field, salt: Field) -> Field {
    hash([DS_DEP, account_index, refund_to, depositor, salt])
}

/// A withdrawal or refund record (SPEC.md §10.4): paid once to `recipient`, by custody inside a
/// net or, after t_payout, from the vault directly, on proof of inclusion in the batch's
/// withdrawals tree.
pub fn withdrawal_record(recipient: Field, amount: u64, salt: Field, batch: u64, index: u32) -> Field {
    hash([DS_WD, recipient, amount as Field, salt, batch as Field, index as Field])
}

/// Root of a batch's withdrawals tree over its records in order, zero-padded.
pub fn withdrawals_root(records: [Field; MAX_WD_BATCH]) -> Field {
    let mut layer = records;
    let mut width = MAX_WD_BATCH;
    for _ in 0..WD_HEIGHT {
        width = width / 2;
        for i in 0..MAX_WD_BATCH / 2 {
            if i < width {
                layer[i] = hash([DS_WD_NODE, layer[2 * i], layer[2 * i + 1]]);
            }
        }
    }
    layer[0]
}

/// The message an oracle publisher signs for an index update (SPEC.md §8.4): the market's index
/// price, the publishers' external mark, and the publication time.
pub fn oracle_message(domain: Field, market: u32, price: u64, external: u64, time: u64) -> Field {
    hash([DS_ORACLE, domain, market as Field, price as Field, external as Field, time as Field])
}

#[test]
fn withdrawals_root_matches_paths() {
    let mut records: [Field; MAX_WD_BATCH] = [0; MAX_WD_BATCH];
    for i in 0..5 {
        records[i] = (i + 11) as Field;
    }
    let root = withdrawals_root(records);
    // Path of record 3, built level by level.
    let mut path: [Field; WD_HEIGHT] = [0; WD_HEIGHT];
    let mut layer = records;
    let mut idx: u32 = 3;
    let mut width = MAX_WD_BATCH;
    for level in 0..WD_HEIGHT {
        path[level] = layer[idx ^ 1];
        width = width / 2;
        for i in 0..MAX_WD_BATCH / 2 {
            if i < width {
                layer[i] = hash([DS_WD_NODE, layer[2 * i], layer[2 * i + 1]]);
            }
        }
        idx = idx / 2;
    }
    assert(tree::merkle_root(DS_WD_NODE, records[3], 3, path) == root);
}
