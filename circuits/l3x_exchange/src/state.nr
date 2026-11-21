use crate::{
    consts::{ACCOUNTS_HEIGHT, BOOK_HEIGHT, DS_ACCT_NODE, DS_ACTV_NODE, DS_MARKET_DATA, DS_MKT, DS_OTHER},
    tree::empty_root,
};
use l3x_types::{hash::hash, state_root, trees};

/// The single P1 market's leaf (SPEC.md §6.6, reduced): book root, index price and time, the
/// next order sequence number, open interest.
pub struct Market {
    pub book_root: Field,
    pub index_price: u64,
    pub index_time: u64,
    pub next_seq: u64,
    pub oi_long: u64,
    pub oi_short: u64,
}

impl Market {
    pub fn hash(self) -> Field {
        hash(
            [
                DS_MKT, self.book_root, self.index_price as Field, self.index_time as Field,
                self.next_seq as Field, self.oi_long as Field, self.oi_short as Field,
            ],
        )
    }

    /// The public market data a batch exposes in its header (P1: the index).
    pub fn data_hash(self) -> Field {
        market_data_hash(self.index_price, self.index_time)
    }
}

pub fn market_data_hash(index_price: u64, index_time: u64) -> Field {
    hash([DS_MARKET_DATA, index_price as Field, index_time as Field])
}

/// Opening of Running.state (SPEC.md §6.2).
pub struct State {
    pub accounts_root: Field,
    pub activity_root: Field,
    pub market: Market,
    pub refresh_cursor: u32,
    pub num_accounts: u32,
}

impl State {
    pub fn other_root(self) -> Field {
        hash(
            [
                DS_OTHER, self.activity_root, self.market.hash(), self.refresh_cursor as Field,
                self.num_accounts as Field,
            ],
        )
    }

    pub fn trees(self) -> Field {
        trees(self.accounts_root, self.other_root())
    }
}

pub fn empty_book_root() -> Field {
    crate::book_empty_root()
}

pub fn genesis_state() -> State {
    State {
        accounts_root: empty_root::<ACCOUNTS_HEIGHT>(DS_ACCT_NODE),
        activity_root: empty_root::<ACCOUNTS_HEIGHT>(DS_ACTV_NODE),
        market: Market { book_root: empty_book_root(), index_price: 0, index_time: 0, next_seq: 0, oi_long: 0, oi_short: 0 },
        refresh_cursor: 0,
        num_accounts: 0,
    }
}

pub fn genesis_state_root() -> Field {
    state_root(genesis_state().trees(), 0, 0, 0)
}

#[test]
fn genesis_is_stable() {
    let g = genesis_state();
    assert(g.trees() == genesis_state().trees());
    let _ = BOOK_HEIGHT;
}
