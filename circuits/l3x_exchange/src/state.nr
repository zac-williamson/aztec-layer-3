use crate::{
    account::{account_leaf, AccountPriv, AccountPub, Activity},
    consts::{
        ACCOUNTS_HEIGHT, CLASS_FEE, CLASS_INSURANCE, DS_ACCT_NODE, DS_ACTV_NODE, DS_MARKET_DATA, DS_MKT,
        DS_MKTS, DS_OTHER, FEE_INDEX, INSURANCE_INDEX, MARKETS, PROTOCOL_ACCOUNTS,
    },
    account::enc,
    tree::merkle_root,
};
use l3x_types::{hash::hash, state_root, trees};

/// A market's leaf (SPEC.md §6.6). Prices are in collateral units per lot; `premium` is the mark's
/// premium over the index in ppm, `premium_acc` its time integral (ppm · s) since `window_start`;
/// `cum_funding` is in micro-units per lot and grows by `funding_rate · mark` per interval.
/// `best_bid` and `best_ask` are the top of book proved at the last mark tick (zero if empty).
/// `trigger_root` is the market's trigger tree (SPEC.md §6.5); `trigger_pending` is set while a
/// trigger is due at the mark, and then the market takes no new orders until the due triggers fire.
pub struct Market {
    pub book_root: Field,
    pub trigger_root: Field,
    pub trigger_pending: bool,
    pub next_seq: u64,
    pub index_price: u64,
    pub index_time: u64,
    pub mark_price: u64,
    pub premium: i64,
    pub premium_acc: i64,
    pub last_tick: u64,
    pub cum_funding: i64,
    pub funding_rate: i64,
    pub window_start: u64,
    pub next_funding: u64,
    pub oi_long: u64,
    pub oi_short: u64,
    pub best_bid: u64,
    pub best_ask: u64,
    /// The print summary of batch `print_batch` (SPEC.md §8.4, [D1]): its last, highest and lowest
    /// fill prices, and the lots and quote notional it filled. A market with no fill in the current
    /// batch still holds an earlier batch's, which the batch's market data ignores.
    pub print_batch: u64,
    pub print_last: u64,
    pub print_high: u64,
    pub print_low: u64,
    pub print_lots: u64,
    pub print_quote: u64,
}

impl Market {
    /// A market with empty books: `empty_root` is the empty tree's root, for orders and triggers.
    pub fn genesis(empty_root: Field) -> Self {
        Market {
            book_root: empty_root,
            trigger_root: empty_root,
            trigger_pending: false,
            next_seq: 0,
            index_price: 0,
            index_time: 0,
            mark_price: 0,
            premium: 0,
            premium_acc: 0,
            last_tick: 0,
            cum_funding: 0,
            funding_rate: 0,
            window_start: 0,
            next_funding: 0,
            oi_long: 0,
            oi_short: 0,
            best_bid: 0,
            best_ask: 0,
            print_batch: 0,
            print_last: 0,
            print_high: 0,
            print_low: 0,
            print_lots: 0,
            print_quote: 0,
        }
    }

    /// Records a fill of `q` lots at `price` in batch `batch`'s print summary, starting a fresh one at
    /// the batch's first fill.
    pub fn record_print(self, batch: u64, price: u64, q: u64) -> Self {
        let mut out = self;
        let fresh = self.print_batch != batch;
        out.print_batch = batch;
        out.print_last = price;
        out.print_high = if fresh | (price > self.print_high) { price } else { self.print_high };
        out.print_low = if fresh | (price < self.print_low) { price } else { self.print_low };
        out.print_lots = (if fresh { 0 } else { self.print_lots }) + q;
        out.print_quote = (if fresh { 0 } else { self.print_quote }) + q * price;
        out
    }

    pub fn hash(self) -> Field {
        hash(
            [
                DS_MKT, self.book_root, self.trigger_root, self.trigger_pending as Field, self.next_seq as Field,
                self.index_price as Field,
                self.index_time as Field, self.mark_price as Field, enc(self.premium), enc(self.premium_acc),
                self.last_tick as Field, enc(self.cum_funding), enc(self.funding_rate),
                self.window_start as Field, self.next_funding as Field, self.oi_long as Field,
                self.oi_short as Field, self.best_bid as Field, self.best_ask as Field, self.print_batch as Field,
                self.print_last as Field, self.print_high as Field, self.print_low as Field,
                self.print_lots as Field, self.print_quote as Field,
            ],
        )
    }

    /// The fields batch `batch` publishes for this market (SPEC.md §8.4, [D1]): the index and its
    /// time, the mark, cumulative funding and the funding rate, the best bid and ask, the batch's
    /// print summary (last, VWAP, high, low; zero without a fill in this batch), and its volume
    /// and the open interest, each rounded down to a power of two.
    pub fn data(self, batch: u64) -> [Field; MARKET_DATA_FIELDS] {
        let printed = (self.print_batch == batch) & (self.print_lots > 0);
        let (last, vwap, high, low, lots) = if printed {
            (self.print_last, self.print_quote / self.print_lots, self.print_high, self.print_low, self.print_lots)
        } else {
            (0, 0, 0, 0, 0)
        };
        [
            self.index_price as Field, self.index_time as Field, self.mark_price as Field,
            enc(self.cum_funding), enc(self.funding_rate), self.best_bid as Field, self.best_ask as Field,
            last as Field, vwap as Field, high as Field, low as Field, bucket(lots) as Field,
            bucket(self.oi_long) as Field,
        ]
    }
}

/// The largest power of two not above `x`, or zero: a magnitude without its digits ([D1]).
pub fn bucket(x: u64) -> u64 {
    let bits: [bool; 64] = (x as Field).to_le_bits();
    let mut b: u64 = 0;
    let mut p: u64 = 1;
    for i in 0..64 {
        if bits[i] {
            b = p;
        }
        if i < 63 {
            p = p * 2;
        }
    }
    b
}

#[test]
fn buckets() {
    assert(bucket(0) == 0);
    assert(bucket(1) == 1);
    assert(bucket(1000) == 512);
    assert(bucket(1024) == 1024);
    assert(bucket(0xffffffffffffffff) == 0x8000000000000000);
}

pub global MARKET_DATA_FIELDS: u32 = 13;
pub global MARKET_DATA_LEN: u32 = MARKET_DATA_FIELDS * MARKETS;

pub fn markets_hash(markets: [Market; MARKETS]) -> Field {
    let mut inputs: [Field; MARKETS + 1] = [0; MARKETS + 1];
    inputs[0] = DS_MKTS;
    for m in 0..MARKETS {
        inputs[1 + m] = markets[m].hash();
    }
    hash(inputs)
}

pub fn market_data(markets: [Market; MARKETS], batch: u64) -> [Field; MARKET_DATA_LEN] {
    let mut out: [Field; MARKET_DATA_LEN] = [0; MARKET_DATA_LEN];
    for m in 0..MARKETS {
        let d = markets[m].data(batch);
        for i in 0..MARKET_DATA_FIELDS {
            out[m * MARKET_DATA_FIELDS + i] = d[i];
        }
    }
    out
}

/// The index prices and cumulative funding indices in published market data, range-checked.
pub fn index_and_funding(data: [Field; MARKET_DATA_LEN]) -> ([u64; MARKETS], [i64; MARKETS]) {
    let mut prices: [u64; MARKETS] = [0; MARKETS];
    let mut cums: [i64; MARKETS] = [0; MARKETS];
    for m in 0..MARKETS {
        let p = data[m * MARKET_DATA_FIELDS];
        let c = data[m * MARKET_DATA_FIELDS + 3];
        assert(((p as u64) as Field == p) & ((c as u64) as Field == c), "market data out of range");
        prices[m] = p as u64;
        cums[m] = (c as u64) as i64;
    }
    (prices, cums)
}

pub fn market_data_hash(data: [Field; MARKET_DATA_LEN]) -> Field {
    let mut inputs: [Field; MARKET_DATA_LEN + 1] = [0; MARKET_DATA_LEN + 1];
    inputs[0] = DS_MARKET_DATA;
    for i in 0..MARKET_DATA_LEN {
        inputs[1 + i] = data[i];
    }
    hash(inputs)
}

/// Opening of Running.state (SPEC.md §6.2). `fees_pending` is collected but not yet credited to the
/// fee account; `insurance_pending` (liquidation fees) and `insurance_micro` (funding remainders, in
/// micro-units) are owed to the insurance account. The maintenance segment sweeps them into their
/// accounts.
pub struct State {
    pub accounts_root: Field,
    pub activity_root: Field,
    pub markets: [Market; MARKETS],
    pub refresh_cursor: u32,
    /// L3 time at which the refresh cursor last wrapped past the last account (SPEC.md §9.5).
    pub cycle_start: u64,
    /// The sequencer's number of the last signed action executed (SPEC.md §11).
    pub last_seq: u64,
    pub num_accounts: u32,
    pub fees_pending: u64,
    pub insurance_pending: u64,
    pub insurance_micro: u64,
}

impl State {
    pub fn other_root(self) -> Field {
        hash(
            [
                DS_OTHER, self.activity_root, markets_hash(self.markets), self.refresh_cursor as Field,
                self.cycle_start as Field, self.last_seq as Field, self.num_accounts as Field, self.fees_pending as Field, self.insurance_pending as Field,
                self.insurance_micro as Field,
            ],
        )
    }

    pub fn trees(self) -> Field {
        trees(self.accounts_root, self.other_root())
    }
}

/// The protocol accounts at genesis (SPEC.md §6.3): the insurance account at index 0 and the fee
/// account at index 1, with zero balances and a zero blind. `protocol` gives their owners, master
/// authorizations and encryption-key commitments; the classes are fixed here.
pub fn genesis_accounts(protocol: [AccountPub; PROTOCOL_ACCOUNTS]) -> [AccountPub; PROTOCOL_ACCOUNTS] {
    let mut out = protocol;
    out[INSURANCE_INDEX].class = CLASS_INSURANCE;
    out[FEE_INDEX].class = CLASS_FEE;
    out
}

pub fn genesis_state(protocol: [AccountPub; PROTOCOL_ACCOUNTS]) -> State {
    let accounts = genesis_accounts(protocol);
    // Leaves 0 and 1 are siblings: hash them together, then climb with empty subtrees.
    let mut zero_path: [Field; ACCOUNTS_HEIGHT] = [0; ACCOUNTS_HEIGHT];
    let mut e = 0;
    for i in 0..ACCOUNTS_HEIGHT {
        zero_path[i] = e;
        e = hash([DS_ACCT_NODE, e, e]);
    }
    let leaf0 = account_leaf(accounts[0], AccountPriv::empty(0));
    let leaf1 = account_leaf(accounts[1], AccountPriv::empty(0));
    let mut path = zero_path;
    path[0] = leaf1;
    let accounts_root = merkle_root(DS_ACCT_NODE, leaf0, 0, path);

    let mut zero_actv: [Field; ACCOUNTS_HEIGHT] = [0; ACCOUNTS_HEIGHT];
    let mut f = 0;
    for i in 0..ACCOUNTS_HEIGHT {
        zero_actv[i] = f;
        f = hash([DS_ACTV_NODE, f, f]);
    }
    let a = Activity::new().hash();
    let mut apath = zero_actv;
    apath[0] = a;
    let activity_root = merkle_root(DS_ACTV_NODE, a, 0, apath);

    let book = crate::book_empty_root();
    State {
        accounts_root,
        activity_root,
        markets: [Market::genesis(book); MARKETS],
        refresh_cursor: 0,
        cycle_start: 0,
        last_seq: 0,
        num_accounts: PROTOCOL_ACCOUNTS,
        fees_pending: 0,
        insurance_pending: 0,
        insurance_micro: 0,
    }
}

pub fn genesis_state_root(protocol: [AccountPub; PROTOCOL_ACCOUNTS]) -> Field {
    state_root(genesis_state(protocol).trees(), 0, 0, 0)
}

#[test]
fn genesis_is_stable() {
    let p = [
        AccountPub { owner: 1, master_auth: 2, enc_commitment: 3, class: 0 },
        AccountPub { owner: 4, master_auth: 5, enc_commitment: 6, class: 0 },
    ];
    let g = genesis_state(p);
    assert(g.trees() == genesis_state(p).trees());
    assert(g.num_accounts == 2);
}
