//! Stop and take-profit triggers (SPEC.md §6.5): a second tree per market with the order book's
//! layout and node aggregates, keyed by trigger price. An UP trigger fires once the mark rises to
//! its price, a DOWN trigger once the mark falls to it: a stop-loss on a long is a DOWN sell, a
//! take-profit an UP sell, and the mirror image for a short. UP triggers use the ask slot, so the
//! lowest price, earliest first, is leftmost; DOWN triggers use the bid slot, so the highest
//! price, earliest first, is rightmost. One walk then finds the next trigger due in each
//! direction. A fired trigger is an IOC order at its limit price: reduce-only, or, for a stop that
//! opens a position, subject to initial margin when it fires.
use crate::{
    book::{order_index, Sibling, SIDE_ASK, SIDE_BID, walk, Walk, LEFTMOST, RIGHTMOST},
    consts::{BOOK_HEIGHT, DS_TRIGGER},
};
use l3x_types::hash::hash;

pub global DIR_DOWN: Field = 0;
pub global DIR_UP: Field = 1;

/// A resting trigger. `epoch` is its owner's order epoch when placed, so CancelAll voids triggers
/// as it voids orders. A trigger is reduce-only unless `entry`: a stop that opens a position,
/// which fires only if its owner can afford it then (SPEC.md §6.5).
pub struct Trigger {
    pub dir: Field,
    pub side: Field,
    pub account_index: u32,
    pub lots: u64,
    pub limit: u64,
    pub epoch: u64,
    pub entry: bool,
}

impl Trigger {
    pub fn empty() -> Self {
        Trigger { dir: 0, side: 0, account_index: 0, lots: 0, limit: 0, epoch: 0, entry: false }
    }

    /// The leaf value; a trigger with no lots is the empty leaf.
    pub fn leaf(self) -> Field {
        if self.lots == 0 {
            0
        } else {
            hash(
                [
                    DS_TRIGGER, self.dir, self.side + (self.entry as Field) * 2, self.account_index as Field,
                    self.lots as Field, self.limit as Field, self.epoch as Field,
                ],
            )
        }
    }

    pub fn up_lots(self) -> u64 {
        if self.dir == DIR_UP { self.lots } else { 0 }
    }

    pub fn down_lots(self) -> u64 {
        if self.dir == DIR_DOWN { self.lots } else { 0 }
    }
}

pub fn trigger_index(dir: Field, price: u32, seq: u64) -> Field {
    order_index(if dir == DIR_UP { SIDE_ASK } else { SIDE_BID }, price, seq)
}

pub fn trigger_walk(t: Trigger, index: Field, path: [Sibling; BOOK_HEIGHT]) -> Walk {
    walk(t.leaf(), t.up_lots(), t.down_lots(), index, path)
}

/// Replaces the trigger at `index` and returns the new root; `old` must be there now.
pub fn replace_trigger(root: Field, index: Field, old: Trigger, new: Trigger, path: [Sibling; BOOK_HEIGHT]) -> (Field, Walk) {
    let before = trigger_walk(old, index, path);
    assert(before.root == root, "trigger path does not match root");
    let after = trigger_walk(new, index, path);
    (after.root, before)
}

/// The next trigger due in one direction at a tick, or a proof that there is none.
pub struct TriggerTop {
    pub has: bool,
    pub price: u32,
    pub seq: u64,
    pub trigger: Trigger,
    pub path: [Sibling; BOOK_HEIGHT],
}

impl TriggerTop {
    pub fn empty() -> Self {
        TriggerTop { has: false, price: 0, seq: 0, trigger: Trigger::empty(), path: [Sibling { hash: 0, ask: 0, bid: 0 }; BOOK_HEIGHT] }
    }
}

/// The lowest UP trigger's price, or 0 if there is none. With `has`, the trigger at (price, seq)
/// is an UP trigger with none to its left; without, the walk from the rightmost slot, which is
/// never a trigger, sees no UP trigger to its left.
pub fn lowest_up(root: Field, top: TriggerTop) -> u64 {
    if top.has {
        assert((top.trigger.dir == DIR_UP) & (top.trigger.lots > 0), "lowest UP trigger is not one");
        let w = trigger_walk(top.trigger, trigger_index(DIR_UP, top.price, top.seq), top.path);
        assert(w.root == root, "lowest UP trigger path");
        assert(w.asks_left == 0, "not the lowest UP trigger");
        top.price as u64
    } else {
        let w = walk(0, 0, 0, RIGHTMOST, top.path);
        assert(w.root == root, "no UP trigger path");
        assert(w.asks_left == 0, "there are UP triggers");
        0
    }
}

/// The highest DOWN trigger's price, or 0 if there is none; the mirror image of lowest_up.
pub fn highest_down(root: Field, top: TriggerTop) -> u64 {
    if top.has {
        assert((top.trigger.dir == DIR_DOWN) & (top.trigger.lots > 0), "highest DOWN trigger is not one");
        let w = trigger_walk(top.trigger, trigger_index(DIR_DOWN, top.price, top.seq), top.path);
        assert(w.root == root, "highest DOWN trigger path");
        assert(w.bids_right == 0, "not the highest DOWN trigger");
        top.price as u64
    } else {
        let w = walk(0, 0, 0, LEFTMOST, top.path);
        assert(w.root == root, "no DOWN trigger path");
        assert(w.bids_right == 0, "there are DOWN triggers");
        0
    }
}

/// Whether a trigger is due at `mark`, given the lowest UP and highest DOWN trigger prices.
pub fn due(up: u64, down: u64, mark: u64) -> bool {
    ((up > 0) & (up <= mark)) | ((down > 0) & (down >= mark))
}
