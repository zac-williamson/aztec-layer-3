use crate::consts::{DS_DOMAIN, DS_PARAMS};
use l3x_types::{config_hash, hash::hash};

/// Exchange parameters committed in config_hash (SPEC.md §6.2), P1 subset.
pub struct Params {
    /// Signing domain: chain and a per-deployment id, so signatures do not replay elsewhere.
    pub chain_id: Field,
    pub instance: Field,
    /// Oracle publisher key (P1: one publisher).
    pub oracle_pk_x: Field,
    pub oracle_pk_y: Field,
    /// Initial margin rate, maximum distance of a limit price from the index, and maximum change
    /// per oracle update, in parts per million; maximum index age in seconds.
    pub imr_ppm: u64,
    pub price_band_ppm: u64,
    pub max_jump_ppm: u64,
    pub max_age: u64,
}

impl Params {
    pub fn hash(self) -> Field {
        hash(
            [
                DS_PARAMS, self.chain_id, self.instance, self.oracle_pk_x, self.oracle_pk_y,
                self.imr_ppm as Field, self.price_band_ppm as Field, self.max_jump_ppm as Field,
                self.max_age as Field,
            ],
        )
    }

    pub fn domain(self) -> Field {
        hash([DS_DOMAIN, self.chain_id, self.instance])
    }

    pub fn config(self, vk_tree_root: Field) -> Field {
        config_hash(vk_tree_root, self.hash())
    }
}
