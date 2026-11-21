use crate::consts::{DS_DOMAIN, DS_MKT_PARAMS, DS_PARAMS, MARKETS, N_ORACLES};
use l3x_types::{config_hash, hash::hash};

/// One market's parameters (SPEC.md §6.6, §8), in ppm. A market is listed when `imr_ppm > 0`.
///   imr, mmr, cmr: initial, maintenance and close-out margin fractions (SPEC.md §8.3);
///   price_band: maximum distance of a limit price from the mark;
///   max_jump: maximum index change per oracle update;
///   mark_band: maximum distance of the mark from the index;
///   maker_fee, taker_fee: fee rates (hundredths of a basis point are ppm);
///   liq_fee: fee on the notional a liquidation closes against the book, paid to the insurance
///   fund (at most 1%, SPEC.md §8.5).
pub struct MarketParams {
    pub imr_ppm: u64,
    pub mmr_ppm: u64,
    pub cmr_ppm: u64,
    pub price_band_ppm: u64,
    pub max_jump_ppm: u64,
    pub mark_band_ppm: u64,
    pub maker_fee_ppm: u64,
    pub taker_fee_ppm: u64,
    pub liq_fee_ppm: u64,
}

impl MarketParams {
    pub fn hash(self) -> Field {
        hash(
            [
                DS_MKT_PARAMS, self.imr_ppm as Field, self.mmr_ppm as Field, self.cmr_ppm as Field,
                self.price_band_ppm as Field,
                self.max_jump_ppm as Field, self.mark_band_ppm as Field, self.maker_fee_ppm as Field,
                self.taker_fee_ppm as Field, self.liq_fee_ppm as Field,
            ],
        )
    }

    pub fn listed(self) -> bool {
        self.imr_ppm > 0
    }
}

/// Exchange parameters committed in config_hash (SPEC.md §6.2).
pub struct Params {
    /// Signing domain: chain and a per-deployment id, so signatures do not replay elsewhere.
    pub chain_id: Field,
    pub instance: Field,
    /// Oracle publisher keys; an update needs `oracle_k` distinct signatures (SPEC.md §8.4).
    pub oracle_pk_x: [Field; N_ORACLES],
    pub oracle_pk_y: [Field; N_ORACLES],
    pub oracle_k: u32,
    /// Maximum index age, in seconds, for risk-increasing actions; funding interval in seconds.
    pub max_age: u64,
    pub funding_interval: u64,
    pub markets: [MarketParams; MARKETS],
}

impl Params {
    pub fn hash(self) -> Field {
        let mut inputs: [Field; 6 + 2 * N_ORACLES + MARKETS] = [0; 6 + 2 * N_ORACLES + MARKETS];
        inputs[0] = DS_PARAMS;
        inputs[1] = self.chain_id;
        inputs[2] = self.instance;
        for i in 0..N_ORACLES {
            inputs[3 + 2 * i] = self.oracle_pk_x[i];
            inputs[4 + 2 * i] = self.oracle_pk_y[i];
        }
        inputs[3 + 2 * N_ORACLES] = self.oracle_k as Field;
        inputs[4 + 2 * N_ORACLES] = self.max_age as Field;
        inputs[5 + 2 * N_ORACLES] = self.funding_interval as Field;
        for m in 0..MARKETS {
            inputs[6 + 2 * N_ORACLES + m] = self.markets[m].hash();
        }
        hash(inputs)
    }

    pub fn domain(self) -> Field {
        hash([DS_DOMAIN, self.chain_id, self.instance])
    }

    pub fn config(self, vk_tree_root: Field) -> Field {
        config_hash(vk_tree_root, self.hash())
    }
}
