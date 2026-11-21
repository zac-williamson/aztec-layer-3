# L3X: confidential order-book exchange rollup on Aztec

Status: draft 0.4, 2026-11-21. Decisions D1–D13 are resolved (§16). Phase P0 (§15) is complete in this repository on Aztec 6.0.0, because the 6.1.0 toolchain is not yet published to the installer or npm; see `README.md`. P1 is under way. Before P0, only the proof-compression proof of concept in [`zac-williamson/rollup-on-aztec`](https://github.com/zac-williamson/rollup-on-aztec) existed (§3). Draft 0.4 records P0's findings: the merge tree and VK tree as built (§9), and a Mode R capacity well below the public-log cap (§9.5, M5). Draft 0.2 incorporated findings from an internal adversarial review; there has been no external review. Target: Aztec `v6.1.0` with its pinned Noir and Barretenberg. "L3X" is a working name. MUST, SHOULD and MAY are used as in RFC 2119. **[D#]** refers to a recorded decision (§16); **[M#]** marks a figure that depends on measurement (§14).

## 1. Purpose and scope

L3X is a central-limit-order-book (CLOB) perpetual futures exchange with Lighter-class latency and throughput, built as an application-specific validity rollup that settles to an Aztec contract. Its distinguishing property is **public confidentiality**: account identities and the fact of their activity are public; values (order prices and sizes, fills, collateral, positions, PnL, leverage) are not. L3X is confidential, not private: amounts are hidden, addresses are not.

Goals, in priority order:

1. Funds safety without trusting the operator: a validity proof for every state transition, and an exit path that needs only Aztec and published data.
2. Exchange-grade performance: millisecond soft confirmations; throughput limited by horizontally scalable proving, not by Aztec.
3. Public confidentiality as bounded in §4.
4. Verifiable matching and risk: price-time priority, margin, funding, fees and liquidation preconditions are enforced by circuits. The book is hidden, so the public cannot audit individual fills, but anyone who checks the proof knows the rules held for the sequenced order flow.

v1 scope: linear perpetuals margined in one collateral token [D7], cross margin, limit and market orders with GTC/IOC/FOK/post-only/GTT and reduce-only, stop and take-profit triggers, oracle index prices, periodic funding, liquidation with an insurance-fund backstop. Perpetuals come first because they need only one asset on Aztec; underlyings enter as oracle prices. Spot, isolated margin, public liquidity pools and multi-collateral are later phases (§15).

Non-goals for v1: confidentiality against the operator; account anonymity; hiding depositor or withdrawal-recipient addresses; decentralized sequencing; hiding when an account's balances change.

Why a rollup and not Aztec contracts: an order as an Aztec transaction costs seconds of client proving plus block inclusion, orders of magnitude from CLOB requirements. Why Aztec and not Ethereum, where Lighter settles:

- deposits and withdrawals move to and from Aztec private balances, with only net totals per custody transaction public (§10.3);
- the exchange composes with private Aztec applications;
- its per-batch market data reaches Aztec contracts with a proof that the exchange's rules were followed.

The costs are an extra layer before L1 finality and Aztec's small data-availability budget (§9.5).

## 2. Roles and trust model

| Role | Responsibility |
| --- | --- |
| Account owner | Controls an account through a master authorization and session keys (§7.2). |
| Operator | Gateway, sequencer, matching and risk engine, provers, settlement and custody transactions. One bonded operator in v1 [D4]. |
| Oracle publishers | Sign index-price updates verified by the circuits [D6]. |
| Aztec | Executes the Bridge contract; provides DA and L1 settlement. |

| Property | Relies on | If violated |
| --- | --- | --- |
| Correct state transitions | Proof soundness | — |
| Custody and exit | Aztec and published DA (§9.5) | — |
| Rules cannot change under users | Immutable Bridge; `upgrade_delay` on configuration (§12) | Exit before a change takes effect |
| Liveness, non-censorship of requests | Operator | Priority requests with deadlines, then desert mode (§12) |
| Deposit acceptance | Operator | Unswept deposits are reclaimable (§10.3) [D13] |
| Confidentiality against the public | Circuits, DA format, custody design (§4) | — |
| Confidentiality against the operator | Not provided in v1 | — |
| Fair ordering | Operator | Receipts make post-receipt reordering provable (§11); pre-receipt front-running is not prevented |
| Timely liquidation | Operator | Risk sweep bounds the delay (§8.7, phase 3) |
| Index prices, desert valuation | Oracle publishers, within circuit-enforced bounds (§8.4) | Market halts on stale or out-of-bounds updates |

The operator sees every order and balance in plaintext, as a centralized exchange or Lighter's sequencer does. It cannot produce an invalid state, take funds, redirect refunds or exits, or prevent exits.

## 3. Baseline: `rollup-on-aztec`

The proof of concept (commit `abe9286`, pinned to Aztec `v4.0.0-devnet.2-patch.1`):

```
client circuit (UltraHonk ZK) ×10
  → batch_app: verify 10 proofs, output pedersen(y_1..y_10)  ┐
  → init_kernel → tail_kernel → hiding_kernel                ┘ one Chonk IVC proof
  → tube: verify the Chonk proof (proved with the noir-rollup target)
  → MiniRollup.verify_batch (private): verify_honk_proof against a stored VK hash
```

Chonk is used because UltraHonk verification inside a Mega circuit defers its group operations to Goblin's ECCVM, which is far cheaper than performing them with non-native arithmetic inside UltraHonk. L3X keeps this for the client-proof lane (§7.4) and generalizes the single sequential batch into a parallel aggregation tree (§9.2).

Gaps that MUST be closed before the pipeline secures value:

| # | Gap | Change |
| --- | --- | --- |
| G1 | The tube is proved with `noir-rollup` (RollupHonk: carries an IPA claim and proof), but `verify_batch` calls `verify_honk_proof`, which accepts only UltraHonk ZK proofs. `prove_e2e.ts` never deploys or calls the contract. | Add a root circuit that verifies the tube with `verify_root_rolluphonk_proof` (new in v6 `bb_proof_verification`; closes the IPA accumulator), proved as UltraHonk ZK for `verify_honk_proof`. bb requires the root to accumulate exactly two IPA claims ("Root rollup must accumulate two IPA proofs"), so the root verifies two RollupHonk proofs. A single-segment batch pairs its tube with a padding segment (§9.2). Implemented in P0. |
| G2 | Verification keys are free witnesses at every inner layer: the client VK in `batch_app`, `app_vk` in `init_kernel`, `kernel_vk` in `tail_kernel` and `hiding_kernel`, and the Chonk VK in `tube`. Only the tube's VK hash is fixed (in the contract). A prover can substitute any inner circuit and emit any `batch_hash`. | Every recursive verification MUST pin the child VK hash, by a circuit constant or by membership in a role-specific VK subtree whose root the Bridge checks (§9.3). Implemented in P0: the Chonk chain and the tube pin constants; merges and the root check membership in the VK tree. |
| G3 | The contract keeps no state: no state root, no replay protection, public inputs bound to nothing on-chain. | Bridge contract (§10). |
| G4 | Fixed shape: exactly 10 proofs of one circuit, no padding, one sequential IVC. | Variable occupancy with VK membership and dummy padding; segment and merge tree (§9.2). Implemented in P0: any number of segments, merged pairwise, with padding for a single segment. The client subtree still has one member, pinned as a constant in `agg_app`. |
| G5 | Version drift. v6.1 renumbered proof types (`HN = 2`, `HN_FINAL = 7`, `CHONK = 8`; `HN_TAIL` no longer exists), so the PoC's `HN_TAIL = 8` would now select Chonk and its `CHONK = 9` is undefined. Sizes changed: Mega app and kernel VKs are 151 fields, the Chonk VK is 119 (PoC: 127), a Chonk proof is 1,193 fields plus the hiding kernel's public IO (PoC: 1935; README: 1632), and an UltraHonk ZK recursive proof is 458. The contract comment also says Poseidon2 where the circuits use Pedersen. | Regenerate every constant from v6.1 `constants.nr`; use Poseidon2 throughout (§6.1). |

## 4. Privacy boundary

| Data | Public | Operator | Counterparty |
| --- | --- | --- | --- |
| Account index, owner Aztec address, master authorization, account class, creation | yes | yes | no |
| That an account's collateral or positions changed in batch *b* | yes | yes | no |
| Which position slots changed | no | yes | no |
| Order placement, cancel, modify; price, size, type | no, unless displayed [D1] | yes | no |
| Fill price and size | per-batch market summary only [D1] | yes | price and size of its own fill |
| Who traded with whom | no | yes | no |
| Collateral, positions, entry prices, PnL, leverage, funding paid, liquidation of an account | no | yes | no |
| Session keys, nonces, fee tier | no | yes | no |
| That a deposit or withdrawal occurred; its Aztec block | yes | yes | no |
| Deposit amount | no; only the net vault change per custody transaction (§10.3) | yes | no |
| Withdrawal amount | no (inside the custody net); yes for claims paid directly from the vault (§10.4) | yes | no |
| Depositor and withdrawal-recipient Aztec addresses | not protected; treat as public | yes | no |
| Index, mark, funding rate, cumulative funding | yes | yes | yes |
| Best bid and ask prices; per-batch last, VWAP, high, low | yes [D1] | yes | yes |
| Volume, open interest, insurance fund | bucketed or hidden [D1] | yes | no |
| Vault balance (total swept collateral) | yes | yes | yes |

The owner sees everything about its own account.

Rules:

- The DA payload MUST NOT contain plaintext values. Each account diff is a hiding leaf commitment plus ciphertexts under the owner's key (§9.5). Changed position slots are encrypted as (slot, value) tuples padded to a minimum count, so the slot identity, and with it the market, is hidden.
- Every public output MUST be a market-level aggregate (§8.4). No public output may depend on a single account's values, except orders whose owner opts into display.
- Order activity MUST NOT be published. Orders, nonces and session keys live in trees whose leaves never enter DA (§6.4, §6.5), so the public learns when an account's balances change, not when it quotes.
- Counterparty pairing MUST NOT be derivable from public data. The set of accounts touched in a batch is public; their pairing is not.
- Custody transactions MUST NOT create notes addressed to any party whose viewing key is public; intermediate notes go to operator-keyed transit escrows (§10.3).

Residual leakage:

- per-account timing and frequency of balance changes;
- counts of touched accounts, padded slot tuples, nullifiers, notes and logs;
- deposit and withdrawal timing, net custody flows, and the vault total;
- top-of-book and print prices.

Sparse activity enables inference, for example when one account changes in a batch whose print moved. A formal leakage analysis is outstanding.

This is confidentiality against the public, not against the operator. Removing operator visibility (threshold-encrypted order flow, MPC or TEE matching) is research (§15, phase 4).

## 5. Architecture

```
 Users ── signed actions, client proofs (encrypted) ──▶ Gateway ─▶ Sequencer ─▶ Engine ──▶ journal
   ▲                                                       │ receipts (ms)              │
   └───────────────────────────────────────────────────────┘                            ▼
                                       witness generation ─▶ segment provers ─▶ merge tree ─▶ root prover
                                                                                                  │
 Users ── register, deposit, forced requests ─▶ Aztec: Bridge ◀── settle(header, root proof, DA) ──┘
                                                      ▲
 Operator ── custody (sweep deposits, pay withdrawals) ┘
```

- **Gateway**: decrypts envelopes, pre-checks signatures and limits.
- **Sequencer**: assigns each accepted action a global sequence number and an L3 block (an ordering interval of 10–50 ms) and returns a signed receipt (§11).
- **Engine**: a deterministic state machine with circuit-identical semantics (widths, rounding, ordering). Its journal is the witness source. A divergence makes a batch unprovable, so the circuits are normative and CI MUST replay engine journals through circuit execution.
- **Provers**: segment proofs in parallel, then merges, then one root proof per batch.
- **Settler and custodian**: one settlement transaction per batch, and custody transactions that sweep deposits and pay withdrawals (§10.3). Batches chain by state root, so a pruned Aztec block only delays settlement: the proof stays valid while its `prev_state_root` is current.

| Finality | Event | Latency |
| --- | --- | --- |
| F0 accepted | sequencer receipt | p99 < 10 ms target [M] |
| F1 proven | root proof of the batch | bounded by prover capacity [M] |
| F2 settled | settlement in an Aztec L2 block | + one Aztec block |
| F3 checkpointed | Aztec checkpoint on L1 | ≤ one 72 s slot + L1 inclusion |
| F4 final | Aztec epoch proof on L1 | ≤ 32 slots (≈ 38 min) + proving |

Trading uses F0. Withdrawals pay at F2 and are final at F4. A deposit is credited once the custody transaction that swept it reaches F3 (default) or F4 (safest). An Aztec prune between F3 and F4 can remove a credited deposit; the operator bears that residual risk.

## 6. State

### 6.1 Conventions

Hashes are Poseidon2 over the BN254 scalar field with distinct domain separators `DS_*`. Widths are enforced by range checks: price ticks `u32`, lots `u48`, signed size `i64`, collateral and notional in token base units `i128`, funding indices `i128` scaled by 10^18. Every rounding goes against the account and its remainder goes to the insurance fund, so conservation is exact.

### 6.2 State root

```
StateRoot  = H(DS_STATE, trees, priority_cursor, batch_number, last_time)
trees      = H(DS_TREES, accounts_root, other_root)
other_root = H(DS_OTHER, activity_root, markets_root, refresh_cursor)
```

Segments carry `trees` as one field of their running values (§9.1). The root circuit opens it to expose `accounts_root` (§9.4). P0 has no activity or markets tree and uses `other_root = 0`.

Configuration is not part of the state. Each batch proves against the `config_hash` that the Bridge holds when it settles (§9.4, §10.2). That hash commits to `chain_id`, the Bridge address, the role-partitioned VK tree root, market parameters, fees, oracle publishers, the operator encryption key and the protocol deadlines. Its preimage is published on-chain whenever a change is scheduled.

### 6.3 Accounts tree (published commitments)

Height 32, indexed by `account_index`, assigned sequentially at registration.

```
AccountLeaf = H(DS_ACCT, pub_hash, priv_hash)
pub_hash    = H(DS_ACCT_PUB, owner, master_auth, enc_key_commitment, class)
priv_hash   = H(DS_ACCT_PRIV, collateral, positions[P_MAX], blind)
Position    = (market_id, size, entry_notional, funding_snapshot)
blind       = H(DS_BLIND, k_enc, account_index, batch_number, da_nonce)
```

- **Public part.** `owner` is an Aztec address. `class` is `user`, `insurance` or `fee`; it is static and MUST NOT encode risk or liquidation state. The insurance account is also the liquidation backstop. The public part is published in clear whenever it changes.
- **Positions.** `P_MAX` (default 16) bounds open markets per account. Positions are a flat array, so a margin check opens one leaf.
- **Encryption key.** `enc_key_commitment = H(DS_ENC, k_enc)`. `k_enc` is a symmetric key the owner shares with the operator at registration (§10.1). The circuits use it to derive `blind` and to encrypt the account's DA entries, so the owner can always reconstruct its own leaf opening. Wallets SHOULD derive `k_enc` from their seed, so that losing device state does not lose it.
- **Re-proving.** `batch_number` and `da_nonce` (§9.4) refer to the batch that last wrote the leaf. The re-encrypted opening in each DA entry includes `blind`, so the owner does not need to track them.

### 6.4 Activity tree (never published)

Same indexing. It holds what trading needs but exit does not:

```
ActivityLeaf = H(DS_ACTV, keys_root, open_bid_lots[P_MAX], open_ask_lots[P_MAX],
                 open_order_count, fee_tier, blind_a)
KeyLeaf      = H(DS_KEY, pubkey, permissions, expiry, nonce)
```

`keys_root` is a height-8 tree: up to 256 session keys per account, matching Lighter's 255 API-key slots, so market makers can parallelize across keys. A slot's `nonce` is never reset when its key changes. Keeping keys, nonces and open-order lots here means quoting changes no published leaf (§4).

### 6.5 Order books

Each market has a price-keyed sparse Merkle tree of resting orders, following Lighter's order-book tree:

```
leaf index = price_ticks · 2^48 + seq                 asks
           = price_ticks · 2^48 + (2^48 − 1 − seq)    bids
OrderLeaf  = H(DS_ORDER, side, account_index, remaining_lots, flags,
               client_order_id, expiry, blind_o)
Node       = H(DS_NODE, left, right, ask_lots, bid_lots, ask_quote, bid_quote)
```

`price_ticks` is 32 bits and `seq` (the sequencer's global sequence number) is 48 bits, so the tree has 80 levels; its root is in the market's leaf (§6.6). Every internal node carries the resting ask and bid lots and quote notional beneath it. A book is never crossed, so bids occupy lower indices than asks. The best ask is the leftmost ask and the best bid the rightmost bid; within a price, earlier orders come first.

- **Priority**: walking one root-to-leaf path and summing opposite-side lots in the sibling subtrees gives the crossing volume ahead of a position. A resting insert requires zero crossing volume; a match against maker order *o* requires zero same-side volume ahead of *o*. Each step costs one 80-level path.
- **Depth**: the same sums prove the impact price used by the mark (§8.4) and any bucketed depth published under [D1].
- **Fill, cancel**: update the leaf (emptied on removal) and its path.
- **Expiry**: an expired GTT order met during matching is removed instead of filled.
- **Triggers**: stop and take-profit orders live in a second per-market tree with the same layout, keyed by trigger price. Triggers are evaluated only at mark ticks (§8.4), and the mark does not change between ticks, so firing a trigger cannot cascade within a tick. At each tick the circuit sets the market's `trigger_pending` flag if the aggregates show any trigger due at the new mark. While the flag is set, the market accepts only trigger firings and cancels; the flag clears when the aggregates show none due.

Order leaves never enter DA, and open orders are void in desert mode. An account may hold at most 1,000 open orders.

### 6.6 Markets tree

```
MarketLeaf = H(DS_MKT, market_id, book_root, trigger_root, trigger_pending,
               index_price, index_time, mark_price, cum_funding, funding_rate,
               last_funding_time, premium_acc, oi_long, oi_short, print_acc)
```

Market parameters come from `config_hash`. Invariant: `oi_long == oi_short` after every action.

## 7. Transactions

### 7.1 Envelope

```
Action = { kind, account_index, key_id, nonce, expiry, payload }
msg    = H(DS_ACTION, chain_id, bridge_address, auth_id, Action)
```

`chain_id` and `bridge_address` come from the configuration. `auth_id` is the signing public key for lane S or the client circuit's VK hash for lane P, so a signature or proof cannot be replayed under a different key or circuit. An action carries exactly one authorization:

- **S**: a Schnorr signature over Grumpkin, with a Poseidon2 challenge, on `msg` by the key in slot `key_id`. Verification costs one two-point embedded-curve MSM and one Poseidon2 hash.
- **P**: a client proof (§7.4) whose public inputs are `(msg, account_index, auth_binding)`. The segment requires `master_auth == H(DS_MAUTH, vk_hash, auth_binding)`, and requires that the configuration permits that circuit to authorize this action kind.

`nonce` MUST equal the slot's stored nonce plus one. Parallelism comes from multiple keys, not nonce gaps. Actions reach the gateway under transport encryption plus envelope encryption to the operator key, and are never published.

Signers MUST derive Schnorr nonces deterministically, hedged with fresh randomness in the manner of RFC 6979. In November 2026, third-party signing software for Lighter reused nonces, and the trader's API key was recovered from publicly exposed signatures. L3X never publishes signatures, which removes that exposure, but signers must still be sound.

### 7.2 Authorization levels

| Level | Covers | Default |
| --- | --- | --- |
| Trade | place, cancel, modify, cancel-all | session key (S), scoped by markets, maximum order notional and expiry |
| Withdraw | withdrawals, transfers | master authorization |
| Admin | keys, `k_enc` rotation, master authorization | master authorization |

`master_auth` is one of:

- a Grumpkin master key (lane S);
- the hash of a client-proof circuit's VK and its parameters (lane P), for example P-256 passkeys, multisig or social recovery;
- the owner's Aztec account, by submitting the action as a priority request through the Bridge (slow, but inherits the Aztec account's authorization).

### 7.3 Kinds

| Kind | Payload |
| --- | --- |
| `PlaceOrder` | market, side, limit price, lots, type (limit, or market with a worst price), TIF (GTC, IOC, FOK, post-only, GTT), reduce-only, trigger, display [D1], client order id |
| `CancelOrder` | market, order reference |
| `CancelAll` | optional market |
| `ModifyOrder` | order reference, price, lots; time priority kept only if lots decrease and price is unchanged |
| `Withdraw` | amount, recipient Aztec address (§10.4) |
| `Transfer` | destination account, amount (phase 2) |
| `AddKey`, `RevokeKey` | key slot, public key, permissions, expiry |
| `RotateEncKey`, `SetMasterAuth` | new commitment or authorization; a new `k_enc` is delivered to the operator encrypted |

Priority requests are queued on the Bridge (§10.1):

- `Register` and the forced requests `ForcedCancelAll`, `ForcedClose(market, worst_price)` and `ForcedWithdraw(recipient)` (all free collateral). Users submit these directly; each pays `request_fee`.
- `Deposit`. Only a custody transaction appends these, and only once the deposit's funds are in the vault (§10.3).

Each queue entry binds the submitting `msg_sender`, which the circuit checks against the account owner. Payloads MAY be encrypted to the operator key in the configuration; the circuit then proves correct decryption, so the operator cannot discard a request as unreadable.

Every priority request is either executed or rejected under a rule the circuit checks. Any condition the circuit could not decide is checked by the Bridge at submission instead; for example, `register` asserts that `k_enc` matches `enc_key_commitment`.

Operator actions are signed by the operator key and recorded in the action log like any other action: oracle updates, mark ticks, funding ticks, trigger firings, liquidation steps, fee-tier changes and risk-sweep checks. Each carries the circuit-checked precondition that justifies it.

### 7.4 Client-proof lane

This is the `rollup-on-aztec` mechanism, generalized. Users submit UltraHonk ZK proofs; the operator verifies up to 10 per Chonk app circuit [M1, M2]. The aggregation circuit:

- proves each proof's VK membership in the client subtree of the VK tree;
- fills unused slots with a fixed dummy proof;
- outputs each proof's `vk_hash` together with its public inputs, so segments can bind the circuit to the account (§7.1).

Default uses [D9]: master authorization (passkeys, multisig, recovery), session-key grants, withdrawals, and credentials, for example a zkPassport-style jurisdiction proof that sets an account flag a market requires.

Per-order client proofs are valid under the envelope but are not the default path. They add client proving time and a recursive verification per action, where a session key costs one embedded-curve signature check. A market maker replacing quotes many times a second cannot afford that. One proof that grants a session key authorizes many fast signed actions.

Client proofs MUST be zero-knowledge when their witness is private from the operator. The root proof is UltraHonk ZK, verified with `verify_honk_proof`. A non-ZK root with `verify_honk_proof_non_zk` is acceptable only when the operator proves its own settlement transactions, because the root proof is then a private input that never leaves the operator.

## 8. Exchange semantics

Defaults follow Lighter where it documents them (§13), pending risk review.

### 8.1 Matching

Continuous price-time priority [D5]. A taker action consumes the best opposite order (§6.5) until it is filled, its limit is crossed, or `MAX_FILLS_PER_ACTION` (default 64) is reached; all steps of one action are proved in one segment.

- Self-trade prevention: the default cancels the resting order and continues; other modes are per-order flags.
- Post-only orders that would cross are rejected; IOC remainders cancel; FOK reverts unless fully filled.
- Reduce-only orders cannot increase |position|; resting reduce-only orders are trimmed when the position shrinks.
- Limit prices more than `price_band` (default ±5%) from the mark are rejected.
- Sequencer delay policies, such as Lighter's 300 ms taker and cancel delays on its zero-fee tier, are permitted but not proven. They are disclosed per tier.

### 8.2 Fill

A fill of `q` lots at price `p` between maker and taker atomically updates both positions (realizing PnL against `entry_notional` on reduction), both collaterals net of fees, both activity leaves' open lots, `oi_long` and `oi_short`, and the market's print accumulator (VWAP numerator and denominator, high, low, last).

### 8.3 Margin

```
equity  = collateral + Σ_m [ size_m·mark_m − entry_notional_m − size_m·(cum_funding_m − funding_snapshot_m) ]
worst_m = max(|size_m + open_bid_lots_m|, |size_m − open_ask_lots_m|)
IM      = Σ_m worst_m·mark_m·imr_m
MM      = Σ_m |size_m|·mark_m·mmr_m
CM      = Σ_m |size_m|·mark_m·cmr_m
```

Default fractions follow Lighter: `imr = 1/max_leverage` (2% at 50×), `mmr = 0.6·imr`, `cmr = 0.4·imr`. A risk-increasing order requires `equity ≥ IM` after the action; below IM only risk-reducing actions are accepted. Withdrawals and transfers require `equity − amount ≥ IM` and `collateral ≥ amount`. `equity < MM` makes an account liquidatable (§8.5).

### 8.4 Time, index, mark, funding, public market data

- **Time**: every L3 block carries a timestamp. Timestamps never decrease, and the Bridge requires each batch's last timestamp to be within `T_lag` (default 15 min) of Aztec time (§10.2). L3 time therefore trails real time by at most `T_lag`, and every age and expiry below is bounded in real time.
  - A block that advances time by more than `max_block_gap` (default 2 s) may carry only oracle updates and ticks, and funding does not accrue across that gap.
  - An operator halt or outage therefore resumes with one catch-up block. Stale indices then block risk-increasing orders until fresh updates arrive.
- **Index**: from signed oracle updates included in L3 blocks [D6]. The circuit verifies k-of-n publisher signatures, increasing timestamps, age ≤ `max_age` against L3 time, and per-update change ≤ `max_jump`. Failing updates are rejected; a market whose index is stale halts risk-increasing orders.
- **Mark**: recomputed at mark ticks, which are oracle updates, at most once per second. As Lighter, `median(impact_mid, index·(1 + clamp(ema_8min(premium), ±0.5%)), external_mark)`, then clamped to `index·(1 ± mark_band)` (default 2%).
  - `impact_mid` is proved from the book aggregates at an impact notional of `500 / imr` collateral units.
  - `external_mark` is the median of centralized-exchange marks supplied by the oracle publishers.
  - Any trader can move prints and the impact component, including accounts the operator controls. The clamp bounds what that can achieve.
- **Funding**: hourly and peer-to-peer. As Lighter, `rate = clamp(P + clamp(r − P, ±0.05%), ±4%) / 8` with `r = 0.01%`, which caps funding at 0.5% per hour.
  - `P` is the time-weighted premium, sampled every second rather than at a sequencer-chosen random minute, so sampling needs no trusted randomness.
  - Each interval, `cum_funding += rate·mark`.
  - Positions settle funding lazily when touched, and equity always includes accrued funding.
- **Public output**: per batch and market, the header's `market_data` carries index, mark, funding rate, cumulative funding, best bid and ask prices, and the print summary [D1]. Consumers should treat these as the prices of one venue: proven to follow the rules, not proven sound.

### 8.5 Liquidation

The waterfall follows Lighter's. For each step the circuit checks the precondition at current marks:

1. `equity < MM`: cancel all the account's orders, then close positions against the book with IOC orders at a limit price that keeps the account's equity-to-requirement ratio constant, charging a fee of at most 1% to the insurance account;
2. `equity < CM`, or the book cannot absorb: the insurance account takes over positions, lowest unrealized PnL first, provided it stays above its own IM;
3. backstop exhausted: auto-deleverage opposing positions ranked by leverage and unrealized PnL. The circuit verifies the ranking from the start of phase 3; before that, ADL counterparty choice is the operator's, as it is on Lighter.

### 8.6 Fees

Maker and taker rates in hundredths of a basis point, by fee tier. Tiers are stored privately and set by the operator. Fees credit the fee account (class `fee`). Zero-fee tiers are allowed.

### 8.7 Risk sweep (phase 3)

Proofs show that every liquidation performed was justified, not that every due liquidation happened. A `risk_cursor` advancing over account indices obliges each batch to check `Q` accounts at current marks (proving `equity ≥ MM` or liquidating), so every account with a position is checked at least every `R` batches [M6].

### 8.8 Conservation

Every action conserves collateral exactly across the touched accounts, the fee account and the insurance account, and preserves `oi_long == oi_short`; funding is zero-sum per market. With custody accounting (§10.3) this gives, at any common set of marks:

```
Σ_accounts equity = vault − swept-but-unprocessed deposits − settled-but-unpaid withdrawals and refunds
```

Unrealized PnL and funding sum to zero across accounts, so `Σ equity` equals net credited deposits. It is therefore never negative, and the vault always covers the two senior terms.

## 9. Batches, proving, data availability

### 9.1 Units

- **L3 block**: an ordering interval with a header (time, oracle updates, action-log root). Receipts reference it.
- **Segment**: a contiguous run of actions proved as one unit. It proves a transition of running values, `Running`:
  - `trees` (§6.2);
  - the action-log hash chain;
  - the priority-queue head and cursor, which advance by folding each consumed entry;
  - the DA sponge state and length (§9.5);
  - the withdrawal-record hash chain and count;
  - L3 time.

  The action log, DA and withdrawals start empty in every batch. Market data is read from the markets tree at the end of the batch.
- **Batch**: consecutive L3 blocks settled by one Aztec transaction.

### 9.2 Circuits

```
X-segment  UltraHonk, rollup target  signed actions, matching, oracle, funding, liquidation
P-segment  Chonk IVC → tube          agg_app (≤10 client proofs) → kernel → exec_app → kernel … → hiding kernel
                └───────────── RollupHonk proofs ─────────────┘
merge      UltraHonk, rollup target  verify_rolluphonk_proof ×2; child VKs in allowed roles; left.end == right.start; IPA claims accumulated
root       UltraHonk ZK              verify_root_rolluphonk_proof ×2 (closes IPA); batch rules; output H(BatchHeader)
Bridge     Aztec private function    verify_honk_proof against root_vk_hash
```

- Every merge-tree node, segment or merge, has the same public output, `NodeOutput = (config_hash, start: Running, end: Running)`. A merge can therefore verify any child; the child's VK-tree role decides what is allowed (§9.3).
- The root is the top merge. bb requires it to accumulate exactly two IPA claims, so it always verifies two RollupHonk proofs. A batch with a single segment pairs it with a padding segment: a trivial circuit whose transition is the identity, proved with the rollup target, which carries bb's default IPA claim.
- Segments without client proofs SHOULD be X-segments, which avoid Chonk and the tube. X-segments enter the merge tree directly: a circuit proved with the rollup target that verifies no proof carries bb's default IPA claim, as padding does [M7, measured in P0].
- Within a segment, touched leaves and tree nodes are read once into in-circuit RAM, mutated there, and written back once at the end. A market maker's repeated actions on its own account cost RAM operations, not Merkle paths. Order-book paths still cost one 80-level path per matching step.
- Segments are proved in parallel: the engine has already computed every intermediate root.

### 9.3 Verification-key discipline

The VK tree, whose root is committed in `config_hash`, is partitioned by role: segments, merges, Chonk apps and kernels, tubes, and client circuits. Every circuit that verifies a proof MUST pin the child VK hash, by constant or by membership in the subtree for the role it expects, so a merge cannot accept a client proof as a child. The root circuit takes the VK tree root from the configuration it commits to in the header. The Bridge checks that configuration against its own `config_hash` and stores only the root VK hash. This closes G2.

As built in P0:

- The tree has height 6: eight roles (client, Chonk, tube, segment, merge, and three reserved) of eight slots each, at leaf index `role·8 + slot`. Leaves are VK hashes; empty slots are zero.
- `config_hash = H(DS_CONFIG, vk_tree_root, params_hash)`.
- Merges and the root accept children in the tube, segment and merge subtrees only. A merge verifies merges, so it cannot contain its own VK hash as a constant; it takes the VK tree root as a witness bound by `config_hash`.
- Circuits with a single possible child, the Chonk chain and the tube, pin that child's VK hash as a constant.
- bb constrains `hash(vk) == vk_hash` inside every recursive verification, so a child cannot present one VK and claim another's tree slot.

### 9.4 Batch header

```
BatchHeader {
  prev_state_root, new_state_root, new_accounts_root, batch_number,
  l3_block_range, min_time, max_time,
  priority_start, priority_end, priority_head_start, priority_head_end,
  withdrawals_root, withdrawals_count, action_log_root, da_hash,
  market_data, config_hash
}
da_nonce = H(DS_DANONCE, prev_state_root, action_log_root)
```

`min_time` is the L3 time at the start of the batch, which is the previous batch's `max_time`; `max_time` is the time of its last block.

The root proof has one public input: `H(DS_HEADER, BatchHeader)`. The root circuit proves that:

- `new_state_root` opens to `new_accounts_root`, so exits can use published data alone;
- folding exactly `priority_end − priority_start` consumed entries from `priority_head_start` yields `priority_head_end`;
- every segment used the configuration in `config_hash`;
- the action log, DA and withdrawals started empty, and the DA sponge finalizes to `da_hash`.

`da_nonce` makes every encryption specific to one attempt. If a batch is re-proved with different contents after an Aztec prune, the two payloads use different keystreams.

### 9.5 Data availability

The DA payload of a batch has three parts.

1. **Change entries**, one for every account whose `AccountLeaf` changed (final state). Each entry contains:
   - `account_index`, the public part in clear (only if it changed), and the new `AccountLeaf`;
   - ciphertexts `ct_i = pt_i + KS(k_enc, account_index, batch_number, da_nonce, i)`.

   The plaintext is the new collateral, the changed positions as `(slot, position)` tuples padded to at least `D_MIN = 2` tuples, `blind`, and the fields and salt of any withdrawal or refund record the account created in this batch.
2. **Refresh entries.** `refresh_cursor` advances so that every account, active or not, receives a fixed-size refresh entry at least once per `W` (default 14 days, inside Ethereum's ~18-day blob retention). A refresh entry is the leaf commitment and the full encrypted opening, padded to `P_MAX` positions.
3. **Withdrawal hashes**: one blinded record hash per withdrawal or refund (§10.4).

`da_hash` is a Poseidon2 sponge of rate 3 over the payload in order, finalized with the payload length. Segments carry the sponge state in `Running`, so the payload may split anywhere between segments; the Bridge recomputes the hash over the flat payload.

`KS` is a Poseidon2 keystream. Plaintext values are packed into as few fields as possible. The circuit proves that every ciphertext encrypts the true values under the key committed in `enc_key_commitment`, so the operator cannot publish garbage. A typical change entry (collateral plus one position) is 4–6 fields; a refresh entry is about 2 + 2·`P_MAX` fields [M8].

DA published within any window of length `W` therefore suffices to rebuild the whole accounts tree and every owner's opening. A user who has lost all local state can still exit (§12). Activity and order trees are not published. The operator MAY also publish snapshots for faster sync; nothing depends on them.

| Mode [D3] | Where | Capacity | Exit relies on |
| --- | --- | --- | --- |
| R (default) | public logs of the settlement transaction | bounded by the per-transaction DA gas admission limit, below the 4,096-field public-log cap (see below); shared with `market_data` | Aztec, hence Ethereum, DA |
| E | Ethereum blobs posted through an L1 inbox; bound to `da_hash` by a KZG point evaluation (checked on L1 by the precompile and in the root circuit by barycentric evaluation) and relayed to the Bridge by L1→L2 message | blob market | Ethereum DA; adds L1→L2 latency |
| V | committee; k-of-n signatures on `da_hash` verified in the root circuit | unbounded | committee honesty |

Mode R capacity [M5]. Public logs are capped at `FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH` = 4,096 fields per transaction, including two header fields per log. The binding limit is lower: a node admits a transaction only if its DA gas fits `ceil(1.5 · B / blocks_per_checkpoint)`, where `B` is the checkpoint's blob space net of encoding overhead (`stdlib` `computeNetworkTxGasLimits` in v6.0.0). A settlement spends 30 fields of DA on its own effects. That leaves:

- about 3,640 payload fields at 10 blocks per checkpoint (72 s slots, 6 s blocks);
- 1,714 payload fields on the 6.0.0 local network (21 blocks per checkpoint), measured.

DA scales with distinct accounts whose balances change in a batch, not with trades. One full Mode R settlement per 72-second slot carries roughly 600–900 change entries (≈ 1.6 KB/s) at 10 blocks per checkpoint.

For calibration, Lighter publishes unencrypted diffs and was measured at about one 128 KB blob per batch commit, with commits every ~3.5 min (≈ 0.6 KB/s). L3X entries are larger, so Mode R supports an account-change rate of the same order as Lighter's today.

Refresh costs `N_accounts · (2 + 2·P_MAX) / (W / slot)` fields per batch: about 200 at 100,000 accounts and about 2,000 at one million (`P_MAX = 16`, `W` = 14 days). A full payload also occupies about 15% of Aztec's network-wide budget of `BLOBS_PER_CHECKPOINT × FIELDS_PER_BLOB` = 24,576 fields per slot, so its price depends on Aztec's fee market [M5]. Mode E is the path beyond either limit.

## 10. Aztec contracts

### 10.1 Bridge

| Storage | Type | Use |
| --- | --- | --- |
| `state_root`, `accounts_root`, `batch_number`, `last_time`, `priority_cursor` | `PublicMutable` | exchange tip |
| `root_vk_hash`, `config_hash`, `operators` | `DelayedPublicMutable` | readable in private; changes take effect after `upgrade_delay`. A `DelayedPublicMutable` cannot be set without its delay, so the genesis values live in `PublicImmutable` and apply until a scheduled change takes effect. |
| `priority_count`, `priority_head[n]`, `priority_time[n]` | `PublicMutable`, `Map` | priority queue as hash-chain prefixes, `priority_head[0] = 0` |
| `pending_deposit[h]` | `Map` | deposits awaiting sweep: submission time and status |
| `withdrawals_root[batch]`, `settled_time[batch]`, `market_data_hash` | `Map`, `PublicMutable` | settled withdrawal lists, settlement times, latest market data |
| desert state | `PublicMutable`, `Map` | flag, frozen `accounts_root`, `market_data_hash` and `config_hash`, claim window, claims (§12) |

| Function | Context | Behaviour |
| --- | --- | --- |
| `register(master_auth, enc_key_commitment, k_enc)` | private | asserts `H(DS_ENC, k_enc) == enc_key_commitment`; charges `request_fee`; queues `Register` with `owner = msg_sender`; delivers `k_enc` to the operator by constrained on-chain delivery |
| `deposit(account_index, amount, refund_to, sk_d)` | private | §10.3 |
| `submit_forced(request)` | private | charges `request_fee`; queues the request with `msg_sender`, optionally encrypted |
| `settle(header, proof, vk, da_payload, da_len)` | private | asserts `msg_sender ∈ operators` and `header.config_hash == config_hash`; checks `da_hash` over the first `da_len` fields; `verify_honk_proof(vk, proof, [H(header)], root_vk_hash)`; `enqueue_self._apply(header, da_payload, da_len)` |
| `schedule_upgrade(vk_tree_leaves, params_hash, root_vk_hash)` | public, operator | recomputes `config_hash` from the preimage, schedules it and `root_vk_hash` together, and publishes the preimage |
| `schedule_operator(operator)` | public, operator | schedules a new operator |
| `_apply(header, da_payload)` | public, only-self | §10.2 |
| `custody(…)` | private, operator | §10.3, §10.4 |
| `reclaim_deposit(record)` | private | §10.3 |
| `claim_withdrawal(batch, record, path)` | private | §10.4 |
| `activate_desert`, `desert_refund`, `exit_register`, `exit_withdraw` | public or private | §12 |

No Bridge function may change the Bridge's own contract class (§12). Configuration changes publish the new configuration's preimage as a public event when they are scheduled.

### 10.2 `_apply`

`_apply` MUST assert:

1. not in desert mode; `header.prev_state_root == state_root`; `header.batch_number == batch_number + 1`;
2. `header.priority_start == priority_cursor`, `header.priority_end ≤ priority_count`, `priority_head[priority_start] == header.priority_head_start` and `priority_head[priority_end] == header.priority_head_end`;
3. if `priority_end < priority_count`, then `priority_time[priority_end] ≥ now − T_force`, so no request older than `T_force` is left behind;
4. `last_time ≤ header.min_time ≤ header.max_time ≤ now` and `header.max_time ≥ now − T_lag`;
5. the payload's `da_hash`, checked in `settle` rather than here: the enqueued call's calldata is bound to `settle`'s arguments, so `_apply` receives exactly the payload that was checked, and hashing it costs client-proving gates instead of public gas.

It then:

- emits `[DA_LOG_TAG, batch_number, payload…]` as one public log;
- updates `state_root`, `accounts_root`, `batch_number`, `last_time` and `priority_cursor`;
- stores `withdrawals_root[batch_number]`, `settled_time[batch_number]` and `market_data_hash`;
- emits `market_data` as a public event, roughly 8 fields per market from the same 4,096-field log budget.

`settle` checks `config_hash` in the private phase. The value is a `DelayedPublicMutable`, so the transaction expires before any scheduled change can take effect.

### 10.3 Custody [D2]

The default profile is **C1: escrow transit with a public vault**. The vault is the Bridge's public token balance. Escrows follow the Aztec Standards Escrow pattern: authorization is `msg_sender == salt`, fixed in the escrow's address. The pattern is extended with transfers to public balances.

This section assumes an AIP-20-style token interface. L3X's collateral will be a new confidential token with purpose-built bridges [D7], and custody will be re-derived against that token's interface.

- **Deposit.** The user derives a fresh escrow `E_d` with `salt = bridge` and keys from `sk_d = H(user_secret, deposit_nonce)`. `Bridge.deposit`:
  - checks the derivation and that `amount ≥ min_deposit`;
  - calls `Token.transfer_private_to_private(user → E_d, amount)` under the user's authwit;
  - records `pending_deposit[h]` for `h = H(DS_DEP, account_index, token, amount, E_d, refund_to, salt)`;
  - delivers the record's preimage and `sk_d` to the operator by constrained on-chain delivery.

  `refund_to` is an Aztec address fixed by the depositor. Every refund path pays only `refund_to`, so knowing `sk_d` does not let the operator redirect funds. Only the Bridge can move funds out of `E_d`. The public sees that a deposit happened, not its amount.
- **Custody transaction.** The operator uses a transit escrow `T_i` from a small pool: `salt = bridge`, operator-held keys, and a pre-established handshake with the operator. In one transaction it:
  1. drains k pending deposits' escrows into `T_i` and appends their records to the priority queue, so the queue only ever holds funded deposits;
  2. pays due withdrawals and refunds from `T_i` (§10.4);
  3. settles the net against the vault, with `transfer_private_to_public` for a net inflow or `transfer_public_to_private` for a net outflow.

  AIP-20 creates the note of a public-to-private transfer in the private phase, so `T_i` can spend it in the same transaction. `T_i` ends every transaction with a zero balance, so its key never controls funds between transactions.

  Intermediate notes still leave logs, because v6 constrained-tagged logs are not squashed, but those logs are encrypted to `T_i`. The public effects are the net vault change, nullifiers of drained deposit notes and paid withdrawal ids, recipient notes and logs, and queue appends. The operator SHOULD include at least `k_min` flows per custody transaction [D2].

  Constrained-delivery sequences are strictly ordered per (sender, recipient). The pool of transit escrows therefore lets custody transactions run in parallel, and payouts to one recipient SHOULD be batched.
- **Reclaim.** Once a pending deposit has gone unswept for `T_dep` (default 24 h), or at any time in desert mode, anyone may call `reclaim_deposit`. It drains `E_d` to `refund_to`. A concurrent sweep and reclaim are resolved by `E_d`'s note nullifiers: whichever transaction lands first wins.
- **Scope.** Deposits can be censored (the operator may decline to sweep one) but not lost, and they never trigger desert mode, so dust deposits cannot force it [D13].

Draft 0.1 kept collateral in a "float" escrow with a published key. That leaked every intermediate amount, because anyone could decrypt its constrained-tagged logs.

Alternatives:

- **C0, public vault only**: deposits use `transfer_private_to_public` and every payout comes from the vault directly, so every amount is public. Simplest; for the first prototype only.
- **C2, private pool**: collateral sits in one escrow whose key is held by the operator, so not even the total is public. Exits in desert mode then need that key, so funds liveness depends on the operator or a guardian set holding it. Not recommended.

### 10.4 Withdrawals and refunds

A `Withdraw` or `ForcedWithdraw` debits the account in the batch. A deposit the circuit rejects (for example, one naming an account that does not exist) becomes a refund to its `refund_to`. Both append a record:

```
record        = H(DS_WD, withdrawal_id, account_index, recipient, token, amount)
withdrawal_id = H(DS_WDID, batch_number, index_in_batch, salt)
salt          = H(DS_WDSALT, k_enc, batch_number, index_in_batch)
```

For a refund, the depositor's `salt` from the deposit record replaces the `k_enc` derivation, so the depositor can rebuild it. The salt makes `withdrawal_id` globally unique and unguessable, so record hashes in DA cannot be brute-forced from public owners and plausible amounts. The record's fields and salt are also in the owner's encrypted change entry, so the owner can always rebuild the record.

After settlement the operator pays records in `custody` from `T_i`: it proves inclusion in `withdrawals_root[batch]` (historical public read), emits `withdrawal_id` as a nullifier, and pays the recipient privately. The amount is hidden inside the custody net; the recipient's address is not protected (§4).

If a record is unpaid `T_payout` (default 24 h) after `settled_time[batch]`, the owner calls `claim_withdrawal`, which pays from the vault directly; the amount becomes public. The vault is a public balance, so a claim cannot be blocked by consuming a note under it.

## 11. Sequencing and receipts

For each accepted action the sequencer returns `Receipt = Sign_op(H(action), seq, l3_block, time, result_commitment)`, with the result (fills or rejection reason) encrypted to the user. `action_log_root` is a Merkle root over `seq → H(action)` for the batch.

Accountability (phase 2): a user holding a receipt may challenge on the Bridge. The operator must answer within `T_resp` with a path showing `H(action)` at `seq` in a settled `action_log_root`, or lose its bond. The challenge reveals a hash, not the action. This makes dropping or reordering a receipted action provable. It does not prevent front-running before a receipt is issued.

## 12. Censorship resistance and desert mode

Batches MUST consume priority requests in order. `_apply` rejects a batch that leaves one older than `T_force` unprocessed. The default `T_force` is 14 days, matching Lighter's priority expiry; a shorter deadline strengthens censorship resistance at the cost of operational slack. The circuit MUST consume every request; it may reject an invalid one, for example an unauthorized `ForcedWithdraw`, but cannot skip it (§7.3).

If `priority_time[priority_cursor] < now − T_force`, anyone may call `activate_desert()`. It:

- permanently disables `settle` and `custody`;
- copies `accounts_root`, `market_data_hash` and `config_hash` into frozen storage;
- opens a claim window of `T_claim` (default 30 days).

Every desert function uses only frozen values.

**Valuation.** Positions settle at the frozen **index** prices, not the mark, with funding accrued to the freeze. Open orders are void and negative equity clamps to zero. Using the index limits a departing operator's influence to choosing among recent signed oracle updates within `max_age` and `T_lag` [D12].

**Claims, by seniority:**

1. **Pending deposits** (never swept): `reclaim_deposit` to `refund_to`, at any time.
2. **Swept, unprocessed deposits**: `desert_refund` pays `refund_to` from the vault. The depositor knows the record preimage.
3. **Settled, unpaid withdrawals and refunds**: `claim_withdrawal` from the vault.
4. **Accounts**: `exit_register` proves, in a private function, the opening of the account's leaf in the frozen `accounts_root` and records its equity under a per-account nullifier. The path and the opening both come from the last `W` of DA. Anyone may register a claim; it pays only the leaf's `owner`.

**Payout.** Items 2–4 register within `T_claim`. When the window closes:

- items 2–3 are paid in full from the vault;
- registered account claims are paid `min(1, V/U)·claim`, where `V` is what remains and `U` is their total;
- later claims are paid from the residual in the same order, at no better than the same ratio, without time limit;
- protocol accounts (`insurance`, `fee`) are paid last, only from the residual, and only after `T_late` (default 1 year), so triggering desert mode cannot profit the operator.

Exit amounts are public in desert mode. Underwater accounts do not register, so their deficit is socialized through the pro-rata factor; by §8.8 the vault always covers items 2–3.

**Upgrades.** The Bridge MUST be immutable: no function may update its contract class. Aztec's default update delay is one day and its minimum is 600 s, either of which would undercut every deadline here. The exchange evolves only through `root_vk_hash`, `config_hash` and `operators`. Changes to these take effect after `upgrade_delay` (default 21 days), which MUST exceed `T_force + T_payout` plus a margin, so users can exit first. No key may shorten the delay; Lighter's 21-day timelock can be zeroed by a 4-of-7 multisig, which is the main reason ETHBEAT rates it Stage 0.

There is no pause role [D11]. The operator halts the exchange by not settling, and that halt is bounded by the same valves as any failure:

- settled withdrawals become claimable from the vault after `T_payout`;
- unswept deposits become reclaimable after `T_dep`;
- any pending priority request lets anyone activate desert mode after `T_force`.

## 13. Comparison with Lighter

Lighter facts come from its whitepaper (Oct 2025), its documentation, its public prover and contract code (`elliottech/lighter-prover`, `lighter-contracts`, `lighter-go`), zkSecurity's audit reports, and ETHBEAT (formerly L2BEAT). Measured figures are single snapshots taken on 2026-11-20 from Lighter's public explorer API and should be re-checked.

| | Lighter | L3X |
| --- | --- | --- |
| Settles to | Ethereum L1 | Aztec, then Ethereum |
| Published per account | balances, position sizes, funding-index changes, pool shares, in clear | a leaf commitment and ciphertexts that only the owner and operator can open |
| Unpublished state | orders, book, API keys, nonces ("validium" subtree) | the same: activity tree and books |
| Operator API | serves any account's positions, PnL and trades with counterparties, unauthenticated | serves only the public data of §4 |
| Proof system | Plonky2 over Goldilocks, recursively aggregated, wrapped in gnark PLONK on BN254 | UltraHonk and Chonk (Barretenberg); the final proof is verified inside an Aztec private function |
| Order book | per-market price-keyed sparse tree, 80 levels, aggregate sums in nodes | the same design (§6.5) |
| Proven | priority relative to the sequencer's numbering, signatures, nonces, margin, funding accrual, liquidation validity | the same, plus oracle signatures and bounds, L3 time tracking real time, and trigger completeness at mark ticks |
| Not proven | fair ordering, oracle and mark inputs, fee tier, liquidation timing, ADL counterparty choice | fair ordering (post-receipt reordering is provable, §11), fee tier, liquidation timing until the risk sweep, ADL ranking until phase 3 |
| Deposits | priority requests with a 14-day deadline | swept by the operator; censorable but reclaimable after 24 h; cannot trigger desert mode [D13] |
| Throughput | "tens of thousands of operations/s" claimed; measured ≈ 3.3k tx/s 24-hour average, ≈ 8.4k peak hour | targets in §14, bounded by prover count and DA |
| Latency policy | 300 ms taker and cancel delay on the zero-fee tier, 140 ms taker on premium, makers 0 | sequencer policy, disclosed per tier (§8.1) |
| Hard finality | L1 execution ≈ 27–30 min after blocks are produced | Aztec epoch proof: up to ≈ 40 min plus proving, after settlement [M] |
| Escape hatch | priority requests expire after 14 days, then desert mode; exit at last mark plus funding, negative values clamped to zero | same trigger; settlement at the frozen index; refunds bound to depositor-chosen addresses; pro-rata over a claim window (§12) |
| Upgrades | 21-day timelock that a 4-of-7 multisig can zero; ETHBEAT Stage 0 | immutable Bridge; configuration delay ≥ `T_force + T_payout` with no bypass; no pause role |
| Keys | 255 slots, Schnorr over ECgFp5, per-key nonce + 1; an Ethereum wallet (ECDSA) registers keys | 256 slots, Schnorr over Grumpkin, per-slot nonce + 1 never reset; master authorization by key, client proof or Aztec account |
| Oracle | Stork primary, with Chainlink and Pyth; supplied by the sequencer, not verified in circuit | k-of-n signed updates verified in circuit [D6] |
| Batching | ≈ 1,600 blocks per batch; a commit about every 3.5 min | one settlement per Aztec slot (72 s) [D10] |

L3X adopts from Lighter: the block, segment and batch structure; the split between published account diffs and an unpublished trading subtree; the order-book tree; the margin fractions and liquidation waterfall; the funding formula; and the priority-expiry escape hatch.

It departs from Lighter in five ways:

- values are encrypted, so DA per account is larger and no explorer can show positions;
- oracle inputs and L3 time are verified in circuit;
- the Bridge is immutable;
- custody lives in Aztec private balances rather than an L1 contract;
- deposits are swept before they are queued.

Lighter's audits and incidents shaped §17:

- zkSecurity found a desert-exit path that let a negative account value be withdrawn as positive, and a path by which a new account could start with arbitrary collateral.
- A database failure stopped Lighter for about 4.5 hours in October 2025.
- In November 2026 an API key leaked through nonce reuse in third-party signing software. Lighter then used an instant upgrade to redirect the attacker's queued withdrawal. L3X deliberately cannot do that: no role can redirect funds, and the operator's only lever is declining to settle.

## 14. Performance targets and measurements

Provisional v1 targets:

| Metric | Target |
| --- | --- |
| Receipt latency at gateway | p50 < 2 ms, p99 < 10 ms |
| Sequencer throughput | 5,000 actions/s sustained, 20,000 burst (Lighter measured ≈ 3.3k tx/s average, ≈ 8.4k peak hour) |
| Proof lag F0 → F1 at sustained load | p99 < 5 min (must stay well inside `T_lag`) |
| Settlement cadence | one batch per Aztec slot [D10] |
| Mode R DA | ≤ 4,096 fields per settlement, including refresh |

Capacity: `actions/s ≈ N_provers · actions_per_segment / t_segment`, provided `t_merge·⌈log2(segments)⌉ + t_root + t_settle_tx` fits within the settlement cadence.

P0 measurements, taken in this repository on one Apple Silicon laptop (12 threads) with bb and Aztec 6.0.0, native backend. These are single runs, not benchmarks:

| # | Result |
| --- | --- |
| M1 | Verifying one UltraHonk ZK client proof inside a Chonk (Mega) app costs about 11.0k gates: `agg_app` with 10 proofs is 109,564 gates. A client proof of the P0 auth circuit takes 27 ms. In plain UltraHonk (`agg_ultra`, rollup target, so it could enter the merge tree directly) the same 10 verifications cost 7,592,247 gates (≈ 759k per proof) and 36.7 s to prove, against 6.9 s for the Chonk IVC plus tube: Chonk is 5.3× faster. |
| M2 | Chonk IVC over `agg_app` plus three kernels (11,445, 15,339 and 36,862 gates): 1.6 s. The proof is 1,221 fields plus the user public inputs, which come first. |
| M3 | Tube: 1,473,521 gates, 4.5 s, 480-field RollupHonk proof. |
| M4 | Root, with two RollupHonk verifications and full IPA verification: 8,388,352 gates (≈ 2^23), 42–46 s, 458-field ZK proof. This is a fixed cost per batch. |
| M5 | `Bridge.settle` on a 6.0.0 local network, with client proving and node transaction-proof verification on.<br>Client proving: the private `settle` circuit is 191,285 gates. It verifies the root proof, hashes a 4,080-field argument, checks the DA sponge and reads three `DelayedPublicMutable`s. The transaction's other circuits: account entrypoint 15,777, `private_kernel_init` 57,095, reset-tail-to-public 97,654, hiding kernel 44,438. Send to checkpointed: 6.6–7.1 s.<br>Gas, 40-field payload: 2,240 DA gas, 3.78M L2 gas.<br>Gas, 1,714-field payload: 55,808 DA gas, 5.49M L2 gas. 1,714 fields is the most the network admits (§9.5): its per-transaction DA cap is 55,836 DA gas. A 4,080-field payload would need 131,520 DA gas.<br>Building the log costs ≈ 1,030 L2 gas per field, so a 3,600-field payload would pass the AVM's 6M processable L2 gas. Log emission must be made cheaper before Mode R can use mainnet-geometry capacity. |
| M7 | Merge: 1,479,481 gates, 5.1–6.7 s, verifying two RollupHonk children and accumulating their IPA claims. X-segments enter the merge tree directly as RollupHonk proofs with bb's default IPA claim; the P0 X-segment stub is 680,499 gates (2.3–3.9 s), dominated by a 4,080-field DA absorption loop. Padding: 3,663 gates. |

On this hardware the root alone takes 35–52 s, half to three quarters of a 72-second slot depending on load. It therefore bounds the settlement cadence (D10) until the root is proved on faster hardware, or the IPA closure moves elsewhere. Settling on Aztec is cheap by comparison: verifying the 2^23-gate root proof costs the `settle` function about 29k of its 191k gates. Per segment, the tube (4.5–5 s) costs more than aggregating ten client proofs (1.6 s), and a merge costs about as much as a tube.

Measure before fixing circuit shapes (M1–M4 above are first P0 results):

| # | Measurement |
| --- | --- |
| M1 | Gates and time to verify one UltraHonk ZK proof inside a Chonk app circuit, versus inside UltraHonk |
| M2 | Chonk proving time for `agg_app` with 10 proofs plus kernels; largest practical app circuit |
| M3 | Tube gates and proving time on v6.1 |
| M4 | Root circuit with `verify_root_rolluphonk_proof` |
| M5 | `Bridge.settle` transaction: client proving time, mana, cost of a 4,096-field payload; `custody` transaction cost per flow |
| M6 | Execution gates per action kind (rest, cancel, fill, trigger, oracle update, mark and funding ticks, liquidation) with RAM caching; risk-sweep cost per account |
| M7 | Merge proving time; how X-segments enter the merge tree |
| M8 | Change and refresh entry sizes, and change entries per batch, from replayed market data |

## 15. Delivery plan

| Phase | Scope | Exit criterion |
| --- | --- | --- |
| P0 Port and measure | Port the PoC to v6.1; close G1–G5; root circuit; Bridge with state root, header binding and replay protection; M1–M5 | A batch settles on a v6.1 local network through a fully proved settlement transaction, and substituted inner VKs are rejected |
| P1 One market | Accounts, C0 custody, signed orders, books, matching, margin, Mode R with refresh, desert-mode exit; engine/circuit differential tests | On testnet, a user with no local state exits from DA alone after the operator is stopped |
| P2 Production semantics | C1 custody, multiple markets, oracles, mark and funding ticks, liquidation, insurance account, priority requests, receipts and accountability, client-proof lane | Load test at §14 targets; external audit |
| P3 Scale | Parallel segments and merge tree in production, Mode E, risk sweep, ADL ranking, spot, public liquidity pool | Sustained targets within the proof-lag bound |
| P4 Operator trust | Hot-standby operators with encrypted state replication; research into threshold-encrypted order flow, batch auctions, MPC or TEE matching | — |

P0 status (2026-11-21): complete on Aztec 6.0.0 rather than 6.1, which had not yet been published.

- Batches settle through fully proved settlement transactions on a local network that verifies transaction proofs. The test batches are `root(merge(tube, x-segment), x-segment)` and `root(x-segment, padding)`.
- Substituted or role-crossing VKs are rejected:
  - in the IVC app slot;
  - as a root or merge child outside the VK tree;
  - in a borrowed tree slot with a forged VK hash;
  - in the client subtree.
- Segments that do not chain, or that used another configuration, are rejected.
- A forged header that passes every public check is rejected by the proof binding.
- The Bridge's checks are covered by TXE tests: replay, priority-queue forgeries, `T_force`, time bounds, halt and resume, and delayed configuration and operator changes.
- M1, M4, M5 and M7 are measured (§14); M2 and M3 are the IVC and tube figures from the same runs.

Left for later phases: a client subtree with more than one circuit, and desert-mode, custody and withdrawal paths (P1, P2).

See `README.md`.

## 16. Decisions

All resolved on 2026-11-20. The draft default was adopted for every decision except D7 and D11.

| # | Decision | Resolution | Alternatives considered |
| --- | --- | --- | --- |
| D1 | Visibility of book and market data | Dark book; public best bid/ask prices and per-batch print summary; volume and OI bucketed; per-order opt-in display of size | Fully dark; fully lit book with only balances and positions hidden |
| D2 | Custody | C1 escrow transit with a public vault, `k_min = 4` | C0 public vault only; C2 private pool |
| D3 | DA | Mode R with refresh | Modes E, V |
| D4 | Operator | One bonded operator that sees plaintext | Committee with threshold-encrypted order flow |
| D5 | Matching | Continuous | Frequent batch auctions per L3 block |
| D6 | Oracle | k-of-n signed updates from an external provider (provider not yet named) | An Aztec-native feed |
| D7 | Collateral | A new token type with purpose-built bridges, built for this system (amounts hidden, addresses public, per §1), specified separately. The Shield bridge is out of scope. | Existing Aztec stablecoins |
| D8 | v1 scope | Perpetuals only | Perpetuals and spot |
| D9 | Client-proof lane | Master authorization, key grants, withdrawals, credentials | Per-order proofs |
| D10 | Settlement cadence | One batch per Aztec slot | One per L2 block |
| D11 | Emergency pause | None. The sole operator halts by not settling, within the bounds of §12. | A bounded guardian pause |
| D12 | Desert valuation | Frozen index | Frozen mark (Lighter); k-of-n oracle prices attested to the Bridge after the freeze |
| D13 | Deposit admission | Swept before queued: censorable but reclaimable after `T_dep`, cannot trigger desert mode | Deposits as priority requests with the `T_force` deadline (Lighter) |

## 17. Acceptance criteria

Production requires at least:

- G1–G5 closed, with tests that substitute every inner VK and every role-crossing VK;
- header-binding tests: a settlement with a stale or foreign `config_hash`, a forged `priority_head_start`, or a skipped or reordered priority request is rejected;
- a written soundness argument per circuit and a conservation proof;
- differential tests of the engine against the circuits on replayed and adversarial order flow;
- desert-mode exit from the last `W` of DA alone by a user with no local state, including the pro-rata, late-claim and refund paths;
- negative tests drawn from Lighter's audit findings and this draft's review:
  - an account with negative equity cannot register a positive claim or withdraw;
  - a new account starts with zero collateral and no positions;
  - refunds and exits pay only `refund_to` and `owner`;
- deadline, `T_lag`, halt-and-resume and `activate_desert` tests under an adversarial operator;
- signer tests showing deterministic, hedged Schnorr nonces;
- a leakage review of the DA payload, public outputs, custody transactions and Aztec side effects (counts, timing, handshakes);
- M1–M8 measured and meeting §14;
- testnet operation;
- independent audits of circuits, contracts and engine.
