# L3X: confidential order-book exchange rollup on Aztec

Status: draft 0.14, 2026-11-22. Decisions D1–D13 are resolved (§16). Phase P0 (§15) is complete in this repository on Aztec 6.0.0, because the 6.1.0 toolchain is not yet published to the installer or npm; see `README.md`. P1, a single-market exchange, is built and passes its exit test on a local network (§15, P1 profile). P2 is in progress: multiple markets with mark, funding, fees and the protocol accounts (P2.1), liquidation with the insurance backstop (P2.2), session keys, GTT orders and forced requests (P2.3), refresh enforcement with the desert seniority rules (P2.4), receipts with accountability and client-proof actions (P2.5), client-proof withdrawals (P2.6), the client subtree with a P-256 client circuit (P2.7), order modification and transfers (P2.8), constant-time cancel-all (P2.9), dead-order removal with live-only ticks (P2.10), the risk sweep at refresh (P2.11), a WebAuthn passkey client circuit (P2.12), C1 custody over the D7 collateral token, amounts hidden and addresses public (P2.13), the token's bridge to L1 (P2.14), stop and take-profit triggers (P2.15), and the print summary with bucketed volume and open interest (P2.16), are built (§15, P2 profile). Before P0, only the proof-compression proof of concept in [`zac-williamson/rollup-on-aztec`](https://github.com/zac-williamson/rollup-on-aztec) existed (§3). Draft 0.4 records P0's findings: the merge tree and VK tree as built (§9), and a Mode R capacity well below the public-log cap (§9.5, M5). Draft 0.2 incorporated findings from an internal adversarial review; there has been no external review. Target: Aztec `v6.1.0` with its pinned Noir and Barretenberg. "L3X" is a working name. MUST, SHOULD and MAY are used as in RFC 2119. **[D#]** refers to a recorded decision (§16); **[M#]** marks a figure that depends on measurement (§14).

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

- deposits and withdrawals move to and from confidential balances of the collateral token, with only net totals per custody transaction public (§10.3, §10.5);
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
| G2 | Verification keys are free witnesses at every inner layer: the client VK in `batch_app`, `app_vk` in `init_kernel`, `kernel_vk` in `tail_kernel` and `hiding_kernel`, and the Chonk VK in `tube`. Only the tube's VK hash is fixed (in the contract). A prover can substitute any inner circuit and emit any `batch_hash`. | Every recursive verification MUST pin the child VK hash, by a circuit constant or by membership in a role-specific VK subtree whose root the Bridge checks (§9.3). Implemented in P0: the Chonk chain and the tube pin constants; merges and the root check membership in the VK tree. Since P2.7 `agg_app` checks each client VK's membership in the client subtree. |
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
| Depositor and withdrawal-recipient Aztec addresses | yes: the token records every confidential payment's parties (§10.5) | yes | no |
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
- Custody MUST NOT reveal an individual deposit or payout amount: each custody transaction moves only its net against the vault (§10.3), and the batch header carries no withdrawal total (§10.4).

Residual leakage:

- per-account timing and frequency of balance changes;
- counts of touched accounts, padded slot tuples, nullifiers, notes and logs;
- deposit and withdrawal timing, parties and accounts, net custody flows, and the vault total;
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
- **Triggers**: stop and take-profit orders live in a second per-market tree with the same layout, keyed by trigger price. An UP trigger fires once the mark rises to its price and uses the ask slot; a DOWN trigger fires once the mark falls to it and uses the bid slot. So the aggregates locate the next trigger due in each direction with one walk, as they locate the best ask and bid. Triggers are evaluated only at mark ticks (§8.4), and the mark does not change between ticks, so firing a trigger cannot cascade within a tick. At each tick the circuit sets the market's `trigger_pending` flag if the aggregates show any trigger due at the new mark. While the flag is set, the market accepts no new orders, only trigger firings and cancels; the flag clears when the aggregates show none due. Due triggers fire in price-time order, one operator action each (§15, P2 profile).

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
- **P**: a client proof (§7.4) whose public inputs are `(msg, account_index, auth_binding)`. The segment requires `master_auth == H(DS_MAUTH_P, vk_hash, auth_binding)`, and requires that the configuration permits that circuit to authorize this action kind. `DS_MAUTH_P` differs from the separator of a lane-S master key's `H(DS_MAUTH, pk)`, so neither lane's authorization can be read as the other's.

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
| `PlaceTrigger`, `CancelTrigger` | as built (P2.15): market, side, limit price, lots, direction, trigger price; and market, direction, trigger price, sequence number |
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
- **Public output**: per batch and market, the header's `market_data` carries index, mark, funding rate, cumulative funding, best bid and ask prices, the print summary (last, VWAP, high and low of the batch's fills) and the batch's volume and the open interest, each rounded down to a power of two [D1]. Consumers should treat these as the prices of one venue: proven to follow the rules, not proven sound.

### 8.5 Liquidation

The waterfall follows Lighter's. For each step the circuit checks the precondition at current marks:

1. `equity < MM`: cancel all the account's orders, then close positions against the book with IOC orders at a limit price that keeps the account's equity-to-requirement ratio constant, charging a fee of at most 1% to the insurance account;
2. `equity < CM`, or the book cannot absorb: the insurance account takes over positions, lowest unrealized PnL first, provided it stays above its own IM;
3. backstop exhausted: auto-deleverage opposing positions ranked by leverage and unrealized PnL. The circuit verifies the ranking from the start of phase 3; before that, ADL counterparty choice is the operator's, as it is on Lighter.

### 8.6 Fees

Maker and taker rates in hundredths of a basis point, by fee tier. Tiers are stored privately and set by the operator. Fees credit the fee account (class `fee`). Zero-fee tiers are allowed.

### 8.7 Risk sweep (phase 3)

Proofs show that every liquidation performed was justified, not that every due liquidation happened. A `risk_cursor` advancing over account indices obliges each batch to check `Q` accounts at current marks (proving `equity ≥ MM` or liquidating), so every account with a position is checked at least every `R` batches [M6].

As built (P2.11, §15), the refresh cursor serves as the risk cursor and the refresh window as `R`: a refresh entry is also a risk check.

### 8.8 Conservation

Every action conserves collateral exactly across the touched accounts, the fee account and the insurance account, and preserves `oi_long == oi_short`; funding is zero-sum per market. With custody accounting (§10.3) this gives, at any common set of marks:

```
Σ_accounts equity = vault − swept-but-unprocessed deposits − settled-but-unpaid withdrawals and refunds
```

Unrealized PnL and funding sum to zero across accounts, so `Σ equity` equals net credited deposits. It is therefore never negative, and the vault always covers the two senior terms. Pending deposits are credits the Bridge holds outside the vault, and the vault excludes the operator's bond and open challenge fees (§10.3, §11).

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
| `deposits[credit]` | `Map` | deposits' credits: status (pending, swept, reclaimed) and submission time |
| `withdrawals_root[batch]`, `settled_time[batch]`, `withdrawal_paid[record]`, `market_data_hash` | `Map`, `PublicMutable` | settled withdrawal lists, settlement times, paid records, latest market data |
| desert state | `PublicMutable`, `Map` | flag, frozen `accounts_root`, `market_data_hash` and `config_hash`, claim window, claims (§12) |

| Function | Context | Behaviour |
| --- | --- | --- |
| `register(master_auth, enc_key_commitment, k_enc)` | private | asserts `H(DS_ENC, k_enc) == enc_key_commitment`; charges `request_fee`; queues `Register` with `owner = msg_sender`; delivers `k_enc` to the operator by constrained on-chain delivery |
| `deposit(account_index, amount, refund_to, salt, credits, change_blind, authwit_nonce)` | private | §10.3 |
| `submit_forced(request)` | private | charges `request_fee`; queues the request with `msg_sender`, optionally encrypted |
| `settle(header, proof, vk, da_payload, da_len)` | private | asserts `msg_sender ∈ operators` and `header.config_hash == config_hash`; checks `da_hash` over the first `da_len` fields; `verify_honk_proof(vk, proof, [H(header)], root_vk_hash)`; `enqueue_self._apply(header, da_payload, da_len)` |
| `schedule_upgrade(vk_tree_leaves, params_hash, root_vk_hash)` | public, operator | recomputes `config_hash` from the preimage, schedules it and `root_vk_hash` together, and publishes the preimage |
| `schedule_operator(operator)` | public, operator | schedules a new operator |
| `_apply(header, da_payload)` | public, only-self | §10.2 |
| `custody(deposits, n_deposits, payouts, n_payouts)` | private, operator | §10.3, §10.4 |
| `reclaim_deposit(opening, blind)` | private | §10.3 |
| `claim_withdrawal(batch, index, recipient, amount, salt, path)` | private | §10.4 |
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

- emits `[DA_LOG_TAG, batch_number, market_data…, payload…]` as one public log;
- updates `state_root`, `accounts_root`, `batch_number`, `last_time` and `priority_cursor`;
- stores `withdrawals_root[batch_number]`, `settled_time[batch_number]` and `market_data_hash`;
- puts `market_data` in that log, 13 fields per market (§8.4), from the same 4,096-field log budget.

`settle` checks `config_hash` in the private phase. The value is a `DelayedPublicMutable`, so the transaction expires before any scheduled change can take effect.

### 10.3 Custody [D2]

The default profile is **C1: confidential transit with a public vault**. The vault is the Bridge's public balance of the collateral token (§10.5). Individual deposits and payouts move as credits, whose amounts are hidden; the vault only ever changes by the net of one custody transaction.

A credit is spendable only by a call from its owner (§10.5), not by whoever holds a key, so the Bridge can hold credits itself. No escrow contracts or transit escrows are needed: draft 0.10's `E_d` and `T_i` existed because a note can be spent only with its owner's keys, which a contract does not have.

- **Deposit.** `Bridge.deposit(account_index, amount, refund_to, salt, credits, change_blind, authwit_nonce)`, a private function:
  - asserts `min_deposit ≤ amount < MAX_DEPOSIT`;
  - calls `Token.transfer(depositor → Bridge, amount)` under the depositor's authorization of that exact call. The new credit is owned by the Bridge and has blind `deposit_blind = H(DS_DEP, account_index, refund_to, depositor, salt)`, so its opening fixes the account, the refund address and the depositor. The change returns to the depositor;
  - delivers the opening `(account_index, amount, refund_to, depositor, salt)` to the operator by constrained delivery;
  - records `deposits[credit] = (PENDING, now)` and emits `DepositPending(credit, account_index, refund_to, depositor, time)`.

  `refund_to` is an Aztec address fixed by the depositor. Every refund path pays only `refund_to`, so knowing the opening does not let the operator redirect funds. The public sees that a deposit happened, its account and its parties, not its amount.
- **Custody transaction.** `Bridge.custody(deposits, n_deposits, payouts, n_payouts)`, private, operator only, with up to 4 deposits and 4 payouts. In one transaction it:
  1. spends the deposits' credits, which proves each opening;
  2. pays settled records (§10.4) as new credits of their recipients, delivered by constrained delivery, after checking each record's path to its batch's `withdrawals_root` and that it is unpaid;
  3. settles the net against the vault in the same token call (`Token.settle`, §10.5): `Σ deposits + net_out = Σ payouts + net_in`;
  4. marks the deposits `SWEPT` and appends each to the priority queue as `Deposit(a = account_index, b = H(DS_DEPAMT, amount, salt), c = refund_to)` with the depositor as sender, so the queue only ever holds funded deposits and never their amounts;
  5. asserts the vault still covers the bond and open challenge fees.

  The public effects are the net vault change, the swept credits, the paid record hashes, the recipients' addresses and the queue entries. The operator SHOULD include at least `k_min` flows per custody transaction [D2].

  Constrained-delivery sequences are strictly ordered per (sender, recipient), and two sends to one recipient in a transaction need a handshake committed earlier. The operator therefore pays at most one record per recipient per custody transaction until their handshake exists.
- **Reclaim.** Once a pending deposit has gone unswept for `T_dep` (default 24 h), or at any time in desert mode, anyone holding its opening may call `reclaim_deposit`. It returns the credit to `refund_to` as a new credit, delivered by constrained delivery, and marks the deposit `RECLAIMED`. A concurrent sweep and reclaim are resolved by the credit's spent nullifier: whichever transaction lands first wins.
- **Scope.** Deposits can be censored (the operator may decline to sweep one) but not lost, and they never trigger desert mode, so dust deposits cannot force it [D13].

Draft 0.1 kept collateral in a "float" escrow with a published key, which leaked every intermediate amount. Drafts 0.2–0.10 used per-deposit escrows and operator-keyed transit escrows over an AIP-20-style token; the D7 token makes them unnecessary.

Alternatives:

- **C0, public vault only**: deposits and payouts move public balances, so every amount is public. P1 used it.
- **C2, private pool**: collateral sits in a confidential balance whose opening only the operator knows, so not even the total is public. Exits in desert mode then need that opening, so funds liveness depends on the operator or a guardian set. Not recommended.

### 10.4 Withdrawals and refunds

A `Withdraw` or `ForcedWithdraw` debits the account in the batch. A deposit the circuit rejects (for example, one naming an account that does not exist) becomes a refund to its `refund_to`. Both append a record:

```
record = H(DS_WD, recipient, amount, salt, batch_number, index_in_batch)
salt   = H(DS_WDSALT, k_enc, batch_number, index_in_batch)     withdrawals
salt   = the deposit's salt                                       refunds
```

The salt makes each record unguessable, so record hashes in DA cannot be brute-forced from public recipients and plausible amounts, and lets the owner rebuild the record: the account's owner from its key, the depositor from its salt. The record's fields and salt are also in the owner's encrypted change entry.

The header publishes a batch's `withdrawals_root` and record count, not their total: since draft 0.11 the total is hidden, as custody pays records inside a net.

After settlement the operator pays records in `custody` (§10.3). The amount is hidden inside the custody net; the recipient's address is not protected (§4).

If a record is unpaid `T_payout` (default 24 h) after its batch settled, anyone may call `claim_withdrawal`, which pays the recipient from the vault into its public balance; the amount becomes public. The vault is a public balance, so a claim cannot be blocked by consuming anything under it. Its path is folded in the private phase; the public phase compares the root with the batch's.

### 10.5 Collateral token [D7]

The collateral is a token built for L3X: **amounts hidden, addresses public**. It is confidential in the same sense as the exchange (§1): who pays whom is public, how much is not. The Shield bridge, which makes holdings private, does not fit. The token's `minter` is its bridge (§10.6); tests that need no L1 use an operator as the minter instead.

**Balances.** An address holds a public balance, a plain amount as in an ERC-20, and a confidential balance, a set of credits.

```
credit       = H(DS_CREDIT, owner, amount, blind)       never published
created(c)   = H(DS_CREATED, c)                          nullifier, emitted when c is created
spent(c)     = H(DS_SPENT, c)                            nullifier, emitted when c is spent
```

- Creating a credit emits `created(c)`; the duplicate-nullifier rule makes credits unique.
- Spending a credit proves that `created(c)` exists, by a nullifier read request against the anchor block, and emits `spent(c)`, so a credit is spent once.
- Only the owner spends: every private function recomputes `c` with the caller (or the address that authorized the call) as the owner. Spending authority is the caller, not a key, so contracts hold credits like accounts.
- Every private function checks value conservation and amount ranges in the circuit. A zero amount marks an unused input or output; no credit has a zero amount.
- The two nullifiers of a credit cannot be linked without its opening, so the public cannot tell which earlier payment funded a later one.

**Functions.**

| Function | Context | Effect |
| --- | --- | --- |
| `mint(to, amount)`, `burn(amount)` | public | the minter creates supply in a public balance; anyone destroys its own |
| `transfer_public`, `approve`, `transfer_public_from` | public | public balances, with ERC-20 allowances |
| `shield(amount, blind)` | private | caller's public balance → a new credit of the caller |
| `transfer(from, to, amount, credits[2], blind, change_blind, authwit_nonce)` | private | credits of `from` → a credit of `to` plus change; a caller other than `from` needs `from`'s authorization of the exact call |
| `unshield(to, amount, credits[2], change_blind)` | private | caller's credits → public balance of `to`, plus change |
| `settle(credits[4], outputs[4], public_in, public_out)` | private | caller's credits and `public_in` from its public balance → the outputs and `public_out` to its public balance |

**Delivery.** A new credit's opening reaches its owner by constrained delivery, except when the owner is the caller, who chose it. Change returns to the payer by unconstrained delivery, since only the payer could be harmed by a wrong message. Constrained delivery stops a payer, or the operator's custody, from paying a credit its recipient cannot open.

**Parties.** Every confidential payment emits a plaintext log `(tag = "ct.parties", from, to)`. Public balance changes emit `PublicTransfer(from, to, amount)`, with the token itself standing for the confidential side of `shield`, `unshield` and `settle`.

**Limits.** A private call may emit 16 nullifiers. Each input emits one (`spent`) and each output three (`created`, its delivered event's commitment and its constrained-delivery sequence nullifier), so `settle` with 4 inputs and 4 outputs emits exactly 16. That caps one custody transaction at 4 deposits and 4 payouts.

### 10.6 Token bridge [D7]

The token's bridge to L1 has two halves.

- **L1: an escrow portal**, Aztec's standard `TokenPortal`. It holds the underlying ERC-20.
  - `depositToAztecPublic(to, amount, secret_hash)` locks the amount and sends an L1-to-L2 message with content `sha256ToField(mint_to_public(to, amount))`.
  - `depositToAztecPrivate(amount, secret_hash)` does the same without naming a recipient: `sha256ToField(mint_to_private(amount))`.
  - `withdraw(recipient, amount, with_caller, epoch, n_checkpoints, leaf, path)` consumes the L2-to-L1 message `sha256ToField(withdraw(recipient, amount, caller))` from the Outbox and releases the amount.
- **L2: `ConfidentialTokenBridge`**, the token's minter.

| Function | Context | Effect |
| --- | --- | --- |
| `claim_public(to, amount, secret, leaf)` | public | consumes `mint_to_public(to, amount)` and mints into the public balance of `to` |
| `claim_confidential(to, amount, blind, secret, leaf)` | private | consumes `mint_to_private(amount)` and mints a credit of `to`, delivered by constrained delivery |
| `exit_public(recipient, amount, caller_on_l1)` | public | burns from the caller's public balance and sends `withdraw(recipient, amount, caller_on_l1)` |
| `exit_confidential(recipient, amount, credits, change_blind, caller_on_l1)` | private | burns from the caller's credits, returning change, and sends the same message |

- A claim needs the message's secret, so only whoever holds it claims; a public claim pays only the `to` the deposit named.
- The token trusts its minter in three functions: `burn_public(from, ·)`, `mint_confidential` and `burn_confidential(from, ·)`. The bridge always passes its own caller as `from`, so it burns only its caller's funds.
- **Deployment.** Each contract needs the other's address. The bridge is deployed with the portal's address; the token with the bridge as its minter; the bridge's deployer then binds the token, once; and the portal is initialized with the L2 bridge.
- **Privacy.** Amounts are public on L1 in both directions, so the bridge hides no amount. A deposit claimed into a credit saves a separate shield. `depositToAztecPrivate` leaves the recipient unnamed on L1, but the token's parties log publishes it at the claim.
- **Why the standard portal.** It is a plain escrow with fixed message formats, so the token-specific rules all live on L2 and the L1 contract needs no audit beyond Aztec's. The Shield bridge, which makes holdings private, is out of scope [D7].

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

1. **Pending deposits** (never swept): `reclaim_deposit` returns the credit to `refund_to`, at any time. They were never in the vault, so they take nothing from it.
2. **Swept, unprocessed deposits**: `desert_refund(index, account_index, amount, salt, refund_to, depositor, time)` rebuilds the queue entry from the deposit's opening and pays `refund_to` from the vault. The depositor holds the opening.
3. **Settled, unpaid withdrawals and refunds**: `claim_withdrawal` from the vault, without waiting for `T_payout`.
4. **Accounts**: `exit_register` proves, in a private function, the opening of the account's leaf in the frozen `accounts_root` and records its equity under a per-account nullifier. The path and the opening both come from the last `W` of DA. Anyone may register a claim; it pays only the leaf's `owner`.

**Payout.** Items 2–3 are paid in full from the vault when claimed, until the payout ratio is fixed. Their amounts are hidden until claimed, so the vault cannot reserve for them; they keep their seniority by being claimed within `T_claim`. Account claims register within `T_claim`. At the first account payout after the window:

- the ratio is fixed at `min(1, V/U)`, where `V` is the vault and `U` the registered account claims' total, and each registered account claim is paid `ratio·claim`;
- later claims of any kind are paid from the residual, the vault less what the window's account claims are still owed, first come first served: a later account claim at no better than the ratio, a later item 2 or 3 in full if the residual allows;
- protocol accounts (`insurance`, `fee`) are paid last, only from the residual, and only after `T_late` (default 1 year), so triggering desert mode cannot profit the operator.

Exit amounts are public in desert mode. Underwater accounts do not register, so their deficit is socialized through the pro-rata factor; by §8.8 the vault covers items 2–3 claimed in the window in full.

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
| M5 | `Bridge.settle` on a 6.0.0 local network, with client proving and node transaction-proof verification on.<br>Client proving: the private `settle` circuit is 191,285 gates. It verifies the root proof, hashes a 4,080-field argument, checks the DA sponge and reads three `DelayedPublicMutable`s. The transaction's other circuits: account entrypoint 15,777, `private_kernel_init` 57,095, reset-tail-to-public 97,654, hiding kernel 44,438. Send to checkpointed: 6.6–7.1 s.<br>Gas, 40-field payload: 2,240 DA gas, 3.78M L2 gas.<br>Gas, 1,714-field payload: 55,808 DA gas, 5.49M L2 gas. 1,714 fields is the most the network admits (§9.5): its per-transaction DA cap is 55,836 DA gas. A 4,080-field payload would need 131,520 DA gas.<br>Building the log costs ≈ 1,030 L2 gas per field, so a 3,600-field payload would pass the AVM's 6M processable L2 gas. Log emission must be made cheaper before Mode R can use mainnet-geometry capacity.<br>Custody (P2.13): a custody transaction with up to four deposits and four payouts, each payout a constrained delivery, proves on the client and lands checkpointed in 6.5–7.3 s; a deposit, with its authorization, in 6.5–7.1 s. Per-flow gas is not yet measured. |
| M6 | P1, without RAM caching (each touched leaf costs Merkle paths): `seg_trade` is 276,126 gates for 2 actions with up to 2 fills each (≈ 138k per action slot); `seg_priority` 94,286 for 4 requests; `seg_block` 6,996 including one Schnorr verification; `seg_refresh` 26,917 for 4 accounts. Each proves in under 2 s. P2.1 (four markets, k-of-n oracles, funding, fees): `seg_trade` 339,934 gates; `seg_block` 161,955 for up to four index updates with three signatures and two 80-level top-of-book walks each; `seg_priority` 99,717; `seg_refresh` with the sweep 47,828. P2.2: `seg_liquidate` 327,161 gates for two liquidation steps (each any of cancel, close with two matching steps, takeover, deficit, ADL); its segments prove in 3.6–6.3 s under load. P2.3 (session keys, GTT, forced requests): `seg_trade` 430,513; `seg_priority` 155,159; `seg_liquidate` 386,374; `seg_forced` 221,271. Risk-sweep costs await phase 3. |
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

Left for later phases: a client subtree with more than one circuit (built in P2.7), and the custody paths of C1 (built in P2.13).

### P1 profile (as built, 2026-11-21)

P1 runs one market end to end. Where it narrows the design, the full design remains normative for later phases; everything not listed here is deferred to P2.

**State** (§6, reduced):

- Accounts and activity trees of height 32 with nodes `H(DS, left, right)`.
- `AccountLeaf = H(DS_ACCT, pub_hash, priv_hash)` with `pub = (owner, master_auth, enc_key_commitment, class)` and `priv = (collateral, size, entry_notional, blind)`: one position slot (`P_MAX = 1`), signed values in 64-bit two's complement. `master_auth = H(DS_MAUTH, pk)` for a Grumpkin master key. There are no session keys: the master key signs every action.
- `ActivityLeaf = H(DS_ACTV, nonce, open_bid_lots, open_ask_lots, open_order_count)`.
- `MarketLeaf = H(DS_MKT, book_root, index_price, index_time, next_seq, oi_long, oi_short)`; the mark is the index.
- The book is the tree of §6.5. A node is one Poseidon2 permutation of `(left, right, ask_lots + bid_lots·2^64, DS_BOOK)`; an order leaf is `H(DS_ORDER, side, account_index, lots)`. Sequence numbers stay below 2^47, so a resting bid has no ask at or below its price exactly when no ask lies to its left.
- Bounds that keep position arithmetic in 64 bits: price and lots below 2^24, |size| below 2^32, |collateral| and deposits below 2^62.

**Segments.** All are X-segments in the segment subtree of the VK tree:

| Segment | Per proof | Gates | Does |
| --- | --- | --- | --- |
| `seg_block` | one L3 block | 6,996 | Sets L3 time; it is the only segment that advances it. Applies at most one oracle update signed by the configured key, newer than the last and not after the block, moving at most `max_jump`. |
| `seg_priority` | ≤ 4 requests | 94,286 | `Register` (an account at the next index, zero balances) and `Deposit` (a credit, or a refund record if the account does not exist), in queue order. |
| `seg_trade` | ≤ 2 signed actions | 276,126 | `PlaceOrder` (GTC, IOC; ≤ 2 fills), `CancelOrder`, `Withdraw`. |
| `seg_refresh` | ≤ 4 accounts | 26,917 | Republishes the next accounts after `refresh_cursor`. |

Each segment proves in under 2 s on the reference laptop; a merge (1.48M gates) takes about 6 s and the root 35–50 s. At these sizes merges dominate, so P2 SHOULD raise actions per segment [M6, M7].

**Trading rules.**

- An action is signed by the account's master key over `H(DS_ACTION, domain, kind, account, nonce, payload)`, with `nonce` = stored + 1 and `domain = H(DS_DOMAIN, chain_id, instance)` from the configuration. The account's leaf is always proven against the accounts root, which authenticates the key.
- A limit price must lie within `price_band` of the index.
- An order fills against the best opposite order at the maker's price; the tree aggregates prove it is the best. Self-trade is rejected.
- The remainder rests (GTC) or cancels (IOC), either way only after proving that no crossing liquidity is left. An order that would need more than two fills is not sequenced.
- Reductions realize PnL against the average entry; a flip closes the position and opens the rest. Rounding moves value only between realized and unrealized PnL, so equity is exact.
- An action that increases worst-case size needs an index no older than `max_age` and equity ≥ worst·index·imr afterwards.
- `Withdraw` needs collateral ≥ amount and equity − amount ≥ IM. It appends a record `H(DS_WD, recipient, amount, salt, batch, index)` with `salt = H(DS_WDSALT, k_enc, batch, index)`.
- Only accounts whose `AccountLeaf` changes get DA entries, so placing and cancelling orders publishes nothing (§4).

**DA** (§9.5):

- Each segment opens with `[TAG_SEG, da_nonce]`, where `da_nonce = H(DS_DANONCE, batch, action log after the segment's actions, the segment's DA offset)`. It is published so owners can decrypt. It replaces §9.4's batch-level nonce, which segments cannot compute because they do not know the batch's final action log.
- Account entries, for changes and refreshes, are 11 fields: tag, index, leaf, the public part in clear, and ciphertexts of collateral, size, entry notional and blind.
- Blind and keystream are bound to `(k_enc, account, da_nonce, position)`, so no keystream is ever reused, even for two entries of one account in one segment.
- Withdrawal and refund records are 2 fields.
- The refresh rate is not yet enforced.

**Bridge**, C0 profile (§10.3):

- `register` is private. It checks `k_enc` against the commitment, delivers `k_enc` to the operator by constrained on-chain delivery, and queues the request with `owner = msg_sender`. A user therefore cannot register a key the operator does not hold, which would otherwise block the queue into desert mode.
- `deposit` pulls tokens into the vault and queues the request.
- `settle` and `_apply` work as in P0, plus market data and per-batch withdrawal trees.
- `claim_withdrawal` pays a record in a settled batch's tree from the vault, once, to its recipient.
- `activate_desert`, `desert_refund`, `exit_register` and `exit_withdraw` follow §12. The pro-rata ratio is fixed at the first payout after the claim window closes, and senior obligations (unpaid withdrawals and unprocessed deposits) are reserved first.
- Collateral is a minimal public token for C0, not the D7 token.
- Storage is grouped into packed structs, because aztec-nr's type-complexity limit rejects a contract with about 40 separate state variables.

**Exit test** (P1 exit criterion), on the 6.0.0 local network with real client proofs, not yet on a testnet:

1. Alice and Bob register (7–9 s each, including constrained key delivery) and deposit.
2. Three batches settle, each 7–8 s from send to checkpoint:
   - batch 1: priority requests and a refund;
   - batch 2: Alice rests a bid at 2100 and Bob sells 60 lots into it, then Alice cancels and Bob withdraws;
   - batch 3: the index moves to 2200 and both accounts are refreshed.
3. Bob claims his refund and his withdrawal from the vault using only the published DA and his key.
4. The operator stops. Alice queues one more deposit; after `T_force` anyone activates desert mode.
5. For each user, a fresh client holding only the node, the Bridge address and the user's seed rebuilds the frozen accounts tree from the DA logs (under 50 ms for 3 batches). It opens the user's leaf and registers a claim valued at the frozen index.
6. Alice is refunded her deposit and receives 1,006,000 (long 60 from 2100 to 2200); Bob receives 1,993,000. The vault ends empty.

**Tests:**

- Every segment's circuit output is compared field by field with the engine (differential check).
- 16 adversarial witnesses are rejected for the intended reason, several built by an engine that deliberately skips one rule:
  - forged signature;
  - another account's key;
  - an operator-substituted signing key;
  - replayed nonce;
  - a fill that skips the best order;
  - self-trade;
  - an IOC that stops with crossing liquidity left;
  - a limit outside the band;
  - margin bypasses on orders and withdrawals;
  - oracle forgery, jump and time regression;
  - a wrong encryption key;
  - a deposit credited to another account;
  - an inflated refresh opening.
- 45 Bridge TXE tests.

**Deferred to P2:**

- C1 custody and the D7 token;
- fees, funding and mark ticks;
- liquidation and the insurance account;
- multiple markets and `P_MAX > 1`;
- session keys, and client-proof actions (the tube changes no state in P1);
- receipts;
- refresh-rate enforcement;
- late desert claims and protocol-account seniority;
- triggers, post-only, FOK, GTT and reduce-only.

See `README.md`.

### P2 profile (in progress, 2026-11-21)

P2 is built in increments, each leaving every test green.

- P2.1: multiple markets, oracles with mark and funding ticks, fees, and the protocol accounts.
- P2.2: liquidation and the insurance backstop.
- P2.3: session keys, GTT orders and forced priority requests.
- P2.4: refresh-rate enforcement, late desert claims and protocol-account seniority.
- P2.5: receipts and accountability (first part), then client-proof actions (second part).
- P2.6: client-proof withdrawals.
- P2.7: the client subtree, with a P-256 client circuit.
- P2.8: `ModifyOrder` and `Transfer`.
- P2.9: `CancelAll` in constant time, through order epochs.
- P2.10: dead-order removal, and ticks that read only live orders.
- P2.11: the risk sweep (§8.7), checked at refresh.
- P2.12: a WebAuthn passkey client circuit.
- P2.13: C1 custody over the D7 collateral token.
- P2.14: the collateral token's bridge to L1.
- P2.15: stop and take-profit triggers.
- P2.16: the print summary and bucketed volume and open interest [D1].

These are built. Where they narrow the design, the full design remains normative.

**State** (§6):

- Four market slots (`MARKETS = 4`). A market is listed when its `imr > 0`. Every account has one position slot per market, so the slot is the market id. Every DA entry encrypts all four slots, so no entry reveals which market changed (§4).
- `priv_hash = H(DS_ACCT_PRIV, collateral, pack(p_0), …, pack(p_3), blind)`.
  - `pack(p) = size + entry·2^64 + funding·2^128`, each limb a 64-bit two's complement.
  - `funding` is the market's cumulative funding index when the position last settled.
  - The hashed fields are exactly the plaintext a DA entry encrypts, so decrypting an entry yields the leaf opening.
- `ActivityLeaf = H(DS_ACTV, nonce, keys_root, open_orders, open_bid_m + open_ask_m·2^64 for each m, epoch)`. P2.3 added `keys_root`, and P2.9 added the order `epoch`.
- `MarketLeaf` has 18 fields (16 before P2.15):
  - the book root, the trigger root and the trigger-pending flag (P2.15), and the next sequence number;
  - the index price and its time;
  - the mark, the premium and its time integral, and the last tick time;
  - the cumulative funding index, the last funding rate, the funding window start and the next funding time;
  - open interest long and short;
  - the best bid and best ask proved at the last tick.
- `other_root = H(DS_OTHER, activity_root, markets_hash, refresh_cursor, num_accounts, fees_pending, insurance_micro)`.
  - `markets_hash = H(DS_MKTS, MarketLeaf_0, …, MarketLeaf_3)`. Every segment opens the four markets once and closes them once, the in-circuit RAM pattern of §9.2.
  - `fees_pending` holds fees not yet credited to the fee account.
  - `insurance_pending` holds liquidation fees, and `insurance_micro` holds funding remainders in micro-units; both are owed to the insurance account.
  - The maintenance segment's sweep credits all three to their accounts.
- Genesis holds the insurance account (index 0, class `insurance`) and the fee account (index 1, class `fee`), both with zero balances and a zero blind.
  - The Bridge takes their public parts at deployment, computes the genesis root itself, and publishes the public parts in a `ProtocolAccounts` event.
  - Exit clients rebuild the genesis tree from that event.

**Parameters**, committed in `config_hash`:

- per market: the margin fractions `imr`, `mmr` and `cmr` (§8.3), `price_band`, `max_jump`, `mark_band`, the maker and taker fee rates (ppm, which are hundredths of a basis point), and the liquidation fee;
- three oracle publishers, with a signature threshold `oracle_k`;
- `max_age` and `funding_interval`.

**Segments**:

| Segment | Per proof | Gates | Change from P1 |
| --- | --- | --- | --- |
| `seg_block` | one L3 block, ≤ 4 index updates | 162,307 | k-of-n signatures, a mark tick per update with two 80-level top-of-book walks |
| `seg_priority` | ≤ 4 requests | 155,159 | four position slots; forced withdrawals (margin) |
| `seg_trade` | ≤ 2 signed actions, ≤ 2 matching steps each | 430,513 | any market; funding settlement, fees, FOK, post-only, GTT, reduce-only, self-trade prevention; margin over every market; session keys |
| `seg_refresh` | sweep and ≤ 4 refresh entries | 48,147 | the sweep |
| `seg_liquidate` (P2.2) | ≤ 2 liquidation steps | 386,374 | new |
| `seg_forced` (P2.3) | one forced close or cancel-all | 221,271 | new |

Gate counts are for the P2.3 build. P2.3 added 27% to `seg_trade`: each action proves a session-key slot, and each matching step carries the expired-order removal, whose maker activity update could be merged with the fill's.

**Oracles, mark and funding** (§8.4):

- An index update is signed over `H(DS_ORACLE, domain, market, index, external_mark, time)`, and `oracle_k` of the three publishers must sign it. As in P1, it must be newer than the market's last update and not after the block, and it may move the index by at most `max_jump`.
- Every update is a mark tick:
  - It proves the top of book from the tree aggregates: either an order with no better order on its side, or a walk from an end slot that is never an order showing the side is empty.
  - `mark = clamp(median(index, external_mark, mid), index·(1 ± mark_band))`. `mid` is the midpoint of the best bid and ask, or the index if a side is empty.
  - The premium-EMA and impact-notional components of §8.4 are deferred.
- `premium = (mark − index)/index`, in ppm. Each tick adds the previous premium times the elapsed time to the premium integral.
- Once `next_funding` is reached:
  - `P` is the premium integral's time average since the funding window opened.
  - `rate = clamp(P + clamp(r − P, ±0.05%), ±4%)/8` per interval, in ppm, truncated toward zero.
  - `cum_funding += rate · mark`, in micro-units per lot.
- At most one interval applies per tick. After a gap the schedule restarts at the tick, so funding never accrues across a halt (§8.4).
- Funding settles lazily:
  - When a fill changes a position, the account first receives `floor(−size·(cum − snapshot)/10^6)`.
  - The remainder, in micro-units, accrues to `insurance_micro`.
  - Equity always includes unrealized funding, rounded the same way.

**Trading** (§8.1–§8.6):

- An order names its market, and its limit price must lie within `price_band` of the mark.
- Time in force: GTC, IOC, FOK (reverts unless fully filled) and post-only (rejected if it would take liquidity).
- Reduce-only is allowed only on IOC and FOK orders, and may neither increase nor flip the position. Resting reduce-only orders, and trimming them when a position shrinks, are deferred.
- Self-trade prevention follows the §8.1 default: the taker's own resting order is cancelled and matching continues. The cancellation uses one of the action's matching steps.
- Fees are `ceil(lots·price·rate)` per fill, for maker and taker, and accrue in `fees_pending`.
- The maintenance segment sweeps `fees_pending` into the fee account and whole units of `insurance_micro` into the insurance account, so no trade touches a protocol account's leaf.
- Margin:
  - Equity is valued at the marks, including unrealized funding.
  - `IM = Σ_m worst_m · mark_m · imr_m`.
  - An action that increases the worst-case size in its market needs `equity ≥ IM` afterwards, and a fresh index in every market where the account has a position or open order.
  - A withdrawal needs the same freshness and `equity − amount ≥ IM`.
- Conservation is exact in micro-units. Sum over every account its collateral, `size·mark − entry` and its exact unrealized funding; add `fees_pending` and `insurance_micro/10^6`. The total equals net credited deposits. The native test checks this after every batch.

**DA** (§9.5):

- Change entries omit the public part: 9 fields (tag, index, leaf and six ciphertexts).
- Full entries carry the public part: 13 fields, for registration and refresh.
- An exit client takes each account's public part from its latest full entry.

**Bridge**:

- Settlement carries 28 fields of market data, seven per market: index, index time, mark, cumulative funding, funding rate, best bid and best ask. They are hashed into the header and emitted in `BatchSettled`. P2.16 adds the print summary and the bucketed volume and open interest (13 fields per market) and moves them to the DA log.
- `exit_register` values a user account at the frozen index prices, with funding accrued to the frozen cumulative indices.
- Claims by protocol accounts are rejected until their seniority rule (§12) is built.

**Tests** (P2.1):

- **Native:** three batches across three markets. They cover the rejections (margin, nonce, post-only, FOK, reduce-only), self-trade prevention, a mark tick from a two-sided book, funding one interval later, and fee sweeps. Every segment is compared with the engine field by field, conservation is checked exactly after each batch, and every account is reopened from the DA.
- **Adversarial:** 25 malicious-operator witnesses, each rejected for the intended reason. P2.1 adds:
  - an under-signed index update;
  - top-of-book proofs that hide a side or report a worse order;
  - a self-trade disguised as a fill;
  - FOK, post-only and reduce-only violations;
  - a risk-increasing order on a stale index;
  - an inflated or swapped sweep.
- **TXE:** 47 Bridge tests, including funding accrued to the freeze and deferred protocol-account claims.
- **Exit test** on the 6.0.0 local network, with real client proofs:
  - The Bridge's genesis holds the operator's protocol accounts.
  - Index updates are signed by two of three publishers.
  - Alice and Bob trade in markets 0 and 1. Bob claims a refund and a withdrawal from the DA.
  - An hour of L2 time later, the next indices apply funding, fees are swept and the accounts refreshed.
  - The operator stops and desert mode starts. Each user's fresh exit client rebuilds the frozen tree from the `ProtocolAccounts` event and three DA logs, in under 1 s.
  - Payouts are valued at the frozen indices with funding accrued: Alice 1,005,366 plus her refunded 5,000 deposit, Bob 1,993,513.
  - The vault keeps 121: the fee account's 119 and 2 units of funding rounding, which the protocol accounts claim once §12's seniority rule is built.

**Session keys** (P2.3, §6.4, §7.2):

- `keys_root` is a height-8 tree: 256 slots of `KeyLeaf = H(DS_KEY, pk, market_mask, max_notional, expiry, nonce)`. A slot that was never used is the empty leaf.
- Every action names its signing key: `MASTER_KEY` (256), or a slot. The key id is part of the signed message: `H(DS_ACTION, domain, kind, account, key_id, nonce, p[8])`.
  - The master key's nonce lives in the activity leaf.
  - A slot's nonce lives in its key leaf and is never reset when the slot's key changes, so an old key's signatures cannot be replayed.
- A session key may only place and cancel orders, in the markets of its mask, with `price·lots ≤ max_notional`, and until L3 time passes its expiry. The withdraw, transfer and admin levels of §7.2 stay with the master key.
- `AddKey(slot, pk, mask, max_notional, expiry)` and `RevokeKey(slot)` are master-key actions. They change only the activity tree, so managing keys publishes nothing.

**GTT orders** (P2.3, §6.5):

- `OrderLeaf = H(DS_ORDER, side, account, lots, expiry, epoch)`; P2.9 added the owner's order epoch. Only GTT orders have an expiry, and it must lie in the future when the order is placed.
- When matching meets an expired order, it removes the order instead of filling it, and the owner's open lots shrink. The step counts against the action's matching steps.
- An expired order counts toward its owner's margin until it is removed. Since P2.10 a tick never reads it (see Dead orders).

**Forced priority requests** (P2.3, §7.3, §12):

- `Bridge.submit_forced(kind, account, b, c)` queues a request with `msg_sender` and pays `request_fee` to the operator, so the queue cannot be flooded for free.
  - `ForcedWithdraw(b = recipient)`
  - `ForcedClose(b = market, c = worst price)`
  - `ForcedCancelAll`
  - The request payload gained a fourth field: `payload_hash = H(DS_REQ, kind, a, b, c)`. Existing kinds have `c = 0`, so their hashes did not change.
- A request takes effect only if the account exists and `msg_sender` is its owner. Otherwise, or if a field is out of range, it is consumed without effect. No request's own fields can make a segment unprovable, which would stall the queue into desert mode. For the same reason, a deposit that would push collateral out of range is now refunded.
- `ForcedWithdraw` (in `seg_priority`): withdraws all free collateral, `max(0, min(collateral, equity − IM))`, to the recipient. Equity needs fresh indices wherever the account is exposed. An account that is not exposed needs none, so a user can always close first and then withdraw.
- `ForcedClose` and `ForcedCancelAll` (in `seg_forced`, one per segment):
  - The close is a reduce-only IOC order at the taker fee, no worse than the worst price. It may stop early only when its two matching steps run out or no liquidity is left within that price.
  - Cancel-all advances the account's order epoch, as a signed `CancelAll` does, which voids all its orders at once (P2.9). Before P2.9 it removed `min(4, open orders)` of them per request.
  - In both cases the owner can submit more requests for the rest.

**Liquidation** (P2.2, §8.5):

- Liquidations are operator steps in their own segment. Each step's message is logged as an action. Each precondition is checked at current marks, with fresh indices wherever the accounts involved are exposed.
- Equity includes unrealized funding. `MM = Σ |size|·mark·mmr` and `CM = Σ |size|·mark·cmr`. Only user accounts can be liquidated.

| Step | Precondition | Effect |
| --- | --- | --- |
| Cancel | `equity < MM`, open orders | Advances the account's order epoch, which voids all its resting orders at once (P2.9; before, one order per step). |
| Close | `equity < MM`, no open orders | Closes up to the whole position in one market against the book, reduce-only, at prices no worse than the limit below. Pays the liquidation fee to the insurance fund. |
| Takeover | `equity < CM`, no open orders | The insurance account takes over the position with the lowest unrealized PnL at the mark. Both settle funding first, and the account realizes its PnL. The insurance account must still meet its IM. |
| Deficit | no positions or orders, negative collateral | The insurance account absorbs the deficit and must still meet its IM. |
| ADL | `equity < CM`, no open orders, and a takeover would leave the insurance account below its IM | Closes the smaller of the position and an opposite user position, chosen by the operator, at the bankruptcy price. Ranking the counterparties is phase 3. |

- **Close limit.** `mark ∓ mark·mmr_m·E⁺/MM`, the price at which closing keeps `equity/MM` constant (§8.5). The offset is truncated, so the limit lies on the account's side. An underwater account closes no worse than the mark.
- **Close size.** A close that stops short of its stated size must prove that no liquidity is left within the limit.
- **Liquidation fee.** `ceil(notional·liq_fee)`, capped at the equity left after the close, and accrued to `insurance_pending`.
- **Bankruptcy price.** `mark − E/size`: closing the whole position there brings equity to zero. It is rounded so the bankrupt account ends at or above zero, so the counterparty bears less than one tick per lot. If equity is not negative, the price is the mark.
- **Matching.** Signed orders and closes share one matching routine, `l3x_exchange::matching`.
- **Engine.** A close's size depends on the steps before it in its segment, so the engine plans each segment in a dry run before executing it. It plans an account's whole waterfall the same way: cancel, close while the book can absorb, takeover lowest PnL first or ADL, then deficit.

**Tests** (P2.2):

- **Native**, batch 4: market 0 falls 13% in two signed updates within one block, which leaves two accounts underwater.
  - Eve's waterfall: her resting order is cancelled, 30 lots close against the book, the insurance account takes over the rest and absorbs her deficit.
  - Frank's position is auto-deleveraged against Dave's short at Frank's bankruptcy price, because a takeover would breach the insurance account's IM.
  - Every step is proved, and conservation holds exactly.
- **Adversarial:** 11 more witnesses, 36 in all:
  - liquidating a healthy account or the insurance account;
  - closing before the orders are cancelled, or below the limit;
  - a takeover out of PnL order, beyond the insurance account's margin, or of an account above close-out margin;
  - a deficit with positions left;
  - an ADL while the insurance account could absorb, or against a same-side position;
  - a liquidation on a stale index.
- `EXECUTE_ONLY=1 npm run native` executes every segment and compares it with the engine without proving, in about 10 s.

**Refresh deadline** (P2.4, §9.5):

- The state gains `cycle_start`: the L3 time at which the refresh cursor last wrapped past the last account, recorded by the maintenance segment at the wrap. The batch header carries it, so `HEADER_LEN` is now 18.
- The Bridge requires, for every batch:
  - `cycle_start` never decreases;
  - it is no later than the batch's `max_time`;
  - `max_time ≤ max(cycle_start, deployment time) + t_refresh`.
- So every batch ends within `t_refresh` of the start of the current cycle. An operator who falls behind must complete the cycle in its next batch, and missing the deadline halts settlement, after which desert mode follows its usual course.
- Each account's latest refresh entry is therefore at most two windows old. The cycle it belongs to began within `t_refresh` of the last settled batch, and it took up to one more window to complete.
- A first version counted completed cycles and restarted the clock at the start of a completing batch. It was replaced, because a batch's start says nothing about when within it the cursor wrapped: for a first batch it is L3 time 0, and after a halt it is the pre-halt time.
- `t_refresh` is set at deployment and must leave a margin below the DA's retention (§9.5).

**Receipts and accountability** (P2.5, §11):

- **Sequence numbers.** Every signed action carries the sequencer's sequence number. The state keeps the last one, `last_seq`, across batches, and actions must execute in strictly increasing order.
- **Receipts tree.** An action's receipt leaf is `H(DS_RECEIPT, seq, msg)`.
  - Every node output carries a `receipts_root`. A trade segment's covers its two leaves. Every other segment, and padding (which asserts it), has 0. A merge hashes its children's roots.
  - So the batch's receipts tree has the shape of its merge tree. The header's 19th field is its root, and a receipt's path runs from its segment up through the merges.
- **Receipt.** The operator signs `H(DS_RECEIPT_SIG, domain, msg, seq, issued_at)` with a receipt key named in the Bridge's configuration.
  - Simplification: §11's receipt also commits to the L3 block and an encrypted result. Here it commits only to the action, its number and when it was issued.
- **Bridge.**
  - `post_bond(amount)`: adds to the operator's bond.
  - `challenge(msg, seq, issued_at, sig)`: takes a valid receipt at least `t_settle` old, and the challenger pays `request_fee`. The signature is checked in the private phase.
  - `answer(msg, seq, batch, depth, bits, path)`: the operator shows the leaf in a settled batch's receipts root, and the fee goes to the operator. The path is folded in the private phase, and the public phase compares the result with the stored root.
  - `slash(id)`: once `t_resp` passes unanswered, the challenger gets the fee back plus `slash` from the bond, as far as the bond goes.
  - The bond and open challenges' fees are held apart from the vault, and desert payouts exclude them.
- **Deployment size.** Publishing a contract class puts its public bytecode in the deployment transaction's DA. So the Bridge's public bytecode must fit one transaction's DA budget: 55,836 DA gas, about 1,745 fields, on the 6.0.0 local network.
  - With receipts it first came to 1,734 fields, which the deployment exceeded together with its other effects.
  - Moving the receipt signature check, the receipt path fold and `exit_register`'s leaf and valuation arithmetic into private functions, each finished by an only-self public call, brought it to 1,537 fields.
  - Further Bridge features need the same discipline, or a split into more than one contract.
- **What it proves.** Leaves bind sequence numbers, and the numbers rise with execution. So a receipted action that was dropped, or executed out of order, has no leaf the operator can show, and the operator loses `slash`. Front-running before a receipt is issued is not prevented.

**Tests** (P2.5):

- **TXE**, 65 tests. They cover an answered challenge and a wrong path, a slash and its deadline, a forged receipt, a receipt too recent to challenge, a receipt challenged twice, and desert payouts that leave out the bond.
- **Native:** every receipt has a path to its batch's receipts root: 21 across the five batches of P2.5's first part, 23 since batch 6 was added. The batch prover checks its own receipts tree against the root circuit's.
- **Adversarial:** an action out of sequence order, and padding that claims a receipts root.
- **Exit test**, on the local network, after the operator posts a bond:
  - Bob challenges the receipt of his withdrawal, and the operator answers with the action's path in batch 2.
  - The operator signed a receipt for an action it then dropped. Bob challenges it, nobody can answer, and anyone can then slash the bond to pay him.

**Desert claims** (P2.4, §12):

- An account may register its claim after the window closes (a late claim). The protocol accounts may register too.
- Claims registered within the window share `min(1, V/U)` as before, and the ratio is 1 if no claim was registered in the window. `V` is the vault less the senior obligations when the ratio is fixed, at the first payout. `U` is the total of the window's claims.
- Late claims and protocol claims are paid `min(ratio·equity, residual)`. The residual is the vault less the senior obligations and less what the window's claims are still owed. A late claim can therefore never take from a window claim.
- Protocol claims are payable only `t_late` after the window closes, and `t_late` is set at deployment (default one year). Triggering desert mode cannot profit the operator.

**Tests** (P2.4):

- **TXE**, 57 tests:
  - a late claim paid from the residual;
  - a late claim that gets nothing while a window claim reserves the vault;
  - a protocol claim refused before `t_late` and paid from the residual after it;
  - a refresh-overdue batch rejected;
  - a completed cycle restarting the clock at the wrap;
  - a cycle that starts after its batch, or goes backwards, rejected.
- **Native:** the five batches wrap the refresh cursor twice, and the last wrap's time is the cycle start.
- **Exit test:** after the users exit, the operator opens the fee account from the DA like any user and claims it. It is paid after `t_late`, which leaves the vault holding only funding rounding.

**Tests** (P2.3):

- **Native**, batch 5:
  - A session key rests a GTT bid. The engine refuses its order outside the mask, its order above the notional cap and its withdrawal. After the key is revoked, its next order is refused too.
  - The GTT bid expires, and a sell removes it and fills the next bid.
  - Through the queue: a forced withdrawal; one submitted by a non-owner, which has no effect; a forced close of 70 lots; a forced cancel-all.
- **Adversarial:** 11 more witnesses, 47 in all:
  - a session key outside its markets, above its cap, withdrawing or adding a key;
  - a replayed key nonce, an expired session key, another key in the slot;
  - a GTT order already expired, a GTC order with an expiry;
  - a forced close that stops with liquidity left;
  - a forced cancel-all that leaves cancellable orders.
- **TXE:** 50 tests. New ones cover the request fee and queueing, the kind check, and an unprocessed forced request blocking settlement after `T_force`.
- **Exit test:** Bob forces a withdrawal through the Bridge on the local network. Batch 3 processes it, and he claims the record from the DA.

**Client-proof actions** (P2.5 and P2.6, §7.1, §7.4):

- **P-segment.** A P-segment's leaf is the tube. It verifies the segment's Chonk proof against the pinned Chonk VK. Inside the IVC, `agg_app` verified ten client proofs and folded the first `count` proofs' VK hashes and public inputs: `acc = H(DS_AGG, acc, vk_hash, msg, account_index, auth_binding)`. The client circuit was pinned by a constant in P2.5, and is a member of the client subtree since P2.7.
- **Binding actions to proofs.** The tube takes the actions as witnesses, recomputes that fold from them and requires it to equal the IVC's output. So it applies exactly the actions client proofs authorized, in the order they were aggregated, and drops none.
- **Checks.** For each action, in order:
  - the account exists;
  - `master_auth == H(DS_MAUTH_P, client_vk_hash, auth_binding)`;
  - `msg == H(DS_ACTION, domain, kind, account, MASTER_KEY, nonce, p[8])`, the master-key message of §7.1;
  - `nonce` is the account's master nonce plus one;
  - the kind is `AddKey`, `RevokeKey` or `Withdraw` (P2.6).

  The tube then applies the action with the routine `seg_trade` uses for the same master-key action: `write_key_slot` for a key change, and `withdraw` for a withdrawal, under the same amount, collateral, freshness and margin rules.
- **Records.** The action log records each P-segment once, as `(actions_hash, count)`. Since P2.6 each P-segment opens a DA segment, whose nonce depends on that log entry.
  - A key change publishes nothing: keys live in the activity tree, which is never published.
  - A withdrawal publishes the account's change entry under a fresh blind and appends its record to the batch's withdrawals chain and the DA, as a master-key withdrawal does. Its record is claimed from the Bridge in the same way.
  - The tube's `receipts_root` is 0, because receipts number the operator's sequenced signed actions (§11).
  - The engine builds a P-segment in two passes. The segment nonce, and so every withdrawal's blind, depends on which actions apply. So a dry run first decides which actions apply, and only then is the segment logged, opened and executed.
- **Lane-P accounts.** An account registers with `master_auth = H(DS_MAUTH_P, client_vk_hash, auth_binding)` for one of the client circuits (P2.7).
  - No Schnorr key can sign as its master key, so its master actions travel as client proofs.
  - It trades through session keys that a client proof grants. One proof authorizes many fast signed actions (§7.4).
  - It withdraws by client proof (P2.6), or through `ForcedWithdraw` from its owner's Aztec account.
- **Narrowing.**
  - Of §7.4's default uses, session-key grants and revocations and withdrawals are built. Credentials, and changes of master authorization or `k_enc`, are not.
- **Cost.** The tube applies ten actions. Each has a 32-level account update, a 32-level activity update, an 8-level key-slot update and, for a withdrawal, the margin check, the change entry and the withdrawal record.
  - Key changes (P2.5) took the tube from 1,473,742 gates to 1,592,466 (+8%).
  - Withdrawals (P2.6) take it to 1,673,299 (+5%), still within 2^21.
  - The IVC is unchanged. A P-segment with any number of actions costs one IVC and one tube proof.

**Tests** (P2.5, second part):

- **Native**, batch 6:
  - Grace registers in lane P.
  - A client proof grants her a session key for market 0, which buys 20 lots from Bob.
  - A second proof, in a later P-segment, revokes the key.
  - The engine refuses a proof applied to Alice's lane-S account, a replayed nonce, a withdrawal any Schnorr key signs for Grace's account, and the revoked key's next order.
  - Both P-segments are proved: real client proofs, the Chonk IVC (1.5 s each) and the tube (4.9–6.9 s). The batch is `root(merge(merge(block, priority), merge(tube, trade)), merge(tube, refresh))`, so tubes merge with X-segments like any other node.
  - The DA reopens Grace's account like any other.
- **Adversarial:** 8 more tube witnesses, 57 in all:
  - an action no proof authorized;
  - a proof applied to another action;
  - an aggregated action dropped;
  - a replayed proof;
  - a proof that withdraws;
  - more actions than proof slots;
  - a forged key-slot path;
  - a proof applied to a lane-S account.
- `EXECUTE_ONLY=1 npm run native` executes the tube without its Chonk proof, since witness generation does not check recursive proofs.

**Client circuits** (P2.7, §7.4, §9.3):

- **Client subtree.** `agg_app` verifies each slot's proof against that slot's own VK. barretenberg binds the VK to the slot's VK hash, and `agg_app` requires that hash to be a leaf of the VK tree's client subtree (role 0).
  - The VK tree root is a third field of `AggOutput`, and so of the Chonk proof's public inputs.
  - The tube requires that root to be the one its configuration commits to.
  - So the configuration, changed only by delayed upgrade (§10.1), decides which client circuits may authorize lane-P actions. Adding one changes the VK tree, not `agg_app` or the tube.
- **Binding.** The aggregation folds each proof's VK hash with its public inputs, and a lane-P master authorization names its circuit: `H(DS_MAUTH_P, vk_hash, auth_binding)`. A proof of one circuit therefore never acts for an account bound to another.
- **Circuits**, both with public inputs `(msg, account_index, auth_binding)`:

  | Slot | Circuit | Authorization | `auth_binding` |
  | --- | --- | --- | --- |
  | 0 | `client_auth` | knowledge of a secret | `H(DS_AUTH, secret)` |
  | 1 | `client_p256` | an ECDSA P-256 signature on the message's 32 bytes | `H(DS_P256, x_hi, x_lo, y_hi, y_lo, salt)`: the key's coordinates in 16-byte halves, and a salt the client keeps so the key is not a public identifier |
  | 2 | `client_webauthn` (P2.12) | a WebAuthn assertion whose challenge is the message | `H(DS_WEBAUTHN, x_hi, x_lo, y_hi, y_lo, rp_hi, rp_lo, salt)`, which also binds the relying party ID hash |

- **P-256 keys.** `client_p256` suits hardware keys that sign a digest, such as a Secure Enclave or a TPM. The message is already a domain-separated hash, so it is the digest. Signers use RFC 6979 nonces and low `s`.
  - WebAuthn passkeys sign `authenticatorData ‖ SHA-256(clientDataJSON)` instead. P2.12 adds a circuit that rebuilds that preimage (see Passkeys).
- **Narrowing.** Every circuit in the subtree may authorize every lane-P kind. §7.1's per-kind permission is not built.
- **Cost.** `client_p256` is 46,551 gates and proves in about 250 ms on the reference laptop, against 29 ms for `client_auth`. A VK hash and a 6-level membership path per slot take `agg_app` from 109,564 to 113,267 Mega gates (+3.4%). The tube is unchanged in size.

**ModifyOrder and Transfer** (P2.8, §7.3):

- **ModifyOrder** `(market, side, price, seq, lots)`. It reduces a resting order in place to `lots`, which must be positive and below the order's remaining lots.
  - The order keeps its index, and so its place in the queue.
  - The account's open lots shrink by the difference. Its open-order count does not change.
  - A modification that would add lots or move the price is a cancellation and a new order, sent as two actions.
  - Session keys may modify, in their markets, as the Trade level of §7.2 allows.
- **Transfer** `(amount, destination)`. It needs the master key, the Withdraw level of §7.2.
  - The source is debited under the withdrawal rules: the collateral, fresh indices wherever the account is exposed, and IM afterwards.
  - The destination must be another user account, and its collateral must stay in range. Protocol accounts change only through the sweep and liquidation, so no trade touches their leaves.
  - Both accounts get change entries. A transfer therefore shows which two accounts changed, but never the amount (§4).
- **Shared rules.** `l3x_exchange::trade` now has `debit` and `credit`, and `withdraw` is `debit` plus the withdrawal record. The tube and `seg_trade` use the same routines.
- **Witness.** A trade action carries the destination account's opening and its path, valid after the source's debit.
- **Cost.** `seg_trade` grows from 430,919 to 476,001 gates (+10.5%), still within 2^19: each action slot carries a destination account update and change entry.
- **Not built.** Client-proof transfers, and `CancelAll`.

**CancelAll** (P2.9, §6.5, §7.3):

- **Order epochs.** Every activity leaf carries the account's order epoch, and every order leaf the epoch its owner had when placing it. An order is live while the two are equal, and void once the owner's epoch moves past it.
- **CancelAll** advances the epoch and sets the account's open orders and open lots to zero, in every market. That is one activity update, however many orders rest.
  - Session keys may send it, whatever their market mask, since it only reduces risk.
  - `ForcedCancelAll` and the liquidation cancel step make the same update. A forced cancel-all now completes in one request, `seg_forced` has no cancellation loop, and a liquidation needs at most one cancel step.
- **Lazy removal.** Void orders stay in the book until matching meets them.
  - Every step against another account's order already proves that account's activity. If the epochs differ, the step removes the order without touching the owner's counters, which already exclude it.
  - A taker's own void order is removed the same way, without shrinking its open lots.
  - `CancelOrder` and `ModifyOrder` accept only live orders.
- **Ticks.** In P2.9 a void order still counted toward a tick's top of book, like an expired GTT order, until something removed it. P2.10 closes this (see Dead orders).
- **Cost.** The epoch adds one field to two leaves.
  - Matching was restructured at the same time. A circuit evaluates every branch, so each step used to pay for a book walk and an activity update in each of its cases. It now writes the order's leaf once and, for another account's order, that account's activity once.
  - `seg_trade`: 395,115 gates, down from 476,001 in P2.8.
  - `seg_forced`: 103,254, down from 221,271 in P2.3; it also lost its loop of four 80-level cancellations.
  - `seg_liquidate`: 254,897, down from 386,374 in P2.2.

**Dead orders** (P2.10, §6.5):

- **Removal.** The maintenance segment removes up to four dead orders before its sweep and refreshes.
  - A dead order is void, or an expired GTT order. It proves its owner's activity, which shows which: a moved epoch, or an expiry before the segment's time.
  - An expired order's lots leave its owner's open lots. A void order's already have.
  - Each removal is an operator action, logged as `H(DS_CLEAN, market, side, price, seq)`. A live order cannot be removed.
- **Ticks read only live orders.** For each side, a tick proves the top order's owner activity against the activity root. It requires the same epoch, and no expiry at the block time. A trader can therefore no longer leave an order that cannot fill at the top of the book to move the mark.
- **Operator.** Before ticking a book, the operator removes the dead orders at its top.
  - An order that expires only by the new block's time can be removed only once L3 time reaches it.
  - So the engine first opens the block without updates, then removes the orders, then ticks at the same time. Blocks may repeat a time.
- **Cost.** `seg_block`: 188,143 gates, up 16% for eight activity proofs. `seg_refresh`: 141,339, up from about 48,000, at roughly 23,000 per removal.

**Risk sweep** (P2.11, §8.7):

- **The refresh is the sweep.** A refreshed user account also proves its activity. If its exposure has fresh indices, it must not be below maintenance margin. An account that is due for liquidation must be liquidated before the refresh cursor can pass it.
- **Bound.** The refresh deadline (P2.4) brings every account up for refresh within the refresh window of each cycle's start. So a liquidation that is due at fresh marks happens within about two windows, or settlement halts, as for a missed refresh.
- **Stale indices.** A stale index exempts the account. A liquidation needs fresh indices too (§8.5), and an oracle outage must not stall the refresh.
- **Departure from §8.7.** There is no separate `risk_cursor` or per-batch `Q`. The refresh cursor and the refresh window take their roles, so `R` is the number of batches in a window.
- **Scope.** Protocol accounts are never liquidated, and are not checked.
- **Cost.** `seg_refresh`: 160,565 gates, up 19,000 for four checks.

**Passkeys** (P2.12, §7.4):

- **Circuit.** `client_webauthn` (client slot 2) verifies a WebAuthn assertion as a browser's passkey makes it, so a user can authorize lane-P actions with Face ID or a security key.
- **Challenge.** The challenge is the action message.
  - clientDataJSON must begin with `{"type":"webauthn.get","challenge":"`, then the message's 32 bytes in unpadded base64url, then a closing quote. Browsers serialize these two members first.
  - The rest of clientDataJSON is hashed as signed but not parsed: the origin, `crossOrigin`, and fields browsers sometimes append.
- **Relying party.** authenticatorData is 37 bytes, and its user-present flag must be set.
  - Its first 32 bytes, the SHA-256 of the relying party ID, are bound into `auth_binding` along with the key and a salt.
  - A passkey registered with another site therefore cannot authorize, and the circuit need not check the origin.
- **Signature.** The signature is ECDSA P-256 over `SHA-256(authenticatorData ‖ SHA-256(clientDataJSON))`.
  - clientDataJSON may be up to 311 bytes. The circuit hashes it with the SHA-256 compression function over five blocks and keeps the state after the message's last block. The Noir standard library of this toolchain has the compression function but no `sha256`.
  - Clients convert the DER signature a browser returns to `r ‖ s`, with `s` normalized to the lower half. Both forms are valid ECDSA.
- **Narrowing.**
  - authenticatorData carries no extensions.
  - User verification is not required.
  - Signature counters are not checked; the operator can watch them for cloned authenticators.
- **Cost.** `client_webauthn` is 87,206 gates and proves in 0.7–1 s on the reference laptop, with the build running alongside. The P-256 verification is about half of it (46,551 gates alone in `client_p256`); the seven SHA-256 compressions are a cheap black box.

**C1 custody and the collateral token** (P2.13, §10.3–§10.5):

- **Token.** `ConfidentialToken` (`contracts/ctoken`) implements §10.5: public balances with allowances, credits as nullifier pairs, `shield`, `transfer` (with `authorize_once` for callers acting for `from`), `unshield` and `settle`. Its public bytecode is 213 fields.
- **Deposit.** A depositor shields a public balance and calls `Bridge.deposit`, which pulls the amount through `Token.transfer` under the depositor's authorization. The credit's blind binds the account, refund address and depositor; the opening goes to the operator by constrained delivery.
- **Custody.** One operator call sweeps up to four deposits and pays up to four records through one `Token.settle`, whose public leg is the net. Payout paths are folded in the private phase; the public phase checks their roots against the batches, marks the records paid, queues the deposits and checks that the vault still covers the bond.
- **Queue.** A `Deposit` entry is `(a = account, b = H(DS_DEPAMT, amount, salt), c = refund_to)`. `seg_priority` takes the opening as witness and checks it against `b`. A refund record goes to `refund_to`, salted with the deposit's salt instead of the public entry.
- **Header.** `withdrawals_amount` left the header and `Running` (18 and 13 fields), and the Bridge no longer tracks unpaid withdrawals or queued deposits as public totals. Desert mode instead pays items 2–3 in full until the payout ratio is fixed (§12).
- **Claims.** `claim_withdrawal` waits `T_payout` outside desert mode and pays into the recipient's public balance. It and `desert_refund` fold their hashes in the private phase.
- **Deployment size.** The Bridge's public bytecode grew to 1,664 fields, past the local network's per-transaction DA admission limit (the deployment needed 56,768 of 55,836 DA gas). Moving the claim's path, the refund's entry and the custody event out of public code brought it to 1,598 fields.

**Token bridge** (P2.14, §10.6):

- **Contracts.** `ConfidentialTokenBridge` (`contracts/ctbridge`) is the token's minter, and Aztec's prebuilt `TokenPortal` and `TestERC20` serve as the L1 half in tests. The token gains `mint_confidential`, `burn_public` and `burn_confidential`, all minter-only.
- **Messages.** The bridge rebuilds the portal's message contents in the circuit: the ABI encoding of each pseudo-call with its 4-byte selector, then SHA-256 truncated to a field.

**Triggers** (P2.15, §6.5):

- **Tree.** Each market has a trigger tree with the book's layout and node aggregates, keyed by trigger price. A stop-loss on a long is a DOWN sell, a take-profit an UP sell, and the mirror image for a short. UP triggers use the ask slot, so the lowest price, earliest first, is leftmost; DOWN triggers use the bid slot, so the highest price, earliest first, is rightmost.
  - `TriggerLeaf = H(DS_TRIGGER, dir, side, account, lots, limit, epoch)`. The owner's order epoch makes CancelAll void triggers as it voids orders.
  - `MarketLeaf` gains `trigger_root` and `trigger_pending`: 18 fields.
- **Placement.** `PlaceTrigger` and `CancelTrigger` are signed actions in `seg_trade`, and session keys may send them within their markets and notional. A trigger takes the market's next sequence number and must not be due at the current mark, so placing one never leaves a due trigger unflagged. A void trigger can still be cancelled.
- **Ticks.** Every mark tick proves the next trigger due in each direction and sets `trigger_pending` if either is due at the new mark. While it is set, the market's `PlaceOrder`s are refused. Cancels, modifications, forced closes and liquidations go on, so leaving a due trigger unfired cannot void a forced close.
- **Firing.** `seg_trigger` fires one trigger per segment, logged as the operator action `H(DS_FIRE, market, index)`. It must be the next due in its direction, so due triggers fire in price-time order.
  - A live trigger is a reduce-only IOC order at its limit, paying the taker fee, for at most the owner's position on its other side. It reserves no margin and never increases risk.
  - It stops early only when its two matching steps run out, and then the rest stays in the tree to fire again; otherwise any rest is dropped, once no order within the limit crosses.
  - A void trigger, or one whose owner has nothing left to reduce, is removed without effect.
  - The segment then proves the next trigger due in each direction and clears the flag once none is due.
- **Narrowing.** Triggers are reduce-only and do not expire, so a stop that opens a position is deferred. §7.3's single `PlaceOrder` with a trigger field is built as two separate kinds.
- **Cost.** `seg_block`: 317,728 gates, for two more 80-level walks per update. `seg_trade`: 438,638, for one trigger write per action, placement and cancellation sharing it. `seg_trigger`: 150,096.

**Market data** (P2.16, §8.4, [D1]):

- **Prints.** Every fill against the book, including liquidation closes and trigger firings, records its price and lots in the market's print summary: the last, highest and lowest price, the lots and the quote notional of batch `print_batch`, reset at the batch's first fill. ADL and takeovers are transfers at the bankruptcy price or the mark, not trades, and do not print.
- **Published.** A batch's market data per market is 13 fields: the seven of P2.1, then last, VWAP (quote notional over lots, truncated), high, low, the batch's volume and the open interest. Volume and open interest are rounded down to a power of two, which publishes their magnitude, not their digits. A market without a fill in the batch publishes zero prints.
- **DA log.** The 52 fields go at the head of the batch's DA log, `[DA_LOG_TAG, batch, market_data, payload]`, instead of the `BatchSettled` event: one loop in the Bridge instead of a larger event, which keeps its public bytecode at 1,604 fields. Exit clients read the frozen market data there.
- **Cost.** `MarketLeaf` gains six fields (24 in all). `seg_trade` 442,282 gates; the root stays at 2^23.

**Tests** (P2.16):

- **Native**, batch 9: market 0 publishes the stop's 25 lots at 1695 and the take-profit's 4 at 1795, so last 1795, VWAP 1708, high 1795, low 1695, volume 16 (29 rounded down), and the open interest rounded down; a market without fills publishes zero prints. Every root proof binds the market data through the header.
- **Exit test:** exit clients read the frozen market data from the last DA log.

**Tests** (P2.15):

- **Native**, batch 9:
  - Alice sets a stop-loss and a take-profit on her long in market 0, Bob a stop on his short, and Carol places a trigger and cancels it. A trigger already due is refused.
  - The index falls to 1695. Alice's stop is due, Bob's order in the market is refused, and the stop fires against Dave's bid.
  - At 1780 Bob's stop, voided by his CancelAll, is removed without effect. At 1800 Alice's take-profit fills Carol's 4-lot bid and drops the rest, as no other bid lies within its limit.
  - Every segment is proved, conservation holds exactly, and the DA reopens every account.
- **Adversarial:** 8 more witnesses, 87 in all:
  - a trigger placed already due, and another account's trigger cancelled;
  - a tick that hides the due stops, or reports a lower stop as the next due;
  - an order traded while triggers are due;
  - a take-profit fired before its price, and a stop fired out of order;
  - a firing that drops a stop with bids left within its limit.

**Tests** (P2.14):

- **Bridge TXE:** 15 tests, with TXE injecting the portal's messages: public claims pay only the named recipient, once, and only for the deposited amount from the portal; confidential claims mint a credit, once; exits burn only the caller's balance or credits and return change; only the bridge mints credits or burns; the deployer binds the token once.
- **L1 round trip** (`npm run l1bridge`), on the local network with its anvil L1 and real client proofs:
  - Alice deposits 1,000 on L1 to her L2 public balance and claims it, and 600 without a recipient, which she claims as a credit.
  - She exits 400 of her public balance and 250 of her credit; each exit's message reaches an Outbox root and the portal releases the ERC-20 on L1. The credit's 350 of change stays on L2.
  - The portal ends holding 950, exactly the supply on L2.
  - Claims take 5.9 s (public) and 7.5 s (confidential) with client proving.

**Tests** (P2.13):

- **Token TXE:** 18 tests: shielding, payment with change, unshielding, settlement against a public balance (four payees, the 16-nullifier limit), conservation, double spends, another owner's credit, an invented credit, payment beyond the inputs, and authorization for exactly one call.
- **Bridge TXE:** 82 tests, up from 65. New: deposits wait for custody, need the depositor's authorization and a minimum; only the operator runs custody; a deposit is swept once and cannot be altered; custody nets deposits against payouts, pays a net outflow, pays a record once, cannot inflate or redirect a payout, and never pays from the bond; reclaim waits for `T_dep`, pays only `refund_to`, and races a sweep; a claim waits for `T_payout`; desert refunds are senior in the window and junior after the ratio is fixed.
- **Adversarial:** a deposit credited with an inflated amount, 79 witnesses in all.
- **Native** and every proving suite run unchanged in shape, with deposits queued as commitments.
- **Exit test** on the 6.0.0 local network, with real client proofs:
  - Alice and Bob shield public balances and deposit three times, one spending a deposit's change; the vault stays empty until custody. The operator opens every pending deposit from its delivered openings.
  - Custody 1 sweeps the three deposits (net in 3,000,777). Custody 2 pays Bob's batch-1 refund as a credit (net out 777), which Bob finds by constrained delivery and spends. Custody 3 sweeps a new deposit of Alice's and pays Bob's forced withdrawal (net out 1,972,283).
  - Bob's batch-2 withdrawal, which custody never paid, is claimed from the vault after `t_payout` with the DA and his key alone.
  - In desert mode, Alice's queued deposit is refunded from the vault and her unswept one returns to her as a credit. Payouts match the engine exactly: Alice 1,005,366 plus her 5,000 refund, Bob 16,230, and the fee account's 119 after `t_late`, which leaves 2 units of funding rounding.
  - Every deposit and payout publishes its payer and payee in the token's plaintext log, read back from the transaction's effects, and no amount.
  - Client-proved transaction times on the reference laptop, over two runs: a shield 5.7–7.1 s, a deposit with its authorization 6.5–7.1 s, a custody transaction 6.5–7.3 s.

**Tests** (P2.12):

- **Native**, batch 8: Ivan registers with a passkey and grants a session key with a WebAuthn assertion, proved through the IVC and the tube. The DA reopens his account.
- **Adversarial:** 4 more witnesses, 78 in all: an assertion of another challenge, one without user presence, one from another site, and a registration (`webauthn.create`) in place of an assertion.
- **Simulator.** The simulated authenticator's assertions verify under Node's own ECDSA verifier on the WebAuthn construction. The circuit accepts clientDataJSON of three, four and five blocks.

**Tests** (P2.11):

- **Native:** every refresh across the eight batches passes the check. The engine refuses to refresh an account that is due for liquidation.
- **Adversarial:** a refresh of an account due for liquidation, 74 witnesses in all.

**Tests** (P2.10):

- **Native**, batch 6: before its market-0 tick, a maintenance segment removes the two void asks left by batches 4 and 5. They are Eve's ask, voided by her liquidation's cancel step, and Dave's, voided by his forced cancel-all.
- **Adversarial:** 3 more witnesses, 73 in all: a tick over a void order, a tick over an expired order, and the removal of a live order. The honest sequence for the same book also executes: a block without updates, the removals, then the tick.

**Tests** (P2.9):

- **Native**, batch 8:
  - Heidi's session key cancels all her orders, Alice cancels all with her master key, and Carol's `ForcedCancelAll` voids hers.
  - Bob's sell then meets Heidi's void bid, and Dave's sell meets Carol's. Matching removes both without filling them, and no position changes.
  - The liquidation waterfall of batch 4 cancels Eve's orders with one epoch step.
- **Adversarial:** 70 in all.
  - Two new witnesses: a void order filled, using its owner's activity from before the cancel-all, and a live order removed as void, using an activity whose epoch moved. Neither activity is in the tree.
  - The forced cancel-all case that left orders behind no longer applies.

**Tests** (P2.8):

- **Native**, batch 7:
  - Dave rests a bid of 20 at 1,745, and Heidi's session key rests a bid of 5 behind it at the same price.
  - Dave reduces his bid to 8, which keeps its place: Bob's sell of 10 fills Dave's 8 before 2 of Heidi's.
  - Heidi's key also reduces a market-1 bid, and Alice transfers 25,000 to Heidi.
  - The engine refuses a modification that adds lots and a transfer beyond Alice's collateral. It also refuses transfers to an account that does not exist and to the insurance account, and a transfer signed by Heidi's session key.
  - 30 receipts across the seven batches each have a path to their batch's root.
- **Adversarial:** 7 more witnesses, 69 in all:
  - a modification that adds lots;
  - transfers above the collateral, to a missing account, to the same account and to a protocol account;
  - a transfer published under another key;
  - a session key that transfers.

**Tests** (P2.7):

- **Native**, batch 6: Heidi registers in lane P with a P-256 key. Her session-key grant is aggregated in one P-segment with Grace's, each proof under its own circuit, and she later withdraws by P-256 proof. The DA reopens her account.
- **Adversarial:** 2 more tube witnesses, 62 in all: a proof applied under another client circuit's VK hash, and an aggregation over another VK tree.
- **VK substitution:** 2 more, 9 in all. `rogue_client` authorizes anything without a secret.
  - H: placed in `agg_app` in `client_auth`'s slot, it fails membership at witness generation.
  - I: placed in `agg_app` with `client_auth`'s VK hash, it passes witness generation, but barretenberg refuses the forged VK hash when the Chonk IVC proves.

**Tests** (P2.6):

- **Native**, batch 6: Grace's second P-segment revokes her session key and withdraws 100,000 by client proof. The engine refuses a third proof, for a withdrawal beyond her collateral. Conservation holds with the withdrawal, and the DA reopens her account after it.
- **Adversarial:** 3 more tube witnesses, 60 in all: a withdrawal sent to another recipient, a withdrawal above the collateral, and a withdrawal published under another key. The case of a proof whose action kind is not allowed now uses an order.

**Next increments:**

1. From P3: the ranking of ADL counterparties (§8.5).

P2's remaining exit criteria are outside this repository: a load test at the §14 targets on a testnet, and an external audit.

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
| D7 | Collateral | A new token type with purpose-built bridges, built for this system: amounts hidden, addresses public (confirmed 2026-11-22). The token (§10.5) and its bridge (§10.6: Aztec's standard escrow portal on L1, a purpose-built minter on L2) are built (P2.13, P2.14). The Shield bridge is out of scope. | Existing Aztec stablecoins |
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
