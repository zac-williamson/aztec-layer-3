# L3X

A confidential order-book exchange rollup on Aztec. [`SPEC.md`](SPEC.md) is the design. This repository holds phases P0 and P1 and the first increments of P2 (SPEC.md §15):

- **P0**: the `rollup-on-aztec` proof pipeline ported to Aztec v6, with a merge tree, a role-partitioned VK tree, and a Bridge that settles batches under a delayed configuration.
- **P1**: a single-market perpetuals exchange.
  - Accounts, deposits and withdrawals through a public vault.
  - Signed limit orders matched on a price-time order-book tree, with margin checks.
  - Encrypted Mode R DA with refresh.
  - A desert-mode exit that needs only the DA and the user's seed.
- **P2.1**: production semantics, first increment.
  - Four market slots, with one position per market in every account.
  - k-of-n signed oracle updates, each a mark tick: the mark is the median of index, the publishers' external mark and the proved book mid, clamped to a band.
  - Hourly funding settled lazily per position, and maker and taker fees, with every rounding against the account.
  - Insurance and fee accounts from genesis.
  - FOK, post-only and reduce-only orders, and self-trade prevention.
- **P2.2**: liquidation (SPEC.md §8.5) as operator steps checked in circuit.
  - The waterfall: cancel the account's orders, close against the book within a ratio-preserving limit, insurance takeover lowest PnL first, deficit absorption.
  - Auto-deleveraging at the bankruptcy price once the insurance account cannot absorb a position.
- **P2.3**: session keys scoped by market, notional cap and expiry; GTT orders, removed when matching meets them expired; forced withdrawals, closes and cancellations submitted through the Bridge.
- **P2.4**: a refresh deadline the Bridge enforces, late desert claims paid from the residual, and protocol accounts paid last, after `t_late`.
- **P2.5**: receipts and accountability, and client-proof actions.
  - Signed actions carry sequence numbers and receipt leaves, rolled up along the merge tree into each batch header. A receipt challenge on the Bridge must be answered with a path, or the operator's bond pays the challenger.
  - Lane-P accounts, whose master authorization is a client circuit rather than a Schnorr key, grant and revoke session keys with client proofs. The Chonk IVC aggregates the proofs, and the tube applies exactly the actions they authorize.
- **P2.6**: client-proof withdrawals. The tube withdraws under the same rules as a master-key withdrawal, through the same library routine. It publishes the account change and the withdrawal record.
- **P2.7**: the client subtree. `agg_app` accepts any client circuit whose VK is in the VK tree's client subtree, so the configuration decides which circuits authorize lane-P actions. A P-256 client circuit joins the secret-knowledge one, for hardware keys.
- **P2.8**: `ModifyOrder` reduces a resting order in place and keeps its queue position; `Transfer` moves collateral between user accounts under the withdrawal rules, revealing which accounts changed but not the amount.
- **P2.9**: `CancelAll` in constant time. Orders record their owner's order epoch; cancelling all advances the epoch, and matching removes void orders when it meets them. Forced cancel-all and liquidation use the same step.
- **P2.10**: dead orders. Maintenance removes void and expired orders, and a tick proves its top-of-book orders live, so an order that cannot fill never moves the mark.
- **P2.11**: the risk sweep. A refreshed account must not be due for liquidation at fresh marks, so with the refresh deadline every due liquidation happens within about two refresh windows.
- **P2.12**: passkeys. A WebAuthn client circuit lets a browser passkey authorize lane-P actions: the assertion's challenge is the action message, and the relying party is bound into the account's authorization.
- **P2.13**: C1 custody over the D7 collateral token, whose amounts are hidden and addresses public.
  - The token keeps public balances and credits: hidden-amount commitments that appear on chain only as a created and a spent nullifier, spendable only by a call from their owner, so contracts hold them without keys.
  - A deposit moves a hidden amount into a credit the Bridge holds and delivers its opening to the operator. The operator's custody transaction sweeps deposits into the public vault and pays settled withdrawals as credits, so only its net is public; the queue holds deposits' amounts as commitments.
  - Unswept deposits return to their refund address after `t_dep`; records custody leaves unpaid are claimable from the vault after `t_payout`.
- **P2.14**: the token's bridge to L1. Aztec's standard escrow portal holds the ERC-20 on L1; the L2 bridge, the token's minter, claims deposits into public balances or straight into credits and burns exits from either.
- **P2.15**: stop and take-profit triggers. Each market keeps a trigger tree beside its book; every mark tick proves whether a trigger is due and, while one is, the market takes no new orders until the operator fires the due triggers in price-time order as reduce-only IOC orders.
- **P2.16**: public market data per D1. Each batch publishes, per market, the last, VWAP, high and low of its fills, and its volume and the open interest rounded down to a power of two.

Toolchain: Aztec **6.0.0** (`.aztecrc`), installed with `aztec-up`, with its bundled `aztec-nargo` (Noir 1.0.0-rc.3) and `aztec-bb`. The scripts run on Node 24, which executes the TypeScript directly, and use the `@aztec-labs` 6.0.0 packages from npm. The spec targets 6.1.0, but neither the installer nor npm publishes its toolchain yet. The v6.0.0 proof-type and size constants match those checked for v6.1 in SPEC.md §3.

## Layout

| Path | Contents |
| --- | --- |
| `circuits/l3x_types` | Shared constants, Poseidon2 sponge, running values and node output, VK tree, DA sponge, `BatchHeader` |
| `circuits/l3x_exchange` | Exchange rules: accounts and positions, activity, markets, order-book tree, signatures, DA encryption, matching, funding, fees, margin, mark ticks, liquidation |
| `circuits/seg_block` | X-segment: L3 block time and up to four k-of-n signed index updates, each a mark and funding tick that also flags due triggers |
| `circuits/seg_priority` | X-segment: Register, Deposit and ForcedWithdraw requests in queue order (refunds for missing accounts) |
| `circuits/seg_trade` | X-segment: PlaceOrder (GTC, GTT, IOC, FOK, post-only, reduce-only; matching, fees, funding), CancelOrder, ModifyOrder, CancelAll, PlaceTrigger, CancelTrigger, Withdraw, Transfer, AddKey, RevokeKey, signed by the master key or a session key |
| `circuits/seg_refresh` | X-segment (maintenance): removes void and expired orders, sweeps fees, liquidation fees and funding remainders into the protocol accounts, republishes accounts under fresh keystreams |
| `circuits/seg_liquidate` | X-segment: liquidation steps (cancel, close, insurance takeover, deficit, auto-deleverage), each with its precondition |
| `circuits/seg_forced` | X-segment: a forced close or forced cancel-all from the priority queue |
| `circuits/seg_trigger` | X-segment: the operator fires the next due stop or take-profit as a reduce-only IOC order and re-proves whether any is still due |
| `circuits/client_auth` | P-lane client circuit (client slot 0): knowledge of the secret behind an account's auth binding, authorizing `msg` |
| `circuits/client_p256` | P-lane client circuit (client slot 1): an ECDSA P-256 signature on `msg` by the key the auth binding commits to |
| `circuits/client_webauthn` | P-lane client circuit (client slot 2): a WebAuthn passkey assertion whose challenge is `msg`, bound to the relying party |
| `circuits/agg_app` | Chonk app: verifies 10 client proofs, each against a VK in the VK tree's client subtree, and folds the first `count` with their VK hashes |
| `circuits/{init,tail,hiding}_kernel` | IVC kernels: OINK, HN, HN_FINAL, each pinning its predecessor's VK hash |
| `circuits/tube` | P-segment leaf: verifies the Chonk proof against the pinned Chonk VK, checks the segment's actions against the proofs' aggregation, and applies them (AddKey, RevokeKey, Withdraw) |
| `circuits/padding` | Identity segment, so a single-segment batch still gives the root two children |
| `circuits/merge` | Verifies two merge-tree nodes against the VK tree, checks they chain, outputs the combined transition |
| `circuits/root` | Top merge: closes IPA, opens the end state, builds the withdrawals tree, binds the batch header |
| `circuits/agg_ultra` | M1 measurement: `agg_app`'s checks in plain UltraHonk |
| `circuits/rogue_app`, `circuits/rogue_segment`, `circuits/rogue_client` | Adversarial fixtures for the VK tests; never deployed |
| `circuits/vendor/bb_proof_verification` | Vendored from aztec-packages v6.0.0 (Apache-2.0) |
| `contracts/bridge` | `L3XBridge`: genesis with the protocol accounts, registration with key delivery, C1 deposits, custody and reclaim, forced requests, settlement, withdrawal claims, desert mode, delayed upgrades; TXE tests |
| `contracts/ctoken` | `ConfidentialToken`, the D7 collateral token: public balances and hidden-amount credits, with every payment's parties public; TXE tests |
| `contracts/ctbridge` | `ConfidentialTokenBridge`, the token's minter and the L2 half of its bridge to L1 (Aztec's `TokenPortal` is the L1 half); TXE tests |
| `scripts/src` | `build.ts`, `prove.ts`, `vk_substitution.ts`, `m1.ts`, and `pipeline.ts` (the batch prover) |
| `scripts/src/exchange` | Engine (mirrors the circuits and builds witnesses), trees, Grumpkin Schnorr, DA decoding, exit client, and the exchange tests |
| `scripts/out` | Generated: VK manifest, batch, measurements and settlement reports (git-ignored) |
| `deployments/aztec-testnet.json` | The public record of the testnet run: addresses, configuration, transactions and results |

`*/src/pinned.nr` files are generated by `build.ts` and are not hand-edited.

## Running

```bash
aztec-up install 6.0.0
```

```bash
cd scripts && npm install
```

```bash
npm run build:circuits
```

The build compiles in dependency order, pins each fixed child's VK hash into its parent, and builds the VK tree. It writes `scripts/out/manifest.json`, which includes the VK tree, the configuration hash and the root VK hash.

```bash
npm run prove
```

This proves one synthetic batch natively, `root(merge(block, priority), priority)`. It writes `scripts/out/batch-1.json` and `scripts/out/measurements.json`.

```bash
npm run vk-substitution
```

This runs the negative tests: a rogue IVC app, rogue segments outside the VK tree or in a borrowed slot or the wrong role, segments that do not chain, a segment under another configuration, and a rogue client circuit in a borrowed client slot or under a forged VK hash. All must be rejected.

```bash
npm run m1
```

This compares aggregating 10 client proofs through Chonk and the tube with doing it in plain UltraHonk. It writes `scripts/out/m1.json`.

```bash
npm run native
```

This runs eight batches natively across markets 0–2. They cover:
- registrations, deposits, a refund and an insurance deposit;
- orders the rules refuse: margin, nonce, post-only, FOK and reduce-only;
- self-trade prevention, a mark tick from a two-sided book, funding an hour later, and fee sweeps;
- a 13% fall in market 0 followed by both liquidation waterfalls, one ending in an insurance takeover and deficit, the other in auto-deleveraging;
- a session key's trading and refusals, a GTT order removed after expiry, and forced withdraw, close and cancel-all requests;
- a lane-P account whose session key is granted and revoked, and whose collateral is withdrawn, by client proofs, and a second lane-P account authorizing with a P-256 key; each P-segment is proved through the Chonk IVC and the tube;
- an order reduced in place that keeps its queue position, a session key's modification, and a transfer between accounts;
- cancel-all by a session key, a master key and a forced request, with the void orders removed by later sells instead of filled.

Each segment's circuit output is checked against the engine, and conservation is checked exactly, in micro-units, after every batch. Every account is then reopened from the DA alone. The run writes `scripts/out/native.json`.

With `EXECUTE_ONLY=1`, the segments are executed and compared with the engine but not proved, which takes seconds instead of minutes.

```bash
npm run adversarial
```

This checks that malicious-operator witnesses are rejected by the segment circuits, each for the intended reason.

```bash
npm run e2e
```

This runs the exit test on an in-process 6.0.0 local network, with real client-side proofs:
- Users register, shield token balances into credits, and deposit them; the operator's custody transactions sweep deposits into the vault and pay withdrawals and refunds as credits. They trade in two markets over three settled batches; funding applies an hour of L2 time later. One withdrawal custody leaves unpaid is claimed from the vault after `t_payout`, with the DA alone.
- The operator stops and desert mode starts. A deposit custody queued is refunded from the vault, and one it never swept returns as a credit.
- Each user exits with a fresh client that holds only the node, the Bridge address and the user's seed, valued at the frozen indices with funding accrued to the freeze.

It writes `scripts/out/e2e.json`.

```bash
npm run l1bridge
```

This runs the token's bridge round trip on a local network with its anvil L1: public and confidential deposits from L1 claimed on L2, and public and confidential exits released by the portal on L1. It writes `scripts/out/l1bridge.json`.

```bash
npm run testnet -- operate
```

```bash
npm run testnet -- exit
```

These run the P1 exit criterion on the public Aztec testnet (6.0.0, L1 Sepolia), with real client and batch proofs and every fee paid by the network's sponsored FPC:
- `operate` deploys the collateral token and the Bridge; Alice and Bob register, shield and deposit. The operator sweeps the deposits and settles three proved batches (the deposits, trades in two markets, a fee sweep with a refresh), then stops, and Bob forces a withdrawal that nobody processes.
- `exit` runs in a new process with an empty wallet. It waits until Bob's request is `t_force` overdue, activates desert mode, rebuilds each account from the DA logs alone, and withdraws each claim once the window closes; the fee account is paid after `t_late`.

`npm run testnet -- local` rehearses both against an in-process local network. The testnet-only keys are created in `scripts/out/testnet-keys.json`, and the public record of the run is `deployments/aztec-testnet.json`.

```bash
npm run testnet -- l1
```

This runs the token's bridge round trip between Sepolia and the testnet. It needs Sepolia ETH on the L1 key in `scripts/out/testnet-keys.json`, and it resumes where it stopped, since each exit waits for its epoch to be proven on L1.

```bash
cd contracts && aztec compile && aztec test
```

This compiles the token, its bridge and the exchange Bridge and runs their TXE tests.

## Status

P0 is complete, P1 is complete, and P2 is in progress (SPEC.md §15 has the profiles, and §14 the measurements).

| Item | State |
| --- | --- |
| P0: G1–G5 | Done. Merge tree with uniform node outputs; role-partitioned VK tree; delayed configuration; v6 constants. |
| P0: M1, M4, M5, M7 | Measured. Chonk is 5.3× faster than UltraHonk recursion for 10 client proofs. The network admits at most 1,714 DA fields per settlement on the local network. |
| P1: exchange | One market: accounts, signed orders, matching on the order-book tree, IOC/GTC, cancels, withdrawals, initial margin, oracle index, refresh. |
| P1: custody | C0: deposits into a public vault; withdrawals and refunds paid from the vault on proof of inclusion. |
| P1: DA and exit | Encrypted account entries. A desert-mode exit from DA alone pays every account at the frozen index, pro rata if the vault falls short. |
| P1: tests | Engine and circuit compared on every segment; 16 adversarial witnesses rejected; 45 Bridge TXE tests; end-to-end exit on a local network. |
| P1: testnet | The exit criterion, met on the public Aztec testnet on 2026-11-23 with the P2.16 build. Three proved batches settled through the Bridge; then the operator stopped, and clients with empty wallets exited from the DA alone (SPEC.md §15, Testnet run; `deployments/aztec-testnet.json`). |
| Testnet: token bridge | The same day, between Sepolia and the testnet: public and confidential deposits from L1 claimed on L2, and public and confidential exits released by the portal on Sepolia once their epoch was proven, about 29 minutes after the burn. The portal ends holding exactly the token's supply on L2. |
| P2.1: markets, mark, funding, fees | Four market slots; k-of-n oracle updates as mark ticks with proved top of book; lazy funding and fees with every rounding against the account; insurance and fee accounts from genesis, credited by a sweep; FOK, post-only, reduce-only, self-trade prevention. |
| P2.1: tests | Native run with exact conservation after every batch; 25 adversarial witnesses rejected; 47 Bridge TXE tests; the exit test on a local network with funding accrued to the freeze. |
| P2.2: liquidation | Cancel, close within the ratio-preserving limit, insurance takeover lowest PnL first, deficit absorption, auto-deleveraging at the bankruptcy price; preconditions checked in circuit at fresh marks. |
| P2.2: tests | Both liquidation waterfalls proved in the native run; 11 more adversarial witnesses (36 in all). |
| P2.3: keys, GTT, forced requests | Session keys (256 slots, scoped by markets, notional and expiry, nonces never reset); GTT orders; forced withdraw, close and cancel-all through `Bridge.submit_forced`, consumed without effect unless valid and from the owner. |
| P2.3: tests | Native batch 5; 11 more adversarial witnesses (47); 50 TXE tests; a forced withdrawal through the Bridge in the exit test. |
| P2.4: refresh, desert seniority | The Bridge rejects batches past the refresh deadline unless they complete a refresh cycle; late claims and protocol claims are paid from the residual at no better than the window ratio, protocol claims only after `t_late`. |
| P2.4: tests | 57 TXE tests; the exit test's operator claims the fee account after `t_late`, leaving only funding rounding in the vault. |
| P2.5: receipts | Sequence numbers in execution order; a receipts root per batch along the merge tree; Bridge bond, challenges, answers with paths, and slashing. |
| P2.5: tests | 65 TXE tests; every receipt's path checked in the native run; the exit test answers one challenge and slashes the bond for a dropped receipt. |
| P2.5: client-proof actions | Lane-P master authorization `H(DS_MAUTH_P, client_vk_hash, auth_binding)`; the tube recomputes the IVC's aggregation from the actions and applies AddKey and RevokeKey with the next master nonce. |
| P2.5: tests | Native batch 6 proves two P-segments with real client proofs; 8 more adversarial tube witnesses (57 in all). |
| P2.6: client-proof withdrawals | The tube opens a DA segment and withdraws under seg_trade's rules (shared `withdraw`), publishing the change entry and the withdrawal record. |
| P2.6: tests | Native batch 6 withdraws by client proof; 3 more adversarial tube witnesses (60 in all). |
| P2.7: client subtree | `agg_app` checks each client VK's membership in the client subtree and outputs the VK tree root, which the tube binds to the configuration; `client_p256` for hardware P-256 keys. |
| P2.7: tests | Native batch 6 aggregates proofs of both client circuits in one P-segment; 2 more adversarial tube witnesses (62 in all); VK substitution tests H and I for a rogue client circuit (9 in all). |
| P2.8: modify, transfer | ModifyOrder reduces an order in place (session keys allowed); Transfer debits under the withdrawal rules and credits another user account, both republished. |
| P2.8: tests | Native batch 7 shows a modified order keeping its place; 7 more adversarial witnesses (69 in all). |
| P2.9: cancel-all | Order epochs: CancelAll, ForcedCancelAll and the liquidation cancel step void every order in one activity update; matching removes void orders lazily, and writes each order leaf and maker activity once per step (seg_trade 395k gates, seg_forced 103k, seg_liquidate 255k). |
| P2.9: tests | Native batch 8 voids orders three ways and shows them removed without fills; 2 new adversarial witnesses (70 in all). |
| P2.10: dead orders | Maintenance removes up to four void or expired orders, each logged; ticks prove their top-of-book orders live and unexpired. |
| P2.10: tests | Native batch 6 clears two void asks before ticking; 3 more adversarial witnesses (73 in all). |
| P2.11: risk sweep | The refresh checks each user account at fresh marks (equity ≥ MM, or liquidate first); stale indices exempt an account so an oracle outage cannot stall refresh. |
| P2.11: tests | Every native refresh passes the check; 1 more adversarial witness (74 in all). |
| P2.12: passkeys | client_webauthn checks the challenge, user presence and relying party, hashes clientDataJSON (up to 311 bytes) with SHA-256, and verifies the P-256 assertion signature. |
| P2.12: tests | Native batch 8 grants a session key by passkey; 4 more adversarial witnesses (78 in all); the simulated authenticator agrees with Node's ECDSA verifier. |
| P2.13: custody | The D7 token (credits as nullifier pairs, constrained delivery of openings, plaintext parties); deposits into Bridge-held credits; custody netting up to four deposits and four payouts against the vault; reclaim after `t_dep`; claims after `t_payout`; deposit amounts committed in the queue; no withdrawal total in the header. |
| P2.13: tests | 18 token TXE tests; 82 Bridge TXE tests; 1 more adversarial witness (79 in all); the exit test deposits through custody, receives payouts as credits, and refunds and reclaims deposits in desert mode. |
| P2.14: token bridge | `ConfidentialTokenBridge` mints claimed L1 deposits into public balances or credits and burns exits; Aztec's `TokenPortal` escrows the ERC-20 on L1. |
| P2.14: tests | 15 bridge TXE tests; an L1 round trip through deposits, claims, exits and Outbox withdrawals on the local network. |
| P2.15: triggers | Trigger trees per market; ticks flag due triggers and block new orders; `seg_trigger` fires them in price-time order, reduce-only, keeping a remainder only when its matching steps run out. |
| P2.15: tests | Native batch 9 fires a stop, removes a void stop and partly fills a take-profit; 8 more adversarial witnesses (87 in all). |
| P2.16: market data | Per-batch print summary (last, VWAP, high, low) and bucketed volume and open interest in the header's market data, published at the head of the DA log. |
| P2.16: tests | Native batch 9 checks market 0's prints and buckets; every root proof binds them; exit clients read the frozen market data from the DA log. |
| P2: next | From P3, ADL ranking. A testnet load test and an external audit remain P2's exit criteria. |

## Caveats

- The local network settles epochs synthetically, so a receipt status of `proven` there does not mean an epoch proof was verified. What is real in the end-to-end test: the settlement transaction's client-side Chonk proof, which includes verifying the root proof in-circuit, and the node's check of transaction proofs (`realProofs`).
- TXE does not prove, so the Bridge's TXE tests use a dummy root proof; the proof binding is tested in the end-to-end test.
- Timings come from one laptop run each and are not benchmarks.
- The local network's sequencer builds each block at the next slot, so the end-to-end test moves L2 time with the node's debug API instead of waiting.
- The P-segment lane executes only AddKey, RevokeKey and Withdraw, and any client circuit in the subtree may authorize any of them. The P-256 circuit takes a raw digest, so it suits hardware keys but not yet WebAuthn passkeys.
