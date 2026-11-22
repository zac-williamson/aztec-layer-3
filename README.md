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

Toolchain: Aztec **6.0.0** (`.aztecrc`), installed with `aztec-up`, with its bundled `aztec-nargo` (Noir 1.0.0-rc.3) and `aztec-bb`. The scripts run on Node 24, which executes the TypeScript directly, and use the `@aztec-labs` 6.0.0 packages from npm. The spec targets 6.1.0, but neither the installer nor npm publishes its toolchain yet. The v6.0.0 proof-type and size constants match those checked for v6.1 in SPEC.md §3.

## Layout

| Path | Contents |
| --- | --- |
| `circuits/l3x_types` | Shared constants, Poseidon2 sponge, running values and node output, VK tree, DA sponge, `BatchHeader` |
| `circuits/l3x_exchange` | Exchange rules: accounts and positions, activity, markets, order-book tree, signatures, DA encryption, matching, funding, fees, margin, mark ticks, liquidation |
| `circuits/seg_block` | X-segment: L3 block time and up to four k-of-n signed index updates, each a mark and funding tick |
| `circuits/seg_priority` | X-segment: Register, Deposit and ForcedWithdraw requests in queue order (refunds for missing accounts) |
| `circuits/seg_trade` | X-segment: PlaceOrder (GTC, GTT, IOC, FOK, post-only, reduce-only; matching, fees, funding), CancelOrder, ModifyOrder, CancelAll, Withdraw, Transfer, AddKey, RevokeKey, signed by the master key or a session key |
| `circuits/seg_refresh` | X-segment (maintenance): removes void and expired orders, sweeps fees, liquidation fees and funding remainders into the protocol accounts, republishes accounts under fresh keystreams |
| `circuits/seg_liquidate` | X-segment: liquidation steps (cancel, close, insurance takeover, deficit, auto-deleverage), each with its precondition |
| `circuits/seg_forced` | X-segment: a forced close or forced cancel-all from the priority queue |
| `circuits/client_auth` | P-lane client circuit (client slot 0): knowledge of the secret behind an account's auth binding, authorizing `msg` |
| `circuits/client_p256` | P-lane client circuit (client slot 1): an ECDSA P-256 signature on `msg` by the key the auth binding commits to |
| `circuits/agg_app` | Chonk app: verifies 10 client proofs, each against a VK in the VK tree's client subtree, and folds the first `count` with their VK hashes |
| `circuits/{init,tail,hiding}_kernel` | IVC kernels: OINK, HN, HN_FINAL, each pinning its predecessor's VK hash |
| `circuits/tube` | P-segment leaf: verifies the Chonk proof against the pinned Chonk VK, checks the segment's actions against the proofs' aggregation, and applies them (AddKey, RevokeKey, Withdraw) |
| `circuits/padding` | Identity segment, so a single-segment batch still gives the root two children |
| `circuits/merge` | Verifies two merge-tree nodes against the VK tree, checks they chain, outputs the combined transition |
| `circuits/root` | Top merge: closes IPA, opens the end state, builds the withdrawals tree, binds the batch header |
| `circuits/agg_ultra` | M1 measurement: `agg_app`'s checks in plain UltraHonk |
| `circuits/rogue_app`, `circuits/rogue_segment`, `circuits/rogue_client` | Adversarial fixtures for the VK tests; never deployed |
| `circuits/vendor/bb_proof_verification` | Vendored from aztec-packages v6.0.0 (Apache-2.0) |
| `contracts/bridge` | `L3XBridge`: genesis with the protocol accounts, registration with key delivery, C0 deposits, forced requests, settlement, withdrawal claims, desert mode, delayed upgrades; TXE tests |
| `contracts/token` | Minimal public collateral token for C0 (not the D7 token) |
| `scripts/src` | `build.ts`, `prove.ts`, `vk_substitution.ts`, `m1.ts`, and `pipeline.ts` (the batch prover) |
| `scripts/src/exchange` | Engine (mirrors the circuits and builds witnesses), trees, Grumpkin Schnorr, DA decoding, exit client, and the exchange tests |
| `scripts/out` | Generated: VK manifest, batch, measurements and settlement reports (git-ignored) |

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
- Users register, deposit and trade in two markets over three settled batches; funding applies an hour of L2 time later. They claim a refund and a withdrawal from the DA.
- The operator stops and desert mode starts.
- Each user exits with a fresh client that holds only the node, the Bridge address and the user's seed, valued at the frozen indices with funding accrued to the freeze.

It writes `scripts/out/e2e.json`.

```bash
cd contracts && aztec compile && aztec test
```

This compiles the Bridge and runs its TXE tests.

## Status

P0 is complete, P1 is built, and P2 is in progress (SPEC.md §15 has the profiles, and §14 the measurements).

| Item | State |
| --- | --- |
| P0: G1–G5 | Done. Merge tree with uniform node outputs; role-partitioned VK tree; delayed configuration; v6 constants. |
| P0: M1, M4, M5, M7 | Measured. Chonk is 5.3× faster than UltraHonk recursion for 10 client proofs. The network admits at most 1,714 DA fields per settlement on the local network. |
| P1: exchange | One market: accounts, signed orders, matching on the order-book tree, IOC/GTC, cancels, withdrawals, initial margin, oracle index, refresh. |
| P1: custody | C0: deposits into a public vault; withdrawals and refunds paid from the vault on proof of inclusion. |
| P1: DA and exit | Encrypted account entries. A desert-mode exit from DA alone pays every account at the frozen index, pro rata if the vault falls short. |
| P1: tests | Engine and circuit compared on every segment; 16 adversarial witnesses rejected; 45 Bridge TXE tests; end-to-end exit on a local network. |
| P1: not done | The exit criterion names a testnet; the run here is a local network. |
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
| P2: next | C1 custody once the D7 token is specified; WebAuthn passkeys; from P3, ADL ranking. |

## Caveats

- The local network settles epochs synthetically, so a receipt status of `proven` there does not mean an epoch proof was verified. What is real in the end-to-end test: the settlement transaction's client-side Chonk proof, which includes verifying the root proof in-circuit, and the node's check of transaction proofs (`realProofs`).
- TXE does not prove, so the Bridge's TXE tests use a dummy root proof; the proof binding is tested in the end-to-end test.
- Timings come from one laptop run each and are not benchmarks.
- The local network's sequencer builds each block at the next slot, so the end-to-end test moves L2 time with the node's debug API instead of waiting.
- The P-segment lane executes only AddKey, RevokeKey and Withdraw, and any client circuit in the subtree may authorize any of them. The P-256 circuit takes a raw digest, so it suits hardware keys but not yet WebAuthn passkeys.
