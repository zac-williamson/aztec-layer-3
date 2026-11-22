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
- **P2.5**: receipts and accountability. Signed actions carry sequence numbers and receipt leaves, rolled up along the merge tree into each batch header. A receipt challenge on the Bridge must be answered with a path, or the operator's bond pays the challenger.

Toolchain: Aztec **6.0.0** (`.aztecrc`), installed with `aztec-up`, with its bundled `aztec-nargo` (Noir 1.0.0-rc.3) and `aztec-bb`. The scripts run on Node 24, which executes the TypeScript directly, and use the `@aztec-labs` 6.0.0 packages from npm. The spec targets 6.1.0, but neither the installer nor npm publishes its toolchain yet. The v6.0.0 proof-type and size constants match those checked for v6.1 in SPEC.md §3.

## Layout

| Path | Contents |
| --- | --- |
| `circuits/l3x_types` | Shared constants, Poseidon2 sponge, running values and node output, VK tree, DA sponge, `BatchHeader` |
| `circuits/l3x_exchange` | Exchange rules: accounts and positions, activity, markets, order-book tree, signatures, DA encryption, matching, funding, fees, margin, mark ticks, liquidation |
| `circuits/seg_block` | X-segment: L3 block time and up to four k-of-n signed index updates, each a mark and funding tick |
| `circuits/seg_priority` | X-segment: Register, Deposit and ForcedWithdraw requests in queue order (refunds for missing accounts) |
| `circuits/seg_trade` | X-segment: PlaceOrder (GTC, GTT, IOC, FOK, post-only, reduce-only; matching, fees, funding), CancelOrder, Withdraw, AddKey, RevokeKey, signed by the master key or a session key |
| `circuits/seg_refresh` | X-segment (maintenance): sweeps fees, liquidation fees and funding remainders into the protocol accounts, republishes accounts under fresh keystreams |
| `circuits/seg_liquidate` | X-segment: liquidation steps (cancel, close, insurance takeover, deficit, auto-deleverage), each with its precondition |
| `circuits/seg_forced` | X-segment: a forced close or forced cancel-all from the priority queue |
| `circuits/client_auth` | P-lane client circuit: knowledge of the secret behind an account's auth binding, authorizing `msg` |
| `circuits/agg_app` | Chonk app: verifies 10 client proofs against the pinned client VK and folds the first `count` |
| `circuits/{init,tail,hiding}_kernel` | IVC kernels: OINK, HN, HN_FINAL, each pinning its predecessor's VK hash |
| `circuits/tube` | P-segment leaf: verifies the Chonk proof against the pinned Chonk VK and applies the segment's effect |
| `circuits/padding` | Identity segment, so a single-segment batch still gives the root two children |
| `circuits/merge` | Verifies two merge-tree nodes against the VK tree, checks they chain, outputs the combined transition |
| `circuits/root` | Top merge: closes IPA, opens the end state, builds the withdrawals tree, binds the batch header |
| `circuits/agg_ultra` | M1 measurement: `agg_app`'s checks in plain UltraHonk |
| `circuits/rogue_app`, `circuits/rogue_segment` | Adversarial fixtures for the VK tests; never deployed |
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

This runs the negative tests: a rogue IVC app, rogue segments outside the VK tree or in a borrowed slot or the wrong role, segments that do not chain, and a segment under another configuration. All must be rejected.

```bash
npm run m1
```

This compares aggregating 10 client proofs through Chonk and the tube with doing it in plain UltraHonk. It writes `scripts/out/m1.json`.

```bash
npm run native
```

This runs five batches natively across markets 0–2. They cover:
- registrations, deposits, a refund and an insurance deposit;
- orders the rules refuse: margin, nonce, post-only, FOK and reduce-only;
- self-trade prevention, a mark tick from a two-sided book, funding an hour later, and fee sweeps;
- a 13% fall in market 0 followed by both liquidation waterfalls, one ending in an insurance takeover and deficit, the other in auto-deleveraging;
- a session key's trading and refusals, a GTT order removed after expiry, and forced withdraw, close and cancel-all requests.

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
| P2: next | Client-proof actions (P-lane); C1 custody once the D7 token is specified. |

## Caveats

- The local network settles epochs synthetically, so a receipt status of `proven` there does not mean an epoch proof was verified. What is real in the end-to-end test: the settlement transaction's client-side Chonk proof, which includes verifying the root proof in-circuit, and the node's check of transaction proofs (`realProofs`).
- TXE does not prove, so the Bridge's TXE tests use a dummy root proof; the proof binding is tested in the end-to-end test.
- Timings come from one laptop run each and are not benchmarks.
- The local network's sequencer builds each block at the next slot, so the end-to-end test moves L2 time with the node's debug API instead of waiting.
- The P0 client circuit and the tube are kept for the P-segment lane, which executes no actions until P2.5.
