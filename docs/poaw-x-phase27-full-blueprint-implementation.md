# PoAW-X Phase 27 — Full-Blueprint Implementation

Status of the Phase 27 effort on branch `testnet/poawx-phase27-full-blueprint-implementation` (from
`2cb5823`). **Testnet/devnet only. NOT audited / production-ready / mainnet-ready.** Mainnet PoAW-X
hard-off (`network_id == 0`). `origin/main` unchanged (`19c496dc5f2fa08981a109b10eeb257105c28c43`).

## Honest summary

Phase 27 began as "implement the remaining seven blueprint systems." A full pre-implementation gap
audit (`docs/poaw-x-phase27-gap-audit.md`, committed first) found that **the repo is not greenfield**:
five of the seven systems were already implemented and consensus-enforced in earlier phases, the
adaptive-modes data layer already existed, and only the **simulation suite was genuinely missing**.

This phase therefore delivered, with full tests:

1. **The gap audit** — an accurate, file:line-referenced map of every system's true state.
2. **The simulation suite** (`src/bin/poawx-sim.rs`) — the one fully-missing, **non-consensus** system:
   a deterministic, off-chain simulator that reuses the **real** consensus primitives.

It **did not** modify any consensus gate. The remaining gaps (Systems 1–3, 5, 6) are additive
**consensus** changes — new wire formats, reorg-below-finalized rejection, persistent penalty/ticket
state, acceptance-behavior changes — each carrying genuine consensus-design decisions. Per the Phase 27
stop conditions (stop on consensus ambiguity, reorg changes, or any step that would weaken
phase21d/21e/22a), these are **deferred to scoped, approval-gated follow-ups** rather than invented
here. They are documented in `docs/poaw-x-phase27-known-limitations.md`.

**This phase is NOT a claim that the full blueprint is complete.** See the validation matrix for the
precise per-system status.

## What each system actually is today (verified)

| System | State | Enforcement |
|--------|-------|-------------|
| 1. Reward manifest / 55-22-13-10 | Enforced | `multi_role_amounts` + coinbase validation in `connect_block` (`chain.rs:2691/2855/3373`); mainnet hard-off |
| 2. Miner tickets / Sybil | Enforced | `validate_phase20_ticket_proofs` (`chain.rs:2922`) when `tickets_enforced`; sybil leading-zero cost |
| 3. Anti-domination | Enforced | `validate_block_dominance_weights` (`chain.rs:1463`), reorg-safe `PersistentDominance`, real `fairness_weight` |
| 4. Puzzle system | Complete | 5 modes, deterministic assignment, `phase21f` enforcement |
| 5. Extended finality + penalties | ~70% enforced | `validate_block_finality` (`chain.rs:1046`), 2/3 threshold, conflict detection; gaps below |
| 6. Adaptive modes | Data layer | `assess()` state machine + policies; not yet wired into block acceptance |
| 7. Simulation suite | **New this phase** | off-chain analysis binary; no consensus surface |

## The simulation suite (`poawx-sim`)

A standalone binary (auto-discovered from `src/bin/`), built with
`cargo build --release --bin poawx-sim`. It is **devnet/testnet model only** and refuses mainnet
(`network_id == 0`).

- **Deterministic**: a fixed `--seed` yields byte-identical JSON (splitmix64 PRNG; no wall-clock, no OS
  RNG). Verified by test `deterministic_report_for_fixed_seed`.
- **Reuses the real primitives**: `poawx_dominance::fairness_weight`, `poawx::multi_role_amounts`,
  `poawx_ticket::leading_zero_bits`, `poawx_puzzle::assign_puzzle_mode`, `poawx_adaptive::assess` — so
  the modeled fairness/reward/sybil/puzzle/adaptive behavior matches what the node computes.
- **Scenarios**: `normal`, `low_participation`, `dominant_miner`, `dominant_pool`, `sybil`, `reorg`,
  `randomness_manipulation`, `reward_distribution`, `finality_attack`, `fresh_wipe`.
- **Configurable**: `--seed`, `--miners`, `--attacker-share` (permille), `--epochs`,
  `--blocks-per-epoch`, `--subsidy`, `--window`, `--sybil-bits`, `--network-id` (non-zero),
  `--scenario`, `--out-dir` (default `./poawx-sim-out`; never `.irium`).
- **Outputs**: `poawx-sim-report.json` + `poawx-sim-report.md` under the explicit out-dir. Non-zero
  exit if any scenario invariant fails (CI-catchable).
- **Metrics**: reward concentration (top-1 and top-group permille), reward Gini (×1000), puzzle-mode
  distribution, sybil registration cost (hashes/identity), adaptive mode, finality-attack thresholds.
- **Tests**: 10 bin tests (`cargo test --bin poawx-sim`), all passing.

Example (seed 1): `dominant_miner` shows a miner with 700‰ of raw work realizing only 475‰ of reward —
the **real** `fairness_weight` reducing concentration without banning the miner. See
`docs/poaw-x-phase27-simulation-results.md`.

## Safety / scope statement

- No consensus gate changed; `phase21d/21e/22a` and PoW/LWMA/difficulty/target/reward untouched.
- Mainnet hard-off preserved; the simulator refuses `network_id == 0`.
- No live nodes, no firewall/sudo, no mainnet/prod, no wallet/key access, no public testnet.
- Baseline `cargo test --lib -- --test-threads=1` remains **748 passed / 0 failed**; the sim adds 10
  bin tests.
- **Not audited, not production-ready, not mainnet-ready.** Public testnet remains gated.
