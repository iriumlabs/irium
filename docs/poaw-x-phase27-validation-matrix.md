# PoAW-X Phase 27 — Validation Matrix

Per-system status against the Phase 27 blueprint, with the tests that back each claim. **Testnet/devnet
only. NOT audited / production-ready / mainnet-ready.** Branch
`testnet/poawx-phase27-full-blueprint-implementation`.

Legend: **Done** = implemented + tested + (where applicable) consensus-enforced. **Enforced w/ gaps** =
core enforced; specific additive gaps deferred. **Data-only** = implemented but not wired into
consensus. **New** = delivered this phase.

| # | System | Status | Consensus-enforced? | Backing tests |
|---|--------|--------|---------------------|---------------|
| 1 | Reward manifest / 55-22-13-10 | Enforced w/ gaps | Yes (`connect_block`) | `phase20_multi_role_amounts_exact_split_and_remainder`, `phase20_bps_constants_total_10000`, `phase20_multi_role_coinbase_valid_accepted`, `phase20_multi_role_coinbase_rejections`, `phase20_production_gate_requires_multirole_and_fairness_mainnet_off` |
| 2 | Miner tickets / Sybil | Enforced w/ gaps | Yes (`validate_phase20_ticket_proofs`) | `ticket_validate_accept_and_rejects`, `sybil_threshold_disabled_permits_enabled_rejects_insufficient`, `ticket_proof_roundtrip_and_validate`, `phase21b_ticket_penalty_enforcement` |
| 3 | Anti-domination | Enforced w/ gaps | Yes (`validate_block_dominance_weights`) | `persistent_apply_revert_exact_inverse`, `persistent_recent_share_and_weight`, `persistent_digest_deterministic_regardless_of_apply_order`, `phase21c_dominance_weight_enforcement`, `phase21c_dominance_connect_disconnect_reorg` |
| 4 | Puzzle system | **Done** | Yes (`phase21f`) | `solve_and_verify_each_mode`, `mode_assignment_deterministic_and_bound`, `threshold_modes_reject_wrong_nonce_and_below_threshold`, `wrong_solver_or_seed_changes_challenge_and_invalidates`, `phase21f_puzzle_enforcement` |
| 5 | Extended finality + penalties | Enforced w/ gaps | Yes (`phase21h`) | `vote_sign_verify_and_rejects`, `proof_threshold_pass_and_fail`, `finality_gossip_cache_ingest_dedupe_window_prune`, `phase21h_finality_enforcement`, `penalty_escalation_and_expiry` |
| 6 | Adaptive modes | Data-only | No (not wired) | `healthy_is_normal`, `low_miner_count_is_caution_not_halt`, `reorg_or_invalid_or_concentration_is_defense`, `defense_to_recovery_then_normal`, `gate_logic_pure` |
| 7 | Simulation suite | **New (Done)** | N/A (off-chain) | `deterministic_report_for_fixed_seed`, `normal_scenario_completes_and_does_not_halt`, `low_participation_does_not_halt`, `dominant_miner_share_is_reduced_by_fairness`, `sybil_cost_nonzero_when_bits_set`, `reorg_scenario_measures_attacker`, `report_has_all_scenarios`, `reward_split_matches_real_primitive`, +2 |

## Simulation-suite acceptance checks (this phase)

| Requirement | Test | Result |
|-------------|------|--------|
| Deterministic output for fixed seed | `deterministic_report_for_fixed_seed` + CLI diff | byte-identical |
| Normal scenario completes | `normal_scenario_completes_and_does_not_halt` | pass |
| Low participation completes (no halt) | `low_participation_does_not_halt` | pass |
| Dominant miner concentration measured | `dominant_miner_share_is_reduced_by_fairness` | pass (raw 700‰ → reward 475‰ @ seed 1) |
| Sybil attacker cost measured | `sybil_cost_nonzero_when_bits_set` | pass (~130k hashes/identity @ 16 bits) |
| Reorg attempt measured | `reorg_scenario_measures_attacker` | pass |
| Report generated (JSON + MD) | CLI run + file check | pass |
| No real network / wallets / mainnet | `mainnet_network_id_is_refused_in_model` + design | pass |
| Uses real reward split | `reward_split_matches_real_primitive` | pass ([550000,220000,130000,100000]) |

## Build / test commands

```
cargo test --lib -- --test-threads=1                 # baseline 748/0 (unchanged this phase)
cargo test --bin poawx-sim -- --test-threads=1       # 10/0 (new)
cargo build --release --bin iriumd --bin poawx-live-proof-harness
cargo build --release --bin poawx-sim
./target/release/poawx-sim --seed 1 --scenario all --out-dir ./poawx-sim-out
```

## What is NOT validated here

The "Enforced w/ gaps" and "Data-only" rows have **deferred** consensus items (finalized-checkpoint
reorg rejection, dominance-state commitment, manifest wrapper, double-sign→penalty wiring, adaptive
integration). These are **not** implemented this phase and are listed in
`docs/poaw-x-phase27-known-limitations.md`. The matrix above reflects the **true** state, not a
completion claim.
