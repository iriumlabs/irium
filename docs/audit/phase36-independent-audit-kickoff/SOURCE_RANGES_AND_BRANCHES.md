# Source Ranges & Branches — PoAW-X Phases 28–34

All commits verified against `origin` at Phase 36 authoring. Linear chain
`40db1aa → 199ed24 → df0cc92 → 7e5f805 → fae91bb → 8f2a64d → 1a032de → 78d5ca3` (+ `17f8a77` docs).
`origin/main` unchanged at `19c496dc5f2fa08981a109b10eeb257105c28c43`.

Diffstats are incremental (each phase vs. the previous head). Test counts: focused `phaseNN_*`, and the
cumulative full-lib total reported in that phase's doc.

| Phase | Branch (`testnet/poawx-…`) | Commit | Feature | Files / lines (incremental) | Test suites | Audit priority |
|---|---|---|---|---|---|---|
| 28 | `phase28-finalized-reorg-rejection` | `199ed24` | Finalized-checkpoint state + reorg-below-finalized rejection | 6 files, +736/−14 | `phase28_*` 8/0; full lib 756/0 | **High** (reorg safety) |
| 29 | `phase29-double-sign-penalties` | `df0cc92` | Double-sign evidence + replayable penalty state (primitive) | 7 files, +939/−7 | `phase29_*` 12/0; full lib 768/0 | Medium (primitive only) |
| 30 | `phase30-block-carried-doublesign-evidence` | `7e5f805` | Block-carried `DSE1` evidence + finality exclusion | 11 files, +1006/−12 | `phase30_*` 7/0; full lib 775/0 | **High** (consensus enforcement) |
| 31 | `phase31-reward-manifest-wrapper-cap-fallback` | `fae91bb` | Reward manifest wrapper + per-role caps + fallback | 8 files, +1041/−8 | `phase31_*` 9/0; full lib 784/0 | **High** (non-inflation) |
| 32 | `phase32-onchain-ticket-store` | `8f2a64d` | On-chain ticket store + epoch rate-limit + expiry | 11 files, +1251/−10 | `phase32_*` 12/0; full lib 796/0 | **High** (Sybil/replay) |
| 33 | `phase33-dominance-state-commitment` | `1a032de` | Block-carried `DMC1` dominance-state commitment | 11 files, +798/−8 | `phase33_*` 9/0; full lib 805/0 | Medium-High (replay/reorg) |
| 34 | `phase34-adaptive-modes-consensus-integration` | `78d5ca3` | Adaptive-mode (`ADM1`) consensus integration | 11 files, +1801/−28 | `phase34_*` 17/0; full lib 822/0 | **High** (determinism/effects) |

## Per-phase primary files

- **28:** `src/chain.rs` (finalized checkpoint derivation in `connect_block`; `reorg_to_tip` rejection).
- **29:** `src/poawx_doublesign.rs`, `src/poawx_penalty.rs` (+ `src/chain.rs` state field).
- **30:** `src/poawx.rs` (`DSE1`), `src/chain.rs` (`validate_block_double_sign_evidence`, apply,
  `rebuild_doublesign_penalty_from_chain`, finality exclusion in `validate_block_finality`).
- **31:** `src/poawx_reward.rs` (manifest/caps/fallback), `src/chain.rs` (additive cap gate).
- **32:** `src/poawx_ticket.rs` (store/rate-limit/expiry/Sybil), `src/poawx.rs` (`TKT1`), `src/chain.rs`
  (`validate_block_ticket_registrations`, eligibility, `rebuild_ticket_store_from_chain`).
- **33:** `src/poawx_dominance.rs` (`PoawxDominanceCommitmentV1`), `src/poawx.rs` (`DMC1`), `src/chain.rs`
  (`validate_block_dominance_commitment`).
- **34:** `src/poawx_adaptive.rs` (state/signals/transition/`ADM1`), `src/poawx.rs` (`ADM1`), `src/chain.rs`
  (`validate_block_adaptive_commitment`, `enforce_adaptive_mode_effects`,
  `rebuild_adaptive_state_from_chain`, reorg wiring).

## Audit-priority rationale

Start with the **High** items that touch acceptance/reorg/non-inflation (28, 30, 31, 32, 34), then 33,
then the 29 primitive. The single highest-leverage file is `src/chain.rs` (`connect_block` +
`reorg_to_tip` cross-state consistency across all five derived states). See `AUDITOR_REVIEW_GUIDE.md`.
