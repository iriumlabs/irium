# PoAW-X Phase 31 — Reward Manifest Wrapper, Caps & Fallback (Implemented)

Formalizes deferred Phase 27 item **1D**: a versioned PoAW-X reward-manifest wrapper, explicit
role-level caps, and a deterministic non-inflationary fallback — built **around** the existing,
working reward validation (no rewrite, no weakening). **Testnet/devnet only. Mainnet hard-off
(`network_id == 0`). NOT audited / production-ready / mainnet-ready.** Branch
`testnet/poawx-phase31-reward-manifest-wrapper-cap-fallback` (from `7e5f805`).

## Manifest wrapper structure (`src/poawx_reward.rs`)

A pure, versioned `PoawxRewardManifestV1` derived from existing data — **no new wire field, no new
block root** (the ext + irx1 root already commit `role_reward` and the coinbase):

- `version, network_id, block_height, total_reward (= subsidy), fee_bps, fee_pkh, fallback`,
  and `outputs: [PoawxRewardRoleOutput; 4]` in canonical order `[Primary, Compute, Verify, Support]`
  (GROSS role allocations, each with `pkh/amount/present`).
- `PoawxRewardRole`, `PoawxRoleRewardCap` (bps ceilings), `PoawxRewardFallbackMode`
  (`FullParticipation` / `PresentRolesOnly`), `PoawxRewardManifestValidationError`.
- `manifest_digest()` — deterministic, for tests/observability (NOT a consensus commitment).

## Cap rules (rounding-aware)

For `[p, c, v, s]` over `total`:
- `c <= floor(2200*total/10000)`, `v <= floor(1300*total/10000)`, `s <= floor(1000*total/10000)` —
  hard per-role ceilings; an absent role must be `0`.
- `p` is the **residual** (`total - c - v - s`); it absorbs the ≤3-wei rounding remainder, so a naive
  `p <= floor(5500*total/10000)` ceiling would wrongly reject valid blocks. `p <= total`.
- `p + c + v + s == minted total <= total_reward` (non-inflationary).
- `total_reward <= subsidy + fees` (here `total == subsidy == block_reward(height)`).
- `fee_bps <= THIRD_PARTY_FEE_CAP_BPS`, fee from PRIMARY only.

Duplicate/alias: the manifest has exactly 4 fixed role slots, each capped independently; no extra
output can inflate a role (the existing exact-match already forbids extra outputs).

## Fallback rules (deterministic, non-inflationary)

`role_amounts_with_fallback(total, present[4])`: each present non-primary role gets its bps floor;
absent roles get `0` and are **not minted**; the rounding remainder attaches to PRIMARY when present,
else not minted. Covers: no other workers, no best worker, too-few finality members, penalized
finality member excluded (via Phase 30 state), one valid miner, and zero participants (mints nothing).
Production today is always **full participation** (deterministic fairness fills all roles); the
fallback is a tested pure spec and is **not** the current production path.

## Rounding rules

Identical to the canonical `multi_role_amounts`: floors for compute/verify/support; remainder to
PRIMARY; exact sum. Verified deterministic for odd/non-divisible totals (incl. `u64::MAX/2`).

## Consensus wiring (additive, gated, mainnet-off)

The existing exact-match (`validate_poawx_coinbase_payout`) already enforces caps/total/non-inflation.
Phase 31 adds an **additive, named** cap gate in `validate_phase20_production_block`, behind
`reward_manifest_caps_enforced(height)` (activation + `IRIUM_POAWX_REWARD_MANIFEST_CAPS_REQUIRED=1`;
**off by default**, mainnet hard-off). When on it re-derives the manifest and asserts caps with explicit
`phase31:` errors — a strict **superset** of the existing check (same `multi_role_amounts`), so it can
only add rejections, never weaken or false-reject. Off by default ⇒ zero regression.

## Tests

`cargo test --lib phase31 -- --test-threads=1` → **9 passed / 0 failed**:

- `phase31_valid_reward_manifest_accepts_55_22_13_10`
- `phase31_rejects_role_cap_overpay` (compute/verify/support over cap)
- `phase31_rejects_total_coinbase_overpay` (declared total > subsidy+fees; primary inflated)
- `phase31_low_participation_fallback_non_inflationary` (absent role not minted; minted ≤ subsidy;
  zero-participant mints nothing)
- `phase31_rounding_is_deterministic` (odd/non-divisible totals; matches canonical split)
- `phase31_penalized_finality_signer_cannot_receive_reward` (real Phase 30 evidence → support
  recipient ineligible → rejected; eligible after window)
- `phase31_manifest_digest_changes_with_content`
- `phase31_mainnet_no_manifest_caps` (gate off for `network_id == 0`)
- `phase31_additive_cap_gate_no_false_reject` (a valid all-gates chain connects with the gate ON)

Regression: full lib suite **784 passed / 0 failed** (was 775; +9). `reward` suite 17/0; `multi_role`
5/0. `poawx-sim` bin **14/0** (+1). Release builds (`iriumd`, `poawx-live-proof-harness`, `poawx-sim`)
succeed.

## Simulation

`poawx-sim` `reward_distribution` now reports `proposer_reward_permille` (550),
`best_worker_reward_permille` (220), `other_worker_reward_permille` (130), `finality_reward_permille`
(100), `unpaid_or_fallback_share_permille`, and `total_reward_cap_respected` — using the real split +
manifest. Deterministic; `reward_caps_and_fallback_modeled` passes.

## Status of 1D

**Closed (formalization + additive enforcement).** Caps/total/non-inflation were already enforced by
exact-match; Phase 31 adds the versioned manifest wrapper, explicit named caps, a deterministic
non-inflationary fallback spec, the penalized-recipient link, and an additive (gated, mainnet-off)
consensus cap gate. No change to `multi_role_amounts`, the canonical coinbase validator, `block_reward`,
LWMA/PoW/anchors, phase21d/21e/22a, finality validation, or mainnet.

**Production-ready: no. Mainnet-ready: no. Audited: no.**
