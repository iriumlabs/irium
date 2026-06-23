# PoAW-X Phase 31 — Reward Manifest Wrapper, Caps & Fallback: Design

Formalizes deferred Phase 27 item **1D**: a versioned PoAW-X reward-manifest wrapper, explicit
role-level caps, and a deterministic non-inflationary fallback — **around** the existing, working reward
validation (no rewrite, no weakening). **Testnet/devnet only. Mainnet hard-off (`network_id == 0`). NOT
audited / production-ready / mainnet-ready.** Branch
`testnet/poawx-phase31-reward-manifest-wrapper-cap-fallback` (from `7e5f805`).

## Current reward enforcement (audited)

- **Constants** (`src/poawx.rs:85`): `MULTI_ROLE_{PRIMARY,COMPUTE,VERIFY,SUPPORT}_BPS = 5500/2200/1300/1000`,
  total 10000.
- **Split** (`multi_role_amounts(total)`, `:147`): `compute/verify/support = floor(bps*total/10000)`;
  `primary = total - compute - verify - support` (the residual — it absorbs the ≤3-wei rounding
  remainder, so `primary >= floor(5500*total/10000)`). Sum is **exactly** `total`.
- **Fee** (`apply_fee`, `:201`): `fee = floor(primary_gross*fee_bps/10000)`, taken **only** from
  PRIMARY; capped at `THIRD_PARTY_FEE_CAP_BPS = 200`; official mode = 0%.
- **Coinbase validation** (`validate_poawx_coinbase_payout`, `src/chain.rs:2956`;
  `validate_multi_role_coinbase_outputs`, `:2883`): the coinbase outputs must **exactly equal**
  `multi_role_amounts(total)` (+ optional fee) — exact pkh, amount, order, count; value-bearing
  non-P2PKH (hidden fee) rejected; `sum == total` re-checked.
- **Entry** (`validate_phase20_production_block`, `:3120`, called from `connect_block` at `:3639`):
  `total_reward = block_reward(height)` (the subsidy). Roles are **always** filled by the deterministic
  fairness assignment, so there is no missing-role case in production.

**Therefore caps + total + non-inflation are ALREADY enforced by exact-match:** each role output ==
its bps floor (≤ its cap), `primary` is the residual (≤ total), and `sum == total == subsidy`. The
general coinbase-value check in `validate_and_apply_transactions` independently bounds total coinbase to
`subsidy + fees`. A penalized finality signer is already excluded from being a committee voter
(Phase 30), so cannot anchor the SUPPORT/finality reward.

## What "wrapper" should contain (formalization, no new wire/root)

A **pure, versioned** `PoawxRewardManifestV1` derived from existing data (no new block field, no new
root — the ext + irx1 root already commit `role_reward` and the coinbase):

- `network_id`, `block_height`, `total_reward` (= subsidy), optional `fee_bps`/`fee_pkh`.
- The four role recipients + amounts (proposer/primary, best-worker/compute, verify, support/finality)
  derived from `multi_role_amounts` + `apply_fee`.
- `PoawxRoleRewardCap` per role (the bps ceilings).
- `PoawxRewardFallbackMode` (participation policy).
- A `manifest_digest()` (deterministic, for tests/observability) — NOT a new consensus commitment.

## Exact cap rules (rounding-aware)

For claimed amounts `[p, c, v, s]` over `total`:
- `c <= floor(2200*total/10000)`, `v <= floor(1300*total/10000)`, `s <= floor(1000*total/10000)`
  (hard per-role ceilings).
- `p == total - c - v - s` (PRIMARY is the residual; absorbs the ≤3-wei remainder; never minted beyond
  `total`).
- `p + c + v + s == total` (exact; non-inflationary).
- `total <= subsidy + fees` (here `total == subsidy == block_reward(height)`).
- Fee (if any) `<= THIRD_PARTY_FEE_CAP_BPS`, taken only from PRIMARY.

A naive `p <= floor(5500*total/10000)` ceiling would be **wrong** (it rejects the legitimate
remainder-to-primary); the residual rule above is the correct rounding-aware cap.

## Deterministic fallback rules (non-inflationary)

Current production = **full participation** (all 4 roles paid). The formal fallback policy
(`PoawxRewardFallbackMode`) for low participation, implemented as a pure function and documented:

- Each **present** role gets its bps-floor amount; **absent** roles get **0** and their share is
  **NOT minted** (total minted strictly decreases — never redistributed beyond caps, never inflated).
- The rounding remainder attaches to PRIMARY when present; if PRIMARY is absent the remainder is not
  minted (lost), never reassigned to exceed a cap.
- A recipient is "present" only if it has a valid eligible role recipient under the EXISTING rules
  (valid claim/admission/puzzle/ticket; not a penalized/suspended finality signer). Fallback never
  pays invalid/missing work.
- Cases: (1) no other workers, (2) no best worker, (3) too few finality members, (4) penalized
  finality member excluded, (5) one miner across roles → governed by existing eligibility (not changed
  here), (6) ≥1 valid miner → mint only present roles, (7) zero valid participants → the existing
  PoAW-X gate decides validity (Phase 31 mints nothing — non-inflationary).

This fallback is **specified + tested as a pure function**; the existing production path (which always
has full participation) is **unchanged**.

## Consensus wiring (additive, gated, mainnet-off)

The existing exact-match already enforces caps. Phase 31 adds an **additive, named** manifest cap gate
inside `validate_phase20_production_block`, behind a NEW activation flag
(`reward_manifest_caps_enforced(height)`, off by default, mainnet hard-off). When on, it re-derives the
manifest and asserts the caps/total with **explicit named errors** (`phase31: ...`). It is a strict
**superset** of the existing check (only adds rejections; derives from the same `multi_role_amounts`),
so it cannot weaken or false-reject a valid block. Off by default ⇒ zero regression to the 775-test
baseline.

## Tests

Manifest module (pure): valid 55/22/13/10 manifest; role-cap overpay rejected (compute/verify/support);
total-overpay rejected; rounding determinism (odd/non-divisible totals; remainder to primary);
fallback non-inflationary (absent roles not minted; minted ≤ total); penalized-signer exclusion
(reuse Phase 30); duplicate/alias output cannot bypass cap; manifest digest mismatch rejected; mainnet
no-op. Consensus: with the additive gate ON, a valid all-gates block still connects (no false reject).
Regression: phase26/28/29/30 + full suite.

## Risks / non-goals

- **No** change to `multi_role_amounts`, `validate_poawx_coinbase_payout`,
  `validate_phase20_production_block`'s existing logic, `block_reward`, LWMA/PoW/anchors, or mainnet.
- **No** new block root/wire field (reuse existing commitments).
- The additive gate is off by default and is defense-in-depth; it cannot fire on a block that passed
  the existing exact-match (which is stricter), so it is tested at the manifest level + as a
  no-false-reject consensus check.
- `SlashedPlaceholder` economic slashing stays a placeholder.
