# PoAW-X Phase 31 — Draft Note (development only — not a release)

> **Draft / development only.** No git tag, no GitHub release, no binaries. **Testnet/devnet only.
> Mainnet hard-off (`network_id == 0`). NOT production-ready / mainnet-ready / audited.** No public
> testnet launch.

Branch: `testnet/poawx-phase31-reward-manifest-wrapper-cap-fallback` (from `7e5f805`). `origin/main`
unchanged (`19c496dc5f2fa08981a109b10eeb257105c28c43`).

## What changed

- **Reward manifest wrapper + caps + fallback (formalizes Phase 27 item 1D).** New
  `src/poawx_reward.rs`: a versioned `PoawxRewardManifestV1` (no new wire/root), rounding-aware role
  caps (`PoawxRoleRewardCap`: non-primary roles hard-capped at their bps floor, PRIMARY is the
  residual), a deterministic non-inflationary fallback (`PoawxRewardFallbackMode`: absent roles not
  minted), a penalized-recipient link (Phase 30), and an **additive** (gated, off-by-default,
  mainnet-hard-off) consensus cap gate in `validate_phase20_production_block` — a strict superset of the
  existing exact-match payout validation.
- **Simulation:** `poawx-sim` `reward_distribution` reports the capped 55/22/13/10 split (550/220/130/100
  permille), the fallback/unpaid share, and `total_reward_cap_respected`.

## Unchanged / safety

- No change to `multi_role_amounts`, the canonical coinbase validator
  (`validate_poawx_coinbase_payout`), `block_reward`, LWMA/PoW/SHA-256d anchors, phase21d/21e/22a,
  finality validation, or mainnet. Total coinbase still bounded to subsidy + fees; no inflationary
  fallback. Mainnet stays hard-off.

## Tests

- `phase31_*`: 9/0. Full lib suite: 784/0 (`reward` 17/0, `multi_role` 5/0). `poawx-sim` bin: 14/0.
  Release builds: OK.

_Development only. Not a release. Not audited / production-ready / mainnet-ready._
