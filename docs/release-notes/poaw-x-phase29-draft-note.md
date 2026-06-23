# PoAW-X Phase 29 — Draft Note (development only — not a release)

> **Draft / development only.** No git tag, no GitHub release, no binaries. **Testnet/devnet only.
> Mainnet hard-off (`network_id == 0`). NOT production-ready / mainnet-ready / audited.** No public
> testnet launch.

Branch: `testnet/poawx-phase29-double-sign-penalties` (from `199ed24`). `origin/main` unchanged
(`19c496dc5f2fa08981a109b10eeb257105c28c43`).

## What changed

- **Double-sign penalty wiring (partial close of Phase 27 item 5B).** New module
  `src/poawx_doublesign.rs`: `PoawxDoubleSignEvidenceV1` (validated equivocation evidence with an
  order-independent id), `PoawxDoubleSignPenaltyState` (deterministic, **replayable** penalty state that
  suspends an offender and removes finality eligibility/weight), a `detect_double_sign` helper, and a
  bounded **local** evidence cache. Reuses the existing `poawx_penalty` primitives.
- **Simulation:** `poawx-sim` `finality_attack` models double-signing and reports
  `double_sign_detected` / `penalty_applied` / `penalized_finality_weight_removed`.

## Important boundary (consensus safety)

Evidence validation + penalty state are **local/replayable primitives** — they are **NOT** wired into
block acceptance, the reward manifest, or committee selection, because blocks do not yet **carry**
double-sign evidence and local-only evidence must not cause consensus divergence. Consensus enforcement
needs a future **block-carried-evidence** design (the remaining part of 5B).

## Unchanged / safety

- No change to finality threshold/committee validation, signature checks, phase21d/21e/22a,
  LWMA/PoW/reward, SHA-256d anchors, or mainnet consensus. Mainnet stays hard-off.

## Tests

- `phase29_*`: 12/0. Full lib suite: 768/0. `poawx-sim` bin: 12/0. Release builds: OK.

_Development only. Not a release. Not audited / production-ready / mainnet-ready._
