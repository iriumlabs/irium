# PoAW-X Independent Audit Kickoff — Phase 36

**Auditor-facing entry point.** Documentation/audit-operations package only — no consensus code was
changed in Phase 36.

**Status: NOT audited. NOT mainnet-ready. NOT production-ready. Public-testnet planning-ready only.**
PoAW-X is hard-off on mainnet (`network_id == 0`) and every feature is off by default behind explicit
env activation gates. Nothing here authorizes a public testnet or mainnet launch.

> **Auditor selection (Phase 37):** the owner-facing selection & engagement-prep package (criteria,
> scorecard, conflict checks, scope options, NDA guide, outreach drafts, decision log) is at
> `docs/audit/phase37-auditor-selection-engagement/README.md`. Auditor not yet selected; audit not yet
> started; outreach not sent. The Phase 38 **remediation workflow** (how findings are triaged, fixed on
> isolated branches, tested, retested, and closed) is at
> `docs/audit/phase38-remediation-workflow/README.md`. No findings received; remediation not started.

## What PoAW-X is

PoAW-X ("proof-of-aligned-work, extended") is a **multi-role consensus overlay** layered on Irium's
existing Bitcoin-style PoW chain. It keeps SHA-256d PoW, LWMA-144 difficulty, the anchor work rules, and
the base block reward **unchanged**, and adds (testnet/devnet only, gated) role-based participation
(primary/compute/verify/support), candidate admission, finality committees, anti-domination fairness,
on-chain tickets, double-sign penalties, and an adaptive security mode. This audit covers the
**Phases 28–34** consensus additions on top of that base.

## In scope

| Phase | Feature |
|---|---|
| 28 | Finalized-checkpoint state + reorg-below-finalized rejection |
| 29 | Double-sign evidence + penalty-state primitives |
| 30 | Block-carried double-sign evidence + consensus finality exclusion |
| 31 | Reward manifest wrapper + per-role caps + low-participation fallback |
| 32 | On-chain ticket store + Sybil/rate-limit/expiry |
| 33 | Dominance-state commitment |
| 34 | Adaptive-modes consensus integration |

Plus the trailing-optional block wire sections `DSE1` (30), `TKT1` (32), `DMC1` (33), `ADM1` (34) and the
`connect_block` / `reorg_to_tip` integration in `src/chain.rs`. Full detail in `AUDIT_SCOPE_FINAL.md` and
`SOURCE_RANGES_AND_BRANCHES.md`.

## Out of scope

Mainnet activation, public-testnet launch, wallet UX, exchange/liquidity, production ops, and all
non-PoAW-X mainnet behavior (PoW/LWMA/anchor/base-reward are unchanged and not under review here). See
`AUDIT_SCOPE_FINAL.md`.

## Branch heads (verified on `origin`)

| Phase | Branch (`testnet/poawx-…`) | HEAD |
|---|---|---|
| 28 | `phase28-finalized-reorg-rejection` | `199ed24` |
| 29 | `phase29-double-sign-penalties` | `df0cc92` |
| 30 | `phase30-block-carried-doublesign-evidence` | `7e5f805` |
| 31 | `phase31-reward-manifest-wrapper-cap-fallback` | `fae91bb` |
| 32 | `phase32-onchain-ticket-store` | `8f2a64d` |
| 33 | `phase33-dominance-state-commitment` | `1a032de` |
| 34 | `phase34-adaptive-modes-consensus-integration` | `78d5ca3` |
| 35 | `phase35-final-closeout-audit-consolidation` | `17f8a77` |

`origin/main` is **unchanged** at `19c496dc5f2fa08981a109b10eeb257105c28c43` (PoAW-X never landed on
main).

## Suggested review order

See `AUDITOR_REVIEW_GUIDE.md` (11 steps, starting with mainnet hard-off and wire compatibility). Then
work the `CONSENSUS_INVARIANTS_CHECKLIST.md`, reproduce with `REPRO_COMMANDS.md`, and record findings in
`FINDINGS_TRACKER_TEMPLATE.md`.

## Package contents

- `AUDIT_SCOPE_FINAL.md` — in/out of scope + safety statement
- `SOURCE_RANGES_AND_BRANCHES.md` — per-phase ranges, files, tests, priority
- `AUDITOR_REVIEW_GUIDE.md` — suggested review order
- `CONSENSUS_INVARIANTS_CHECKLIST.md` — invariants to verify
- `REPRO_COMMANDS.md` — reproduce build/tests/diffs
- `TEST_EVIDENCE_SUMMARY.md` — reported results (auditors should re-run)
- `FINDINGS_TRACKER_TEMPLATE.md` — findings table
- `AUDITOR_QUESTIONS.md` — key questions for the auditor
- `AUDITOR_OUTREACH_DRAFT.md` — draft message (NOT sent; placeholders)
- `AUDIT_DELIVERABLES_EXPECTED.md` — expected audit outputs
- `AUDIT_KICKOFF_STATUS.md` — kickoff checklist state

Prior audit material for context: `docs/audit/poaw-x/`, `docs/audit/poawx-phase26-*`,
`docs/audit/phase35-final-handoff/`, and `docs/poaw-x-phase35-*`.
