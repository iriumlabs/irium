# Pre-Audit Internal Multi-Node Devnet Soak — Plan (Phase 39)

**Documentation-only plan.** No live nodes are run in Phase 39; no code changes. This package defines
how a future internal devnet soak of the **combined PoAW-X Phase 28–34 stack** would be run safely — its
scope, topology, safety boundaries, runbook, scenarios, metrics, pass/fail criteria, abort/rollback, and
evidence capture.

**Status:**
- Plan prepared: **yes**
- Soak executed: **no**
- Production-ready: **no**
- Mainnet-ready: **no**
- Audited: **no**
- Public-testnet-ready: **planning-ready only**

> **Execution gate (Phase 40):** the owner-facing execution-readiness sign-off package is at
> `docs/devnet/phase40-soak-readiness-signoff/README.md`. Execution not yet approved; soak not yet
> executed.

## Purpose

Phases 28–34 each had focused tests and (earlier) single-feature live soaks, but the **combined** 28–34
consensus stack has **not** been live-soaked together across multiple nodes (risk R6/R11 in
`docs/poaw-x-phase35-risk-register.md`). This plan prepares an **internal** (operator-only) devnet soak
to exercise the full stack — convergence, fresh-wipe sync, cold replay, reorg rejection, and the
double-sign / ticket / dominance / adaptive paths — **before** the independent audit and well before any
public testnet.

## Why after Phases 28–34

- The features interact (e.g., adaptive Defense requires committed-admission + finality); only a combined
  run validates the interactions live.
- Deep-scale / cold-resync (Phase 26D/26E) was validated before Phases 30–34 landed; it should be
  re-exercised with all gates active.

## What this plan covers

`SOAK_SCOPE.md`, `TOPOLOGY.md`, `SAFETY_BOUNDARIES.md`, `STORAGE_AND_PORT_PLAN.md`,
`PRECHECK_CHECKLIST.md`, `RUNBOOK_DRAFT.md` (commands not executed), `SCENARIOS.md`,
`METRICS_AND_EVIDENCE.md`, `PASS_FAIL_CRITERIA.md`, `ABORT_AND_ROLLBACK.md`, `EVIDENCE_LOG_TEMPLATE.md`,
`POST_SOAK_REPORT_TEMPLATE.md`, `OWNER_APPROVAL_CHECKLIST.md`.

## What is NOT executed in Phase 39

- No nodes started, no mining, no P2P, no RPC/stratum, no firewall/sudo, no external miners, no public
  testnet. No wallet/key access. No default/`/tmp`/`.irium` storage.
- Actual execution is a **separate, owner-approved phase** gated by `OWNER_APPROVAL_CHECKLIST.md`.

## Relationship to other work

- Risk context: `docs/poaw-x-phase35-risk-register.md` (R6/R11).
- Public-testnet plan (this soak is a prerequisite gate): `docs/poaw-x-phase35-public-testnet-readiness.md`.
- Audit: `docs/audit/phase36-independent-audit-kickoff/README.md`. This soak complements (does not
  replace) the independent audit.
