# Pre-Audit Devnet Soak — Execution Readiness Sign-Off (Phase 40)

**Documentation-only readiness package.** Phase 40 turns the Phase 39 soak *plan* into a concrete
owner-approval **gate**: the decisions and sign-offs required before any internal devnet soak runs. No
nodes are started, no firewall rules changed, no miners run, no code changed.

**Status:**
- Readiness package prepared: **yes**
- Execution approved: **no**
- Soak executed: **no**
- Production-ready: **no**
- Mainnet-ready: **no**
- Audited: **no**
- Public-testnet-ready: **planning-ready only**

## Purpose

Provide a single, owner-facing path from "plan exists" (Phase 39) to "execution is approved" — without
executing anything. It distills the Phase 39 plan into explicit decisions (topology, ports/firewall,
storage, scenarios, duration), a mainnet-safety precheck, a go/no-go gate, a non-executed command
dry-run checklist, an evidence-retention plan, and a final owner-approval template.

## Relationship to Phase 39

- Phase 39 (`docs/devnet/phase39-preaudit-multinode-soak/`) is the full **plan** (scope, topology,
  safety boundaries, runbook draft, scenarios, metrics, pass/fail, abort/rollback, templates).
- Phase 40 (this package) is the **approval gate** on top of it. Execution is a **separate phase** that
  begins only after the owner signs `FINAL_OWNER_APPROVAL_TEMPLATE.md` and the go/no-go is **Go**.

## What this package approves (once signed)

Only an **internal devnet soak execution** of the combined Phase 28–34 stack, under the Phase 39 safety
boundaries. It does **not** approve a public testnet or mainnet — those remain separate, later,
owner-gated decisions.

## What is NOT executed in Phase 40

- No nodes, no mining, no P2P, no RPC/stratum, no firewall/sudo, no external miners, no public testnet.
- No wallet/key access. No default/`/tmp`/`.irium` storage. No credentials stored or printed.

## Contents

- `EXECUTION_READINESS_SIGNOFF.md` — single owner approval form (all boxes pending).
- `TOPOLOGY_DECISION.md` — options A/B/C + recommended default.
- `PORT_FIREWALL_DECISION.md` — port/firewall posture (no changes in Phase 40).
- `STORAGE_ROOTS_SIGNOFF.md` — proposed isolated roots + forbidden paths.
- `SCENARIO_SELECTION.md` — choose from Phase 39 S1–S15 + recommended minimum.
- `DURATION_AND_RESOURCE_PLAN.md` — duration options + resource notes.
- `MAINNET_SAFETY_PRECHECK.md` — mainnet isolation checklist.
- `EXECUTION_GO_NO_GO.md` — go/no-go criteria.
- `COMMAND_DRY_RUN_CHECKLIST.md` — verify commands (non-executed).
- `EVIDENCE_RETENTION_PLAN.md` — what to keep / never keep.
- `FINAL_OWNER_APPROVAL_TEMPLATE.md` — copy/fill approval page.
