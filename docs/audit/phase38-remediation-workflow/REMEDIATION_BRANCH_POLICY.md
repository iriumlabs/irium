# Remediation Branch Policy

How remediation branches are created and managed once real audit findings exist. No remediation branch
exists yet (no findings). Testnet/devnet only; mainnet hard-off.

## Branch naming

- One finding per branch (preferred):
  `testnet/poawx-audit-remediation-<finding-id>-<short-title>`
  e.g. `testnet/poawx-audit-remediation-F-007-reorg-state-restore`
- Grouped branch **only** when findings are tightly related (same root cause / same file region):
  `testnet/poawx-audit-remediation-<id1>-<id2>-<short-title>` — requires owner approval to group (see
  `OWNER_APPROVAL_CHECKPOINTS.md`).

## Hard rules

- **No remediation directly on `main`.** Ever.
- **No remediation directly on the audited baseline branch** (`testnet/poawx-phase34-…` /
  `…phase35-…`); branch off it instead.
- **One finding per branch** unless explicitly grouped (owner-approved).
- **No force push** unless explicitly approved by the owner, and **never** to a shared/reviewed branch.
- **No PR / merge / tag / release** as part of remediation prep; integration is a separate, later,
  owner-gated decision.

## Base commit

- Every remediation branch must start from the **audited baseline** (the commit the auditor reviewed —
  default `78d5ca3`, Phase 34 head) **or** an approved remediation base (a prior remediation branch that
  the auditor has retested and the owner approved as the new base).
- Record the exact base commit in the branch's `REMEDIATION_BRANCH_TEMPLATE.md` copy.

## Required documentation per branch

Each remediation branch must document (via `REMEDIATION_BRANCH_TEMPLATE.md`):
- branch name + finding ID(s)
- **start (base) commit**
- files changed + **fix commit(s)**
- **test evidence** (focused + full regression + sim + build — see `REMEDIATION_TEST_MATRIX.md`)
- risks / residual concerns
- **auditor retest status** (pending / fixed / partially fixed / not fixed / accepted risk)

## Lifecycle position

A remediation branch is **prepared and tested only**; it is not merged. Closing a finding requires
auditor retest evidence (`RETEST_PROTOCOL.md`). Launching anything is separately gated
(`NO_MAINNET_NO_PUBLIC_TESTNET_GATES.md`).
