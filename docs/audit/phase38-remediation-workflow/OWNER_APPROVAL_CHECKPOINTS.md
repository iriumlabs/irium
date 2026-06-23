# Owner Approval Checkpoints

Mandatory owner sign-off points across the audit → remediation → (eventual) launch-planning path. Each
is recorded in `docs/audit/phase37-auditor-selection-engagement/OWNER_DECISION_LOG.md`. None reached yet.

| # | Checkpoint | Owner approval required | Current state |
|---|---|---|---|
| 1 | Auditor selection | Yes | Not done |
| 2 | Audit scope / budget / timeline | Yes | Pending |
| 3 | Start audit | Yes | Not started |
| 4 | Accept or reject a scope change mid-engagement | Yes | n/a |
| 5 | Accept residual risk on a finding | Yes (+ auditor note) | n/a |
| 6 | Group multiple findings into one remediation branch | Yes | n/a |
| 7 | Start a remediation branch | Yes | n/a (no findings) |
| 8 | Request auditor retest | Yes | n/a |
| 9 | Proceed to public-testnet **planning** | Yes (after audit/remediation gates) | Blocked |
| 10 | Proceed to mainnet **governance** planning | Yes (separate program) | Blocked / out of scope |

## Rules

- No checkpoint is auto-resolved by the project or by this tooling; each needs an explicit owner
  decision logged with date + rationale.
- Approvals are **sequential gates**: e.g., remediation branches (7) require findings, which require the
  audit (3), which requires selection (1) and scope/NDA/budget (2).
- Reaching checkpoint 9/10 requires the audit and remediation gates first, and is still subject to
  `NO_MAINNET_NO_PUBLIC_TESTNET_GATES.md` and the Phase 35 readiness/risk docs.
- Owner approvals do not change factual status claims — "audited" requires a completed report +
  remediation/retest (`COMMUNICATION_RULES.md`).
