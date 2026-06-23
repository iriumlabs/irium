# PoAW-X Phase 26 — Next-Decision Tracker

The five open decisions that move Phase 26 forward. Each is **owner-gated** or **audit-gated** — none
can be auto-resolved by the project. **NOT audited / production-ready / mainnet-ready.** Mainnet hard-off
(`network_id == 0`); public testnet gated.

_Last updated: `[YYYY-MM-DD]` by `[name]`_

> **Update (Phase 35 closeout):** Since this tracker was written, the six deferred Phase 27 consensus
> items were implemented at branch level in Phases 28–34 (5A→28, 5B→29/30, 1D→31, 2E→32, 3C→33, 6F→34).
> This **does not** change any decision below — the program is still **not audited / not production-ready
> / not mainnet-ready / public-testnet planning-ready only**, and Decisions 1–5 remain exactly as
> gated. The audit package now covers Phases 28–34: see
> `docs/poaw-x-phase35-final-closeout.md`, `docs/poaw-x-phase35-audit-readiness-package.md`, and
> `docs/audit/phase35-final-handoff/README.md`. The audit (Decision 1) is the unchanged immediate next
> step. The Phase 36 independent-audit **kickoff package** (review guide, invariants checklist, repro
> commands, findings template, outreach draft, status) is now prepared at
> `docs/audit/phase36-independent-audit-kickoff/README.md` — auditor still not selected, audit not
> started. The Phase 37 **auditor selection & engagement-prep** package (selection criteria, scorecard,
> conflict checks, scope options, NDA guide, budget/timeline templates, outreach drafts, decision log) is
> at `docs/audit/phase37-auditor-selection-engagement/README.md`. This directly supports **Decision 1
> (choose auditor)** and **Decision 2 (send package)** below; both remain owner-gated (outreach not sent,
> NDA pending, budget pending).

## Decision 1 — Choose an independent auditor

- **Owner:** project owner / user
- **Status:** Open (no auditor chosen)
- **Prerequisites:** selection criteria reviewed (`docs/audit/phase26l-engagement-tracker/AUDITOR_SELECTION_CRITERIA.md`).
- **Evidence needed:** a named reviewer meeting the must-have criteria, conflict-of-interest check
  recorded.
- **Current blocker:** owner has not selected a reviewer.

## Decision 2 — Send the audit package

- **Owner:** project owner (send), project (prepare)
- **Status:** Blocked on Decision 1
- **Prerequisites:** auditor name/company/contact provided; NDA decision; timeline/budget notes; send
  checklist complete (`docs/audit/phase26l-engagement-tracker/SEND_CHECKLIST.md`); explicit send approval.
- **Evidence needed:** filled outreach message
  (`docs/audit/phase26j-external-handoff/AUDITOR_OUTREACH_MESSAGE.md`), recorded approval, archived sent
  copy.
- **Current blocker:** no recipient, no approval. **No message has been sent.**

## Decision 3 — Handle audit findings

- **Owner:** project (triage/remediate) + auditor (file/retest)
- **Status:** Not started (0 external findings)
- **Prerequisites:** audit underway; remediation workflow ready (`docs/audit/phase26k-remediation-workflow/`).
- **Evidence needed:** findings logged in the tracker; per-finding records; fix commits on the test
  branch; auditor retest verdicts.
- **Current blocker:** audit has not started (depends on Decisions 1–2).

## Decision 4 — Decide public testnet after audit

- **Owner:** project owner
- **Status:** Blocked (gated on audit outcome)
- **Prerequisites:** independent review complete with no open Critical/High findings; readiness package
  reviewed (`docs/poaw-x-phase26g-public-testnet-readiness.md`); separate launch approval.
- **Evidence needed:** auditor scoped sign-off (or accepted residual risk), explicit launch decision.
- **Current blocker:** no audit, no sign-off. Public-testnet gate **BLOCKED**.

## Decision 5 — Governance / mainnet activation

- **Owner:** project owner / governance
- **Status:** Blocked (out of scope for Phase 26)
- **Prerequisites:** out of scope — requires its own program (governance, economics, security, separate
  audits).
- **Evidence needed:** not applicable in Phase 26.
- **Current blocker:** intentionally blocked. PoAW-X is **hard-off for `network_id == 0`**; mainnet is
  not a Phase 26 deliverable and must not be activated here.

## Summary

| # | Decision | Owner | Status | Gating |
|---|----------|-------|--------|--------|
| 1 | Choose auditor | Owner | Open | owner input |
| 2 | Send package | Owner | Blocked | Decision 1 + approval |
| 3 | Handle findings | Project + Auditor | Not started | audit underway |
| 4 | Public testnet after audit | Owner | Blocked | audit sign-off |
| 5 | Governance / mainnet | Owner / governance | Blocked | out of scope |

**Recommended immediate action:** resolve Decision 1 (choose a reviewer) — everything else follows.
Until then, the program is correctly paused at "package prepared," with no claim of audited /
production-ready / mainnet-ready.
