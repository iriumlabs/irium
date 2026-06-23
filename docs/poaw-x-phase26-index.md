# PoAW-X Phase 26 — Document Index

Grouped links to every Phase 26 document. Start with the program summary:
`docs/poaw-x-phase26-final-program-summary.md`. **NOT audited / production-ready / mainnet-ready.**
Mainnet hard-off (`network_id == 0`); public testnet gated.

Baseline: branch `testnet/poawx-phase20-blueprint-completion-local`, HEAD `208d5ff`, source `0208368`,
`origin/main` `19c496dc5f2fa08981a109b10eeb257105c28c43` (unchanged).

> **Successor work (Phases 27–35):** after Phase 26 the six deferred Phase 27 consensus items were
> implemented (Phases 28–34) and consolidated in the Phase 35 closeout package. See
> `docs/poaw-x-phase35-final-closeout.md`, `docs/poaw-x-phase35-phases27-34-commit-map.md`,
> `docs/poaw-x-phase35-consensus-feature-matrix.md`, `docs/poaw-x-phase35-audit-readiness-package.md`,
> `docs/poaw-x-phase35-risk-register.md`, `docs/poaw-x-phase35-public-testnet-readiness.md`, and
> `docs/audit/phase35-final-handoff/README.md`. Status is unchanged: **not audited / not
> production-ready / not mainnet-ready / public-testnet planning-ready only.**

## A. Core implementation / result docs

- `docs/poaw-x-phase26a-seed-reconciliation-design.md` — 26A design (seed contradiction + Option C).
- `docs/poaw-x-phase26b-seed-reconciliation-impl-result.md` — 26B epoch-seed implementation + tests.
- `docs/poaw-x-phase26c-live-multiblock-soak.md` — 26C live three-system 6-block soak.
- `docs/poaw-x-phase26d-admission-cache-persistence.md` — 26D restart cold-resync (persist + reload).
- `docs/poaw-x-phase26e-historical-admission-sync.md` — 26E fresh-wipe sync (serve historical admissions).

## B. Audit docs

- `docs/audit/poawx-phase26-independent-audit-package.md` — 26F audit package (invariants, threat model).
- `docs/audit/poawx-phase26-technical-appendix.md` — 26F per-change analysis (A–E).
- `docs/audit/poawx-phase26-auditor-checklist.md` — 26F 14-question checklist.
- `docs/audit/phase26h-kickoff/` — 26H kickoff package (README, AUDIT_SCOPE, AUDITOR_REVIEW_GUIDE,
  FINDINGS_TRACKER, AUDIT_KICKOFF_EMAIL_DRAFT, AUDIT_DELIVERABLES, REPRO_COMMANDS).
- `docs/audit/phase26i-self-review/` — 26I internal self-review (SELF_REVIEW_REPORT, REPRO_EVIDENCE,
  INTERNAL_FINDINGS, AUDITOR_HANDOFF_NOTES). **Not an audit.**
- `docs/audit/phase26j-external-handoff/` — 26J handoff (PACKAGE_MANIFEST, SEND_READY_SUMMARY,
  AUDITOR_OUTREACH_MESSAGE, AUDITOR_HANDOFF_CHECKLIST, EXTERNAL_FINDINGS_TRACKER_COPY).
- `docs/audit/phase26k-remediation-workflow/` — 26K remediation workflow (README,
  FINDING_TRIAGE_POLICY, AUDIT_RESPONSE_WORKFLOW, REMEDIATION_BRANCH_POLICY, RETEST_PROTOCOL,
  AUDITOR_RESPONSE_TEMPLATES, AUDIT_STATUS_DASHBOARD, FINDING_RECORD_TEMPLATE).
- `docs/audit/phase26l-engagement-tracker/` — 26L engagement tracker (ENGAGEMENT_SUMMARY,
  NEXT_STEPS_TRACKER, AUDITOR_SELECTION_CRITERIA, OWNER_ACTIONS_REQUIRED, AUDIT_ENGAGEMENT_STATUS,
  SEND_CHECKLIST).

## C. Public-testnet readiness (26G; docs-only, launches nothing)

- `docs/poaw-x-phase26g-public-testnet-readiness.md` — scope, prerequisites, success/abort criteria.
- `docs/poaw-x-phase26g-public-testnet-rollout-checklist.md` — env/storage/ports/topology/cleanup.
- `docs/poaw-x-phase26g-public-testnet-risk-register.md` — risks, impact/likelihood, mitigations.
- `docs/poaw-x-phase26g-public-testnet-operator-runbook.md` — operator dry-run + what-not-to-do.

## D. Existing related docs

- `docs/poaw-x-final-local-blueprint-completion-audit.md` — final local blueprint completion audit.
- `docs/audit/poaw-x/KNOWN_LIMITATIONS_AND_NON_GOALS.md` — known limitations / non-goals.
- `docs/audit/poaw-x/AUDITOR_CHECKLIST.md` — broader PoAW-X auditor checklist.
- `docs/audit/poaw-x/THREAT_MODEL.md` — PoAW-X threat model.
- `docs/audit/poaw-x/CONSENSUS_REVIEW_TARGETS.md`, `.../CRYPTO_REVIEW_TARGETS.md`,
  `.../ARCHITECTURE_OVERVIEW.md`, `.../BUILD_AND_TEST_GUIDE.md`, `.../AUDIT_SCOPE.md`,
  `.../FINDINGS_FROM_INTERNAL_REVIEW.md`, `.../POOL_WALLET_NODE_REVIEW_TARGETS.md`, `.../README.md`.
- `docs/poaw-x-blueprint-completion-gap-audit.md` — earlier gap audit.

## Program-level docs (26M)

- `docs/poaw-x-phase26-final-program-summary.md` — executive summary + timeline + status.
- `docs/poaw-x-phase26-index.md` — this index.
- `docs/poaw-x-phase26-commit-map.md` — commit table + audit source ranges.
- `docs/poaw-x-phase26-next-decision-tracker.md` — the five open decisions.
- `docs/release-notes/poaw-x-phase26-draft-release-notes.md` — 26N draft release notes (draft only; no
  tag/release).
- `docs/release-notes/poaw-x-phase26-draft-changelog.md` — 26N draft changelog (grouped by area).

## Findings trackers (where audit findings will be recorded)

- `docs/audit/phase26h-kickoff/FINDINGS_TRACKER.md` (primary; empty).
- `docs/audit/phase26j-external-handoff/EXTERNAL_FINDINGS_TRACKER_COPY.md` (send-copy; empty).
- `docs/audit/phase26i-self-review/INTERNAL_FINDINGS.md` (internal pre-read; Informational only — not
  audit findings).
