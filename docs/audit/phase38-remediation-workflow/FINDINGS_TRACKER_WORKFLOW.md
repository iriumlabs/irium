# Findings Tracker Workflow

End-to-end lifecycle for a single audit finding. No findings exist yet. Use with
`docs/audit/phase36-independent-audit-kickoff/FINDINGS_TRACKER_TEMPLATE.md` (the canonical tracker table)
and `FINDING_RECORD_TEMPLATE.md` (per-finding detail).

## Lifecycle

1. **Finding received** — from the auditor (report or tracker entry).
2. **Assign ID** — `F-NNN` (stable, never reused).
3. **Classify severity** — per `FINDING_TRIAGE_POLICY.md` (auditor's call).
4. **Reproduce or explain non-repro** — record exact steps, or a clear rationale why it doesn't
   reproduce (and ask the auditor to confirm).
5. **Choose remediation path** — remediation branch (`REMEDIATION_BRANCH_POLICY.md`) or accept-risk
   (`ACCEPTED_RISK_POLICY.md`, owner-approved) or dispute (`AUDIT_RESPONSE_TEMPLATES.md`).
6. **Implement fix** — on the isolated remediation branch only (never `main`).
7. **Run focused tests** — for the affected area (`REMEDIATION_TEST_MATRIX.md`).
8. **Run full regression** — full lib suite + `poawx-sim` + release build.
9. **Update the finding record** — branch, commits, tests, regression evidence.
10. **Auditor retest** — send retest evidence (`RETEST_PROTOCOL.md`).
11. **Close only after retest** — a finding is closed only with auditor retest evidence (or an
    owner-approved accepted-risk record); update the dashboard.

## State transitions

`Open → Acknowledged/Disputed → (Reproduced) → In remediation → Fixed (pending retest) →
Closed (retested)` — with `Accepted risk` as an explicit, owner-signed alternate terminal state.

## Invariants

- No finding moves to **Closed** without auditor retest evidence **or** a signed accepted-risk record.
- No remediation lands on `main`; no launch is implied by closing findings
  (`NO_MAINNET_NO_PUBLIC_TESTNET_GATES.md`).
- Remediation must not weaken existing gates (phase21d/21e/22a, Phase 30–34) or change
  PoW/LWMA/base-reward/mainnet — the same change rules as the original implementation apply.
- The dashboard (`REMEDIATION_STATUS_DASHBOARD.md`) is updated at every transition.
