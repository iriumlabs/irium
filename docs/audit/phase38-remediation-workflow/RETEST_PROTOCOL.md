# Retest Protocol

How a remediated finding is verified by the auditor and closed. No findings exist yet.

## Evidence sent to the auditor

For each remediated finding, provide:
- Finding ID + the remediation **branch name** and **base commit**.
- The **fix commit hash(es)** and a concise fix summary.
- **Diff** of the fix (`git diff <base>..<fix>`), scoped to the finding.
- **Test evidence**: focused suite results, full-lib result (X/0), `poawx-sim` (Y/0), release-build OK
  (per `REMEDIATION_TEST_MATRIX.md`).
- Any new tests added that capture the finding (regression guard).
- Notes on residual risk, if any.

## Identifying retest commits

- The auditor retests at the **fix commit** on the remediation branch (cite the exact hash).
- If the fix is rebased/updated, send the new hash; never silently change what was retested.
- Keep the branch immutable once retest starts (no force push to a reviewed branch —
  `REMEDIATION_BRANCH_POLICY.md`).

## Verdicts (recorded in the finding record + dashboard)

- **Fixed** — auditor confirms the issue is resolved at the cited commit (with evidence).
- **Partially fixed** — issue reduced but not fully resolved; remains **Open** at a (possibly lowered)
  severity until fully fixed or accepted.
- **Not fixed** — fix ineffective; stays **Open** at original severity; iterate.
- **Accepted risk** — owner accepts residual risk per `ACCEPTED_RISK_POLICY.md` (signed), with an
  auditor note; recorded as an explicit terminal state (not "Closed/fixed").

## Who can close

- A finding is **Closed (retested)** only by recording the auditor's **Fixed** verdict with evidence.
- **Accepted risk** closure requires explicit **owner sign-off** (logged in
  `docs/audit/phase37-auditor-selection-engagement/OWNER_DECISION_LOG.md`) plus an auditor note.
- The project alone may **not** close a finding without one of the above.

## Launch gate

- **No public testnet** until all **Critical/High/Medium** findings are **Closed (retested)** or
  **explicitly owner-accepted** with an auditor note.
- Retest completion does **not** by itself authorize any launch — see
  `NO_MAINNET_NO_PUBLIC_TESTNET_GATES.md`.
