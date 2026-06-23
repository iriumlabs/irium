# Findings Tracker (Template) — PoAW-X Phases 28–34 Audit

Auditor fills this in. **Currently empty: 0 findings (audit not started).** Severity scale:
Critical / High / Medium / Low / Informational.

## Findings

| ID | Severity | Title | Affected file / phase | Description | Exploitability | Recommendation | Owner response | Remediation commit | Retest evidence | Status |
|----|----------|-------|-----------------------|-------------|----------------|----------------|----------------|--------------------|-----------------|--------|
| F-001 | | | | | | | | | | Open |
| F-002 | | | | | | | | | | Open |
| F-003 | | | | | | | | | | Open |

(Add rows as needed.)

## Status legend

- **Open** — reported, not yet triaged.
- **Acknowledged** — owner accepts the finding.
- **Disputed** — owner disagrees (record rationale in "Owner response").
- **In remediation** — fix in progress on a remediation branch (never on `main`).
- **Fixed (pending retest)** — remediation commit linked; awaiting auditor retest.
- **Closed (retested)** — auditor confirmed the fix; retest evidence linked.
- **Risk accepted** — owner accepts residual risk with rationale (requires explicit sign-off).

## Severity guidance (project view)

- **Critical:** breaks mainnet hard-off; changes PoW/LWMA/base reward; enables inflation; weakens
  phase21d/21e/22a; corrupts consensus state non-deterministically.
- **High:** consensus split risk, replay/reorg state corruption, Sybil/spam bypass, finality
  false-positive penalty, non-replayable committed state.
- **Medium:** liveness degradation, gate-misconfiguration footgun, wire ambiguity without exploit.
- **Low / Informational:** code clarity, doc inaccuracy, defensive hardening.

## Process references

- Triage / remediation / retest patterns: `docs/audit/phase26k-remediation-workflow/` (reuse).
- Remediation branches must follow the no-`main`, no-force-push rules; fixes land on a dedicated
  remediation branch and are retested before any further phase.
