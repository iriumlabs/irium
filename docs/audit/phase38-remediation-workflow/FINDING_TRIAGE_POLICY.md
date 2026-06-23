# Finding Triage Policy

How audit findings are classified and what each severity blocks. No findings exist yet. Testnet/devnet
only; mainnet hard-off regardless of any finding.

## Severity levels & response

| Severity | Response-time target | Dev pauses? | Public testnet blocked? | Mainnet blocked? | Owner approval | Auditor retest |
|---|---|---|---|---|---|---|
| **Critical** | Immediate; stop dependent work | **Yes** (on affected area) | **Yes** | **Yes** | Required | **Required** |
| **High** | Prioritized, before any launch planning | Partial (affected area) | **Yes** | **Yes** | Required | **Required** |
| **Medium** | Scheduled before public testnet | No (continue elsewhere) | **Yes** (until fixed or owner-accepted) | **Yes** | Required | **Required** |
| **Low** | Backlog; fix or accept | No | No (track only) | **Yes** (review before mainnet) | Required to accept | Recommended |
| **Informational** | Optional / hardening | No | No | No | Not required | Optional |
| **Needs Design Decision** | Triage to a design task; do not code blind | Pause that area | **Yes** until resolved | **Yes** | Required | After decision + fix |

## Rules

- **Mainnet is blocked irrespective of findings** — PoAW-X is hard-off on mainnet and mainnet activation
  is a separate governance program (`NO_MAINNET_NO_PUBLIC_TESTNET_GATES.md`). The table's "Mainnet
  blocked?" column reflects that no finding ever *unblocks* mainnet.
- **Critical/High/Medium block public-testnet planning** until closed (retested) or explicitly
  owner-accepted with an auditor note (`ACCEPTED_RISK_POLICY.md`).
- **"Needs Design Decision"** findings must not be patched blind — route to a design note first
  (per the project's change rules), then remediate.
- Severity is the **auditor's** call; the owner/project may dispute in writing (`AUDIT_RESPONSE_TEMPLATES.md`)
  but may not silently downgrade.

## Triage steps

1. Receive finding → assign ID → record in `FINDING_RECORD_TEMPLATE.md`.
2. Classify severity (per the auditor; dispute in writing if needed).
3. Reproduce, or document a clear non-reproduction rationale.
4. Decide remediation branch (per `REMEDIATION_BRANCH_POLICY.md`) or accept-risk path.
5. Track in `REMEDIATION_STATUS_DASHBOARD.md`.
