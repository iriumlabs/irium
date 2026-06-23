# Accepted-Risk Policy

When a finding is not fixed but the owner chooses to accept the residual risk. No accepted risks exist
yet. Accepting risk is **not** the same as "safe."

## When risk may be accepted

- A **Low** or **Informational** finding where a fix is disproportionate, **or**
- A **Medium/High** finding **only** with an explicit owner decision, an auditor note on residual risk,
  and conditions (e.g., gate stays off, parameter constrained, not eligible for public testnet until
  revisited).
- **Critical** findings should not be "accepted" for any path toward public testnet/mainnet — they must
  be fixed and retested.

## Who approves

- The **project owner**, in writing, recorded in
  `docs/audit/phase37-auditor-selection-engagement/OWNER_DECISION_LOG.md` (date, decision, rationale,
  risks accepted, conditions, follow-up). An **auditor note** acknowledging the residual risk is
  required for Medium/High.

## Required documentation

- The finding record marked `Auditor retest result: accepted risk`, linking the owner decision entry.
- A clear statement of **why** it is acceptable, **under what conditions**, and **what would change**
  the decision.
- Visibility: if the accepted risk is **material**, it must remain visible in public/testnet-facing docs
  (e.g., the risk register `docs/poaw-x-phase35-risk-register.md`) — not buried.

## Why accepted risk ≠ safe

- An accepted risk is a **known, deliberately-unmitigated** weakness. It does not make the system
  audited, secure, production-ready, or mainnet-ready.
- Accepted risks **condition or block** launch: Critical/High/Medium accepted risks keep the
  public-testnet gate closed unless the owner explicitly accepts them with an auditor note, and never
  unblock mainnet (`NO_MAINNET_NO_PUBLIC_TESTNET_GATES.md`).

## Review

- Re-review accepted risks before any public-testnet planning step and again before any mainnet
  governance discussion. An accepted risk can be revoked (i.e., scheduled for a real fix) at any time.
