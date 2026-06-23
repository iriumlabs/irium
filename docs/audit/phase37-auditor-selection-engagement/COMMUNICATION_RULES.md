# Communication Rules — Audit Engagement

Rules for all communication with any auditor candidate or engaged auditor. These protect the project and
keep all claims factual. Testnet/devnet only; not audited.

## Never share

- **Private keys / seed phrases** — never, under any circumstances.
- **Server / SSH / sudo passwords** or any production credentials.
- **Production / mainnet access** of any kind.

## Always

- Use **testnet/devnet only** for any reproduction; mainnet stays hard-off.
- Provide the **public repo branch** (`testnet/poawx-…`) and the **docs** (Phase 35/36/37 packages).
- Route findings through the **findings tracker**
  (`docs/audit/phase36-independent-audit-kickoff/FINDINGS_TRACKER_TEMPLATE.md`).
- Keep **all audit claims factual** — describe scope and status accurately.

## Claim discipline

- Do **not** say "audited," "secure," "production-ready," "mainnet-ready," or "public-testnet-ready" in
  any communication.
- The **"audited" claim** may only be made **after** the final report **and** remediation/retest are
  complete — and even then it must state scope (Phases 28–34, testnet/devnet) and residual risk.
- Allowed phrasing now: "auditor selection package prepared," "auditor not yet selected," "audit not yet
  started," "outreach draft only," "NDA pending," "not audited," "not mainnet-ready," "public-testnet
  planning-ready only."

## Process

- Outreach is sent **manually by the owner** after `ENGAGEMENT_READINESS_CHECKLIST.md` is complete and
  logged in `OWNER_DECISION_LOG.md`.
- Disputes over findings are handled **in writing**; the project may disagree but may not suppress the
  auditor's independent technical conclusions.
- Remediation happens on a dedicated remediation branch (never `main`), then retest.
