# Post-Audit Decision Tree

What to do once the audit report arrives, by outcome. No audit has occurred; this is the planned logic.
All paths keep mainnet hard-off and require owner approval for any forward step.

## Paths

### A. No findings
- Record "0 findings" in the dashboard + final report reference.
- **Next:** still NOT auto-cleared for launch — proceed only to owner-gated public-testnet **planning**
  (checkpoint 9), with the Phase 35 risk register/readiness reviewed. Update status to "audited
  (scope: Phases 28–34, testnet/devnet), 0 findings" — never "production/mainnet-ready."

### B. Informational only
- Decide fix-or-note per item; none block planning.
- **Next:** optional hardening; proceed to owner-gated public-testnet planning.

### C. Low findings
- Fix or accept-risk (owner-approved) each; track in dashboard.
- **Next:** Low items don't block public-testnet planning but should be reviewed before mainnet.

### D. Medium findings
- Remediate on isolated branches; retest; close — **or** owner-accept with auditor note.
- **Next:** public-testnet planning is **blocked** until all Medium are Closed-retested or
  owner-accepted.

### E. High / Critical findings
- **Stop dependent work** on the affected area; remediate with priority; retest; close.
- Critical must be **fixed and retested** (not merely accepted) for any forward path.
- **Next:** public-testnet planning **blocked** until all High/Critical are Closed-retested.

### F. Disputed findings
- Respond in writing with evidence (`AUDIT_RESPONSE_TEMPLATES.md`); align on severity with the auditor.
- If unresolved, treat at the auditor's severity until agreed; do not silently downgrade.

### G. Accepted risks
- Owner-signed + auditor note (`ACCEPTED_RISK_POLICY.md`); keep visible in the risk register if material.
- **Next:** conditions attached; may still block/condition public-testnet planning.

## Convergence

After triaging all paths:
1. Ensure no **open** Critical/High/Medium remains (Closed-retested or owner-accepted).
2. Update `REMEDIATION_STATUS_DASHBOARD.md` and the Phase 35 risk register.
3. Only then, at owner discretion, advance to **public-testnet planning** (checkpoint 9) — which is
   itself a plan, not a launch (`NO_MAINNET_NO_PUBLIC_TESTNET_GATES.md`).
4. Mainnet remains a separate governance program (checkpoint 10), not started.
