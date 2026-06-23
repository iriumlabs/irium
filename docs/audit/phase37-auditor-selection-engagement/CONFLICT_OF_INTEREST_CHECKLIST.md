# Conflict-of-Interest Checklist

Complete one per candidate before shortlisting. Any "Yes" on a hard-conflict item is disqualifying
unless explicitly waived with written rationale in `OWNER_DECISION_LOG.md`. No auditor selected.

| # | Check | Yes / No | Notes |
|---|---|---|---|
| COI1 | Any financial interest in Irium / IRM (holdings, options, advisory equity, token allocation)? | ☐ | Hard conflict if yes |
| COI2 | Prior or current work on a directly competing chain that creates a conflict? | ☐ | Assess case-by-case |
| COI3 | Personal relationship with the core team that could bias findings? | ☐ | Disclose + assess |
| COI4 | Compensation structure that incentivizes a particular outcome (e.g., paid only on a "pass")? | ☐ | Must be fixed-fee / outcome-neutral |
| COI5 | Public promotional conflict (would publicly endorse/market Irium during/after)? | ☐ | Avoid promotional entanglement |
| COI6 | Able to publish independent findings (no veto by the project over technical conclusions)? | ☐ | Must be **Yes** |
| COI7 | NDA constraints that would suppress legitimate security findings? | ☐ | Must not hide real vulns (see NDA guide) |
| COI8 | Clear, documented disclosure policy (responsible disclosure timeline)? | ☐ | Must be **Yes** |
| COI9 | Remediation retest performed independently (not rubber-stamped)? | ☐ | Must be **Yes** |
| COI10 | Any subcontractors / undisclosed third parties involved? | ☐ | Require disclosure |

## Rules

- **Outcome-neutral compensation only.** Never pay contingent on a favorable result (COI4).
- **Independence of conclusions is non-negotiable** (COI6): the project may dispute findings in writing
  but may not force their removal.
- **No NDA may suppress a genuine vulnerability** beyond a reasonable responsible-disclosure window
  (COI7; see `NDA_DECISION_GUIDE.md`).
- Record the completed checklist + verdict for each candidate; carry the verdict into the
  `AUDITOR_SHORTLIST_PLACEHOLDER.md` "conflict status" column.

> This checklist evaluates candidates the owner brings; it does not name or recommend any firm.
