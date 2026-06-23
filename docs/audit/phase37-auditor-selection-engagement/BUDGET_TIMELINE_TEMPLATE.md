# Budget & Timeline (Template)

Template only. **No costs, dates, or timelines are invented here** — the owner fills these from real
candidate quotes. Budget/timeline status: **pending.**

## Per-candidate budget/timeline

| Field | Value (owner fills) |
|---|---|
| Candidate | `[NAME / COMPANY]` |
| Scope option (A/B/C/D) | `[ ]` (see `ENGAGEMENT_SCOPE_OPTIONS.md`) |
| Estimated cost | `[CURRENCY + AMOUNT]` |
| Payment milestones | `[e.g., deposit / draft report / final+retest]` |
| Start date | `[YYYY-MM-DD]` |
| Draft report date | `[YYYY-MM-DD]` |
| Remediation window | `[duration]` |
| Retest date | `[YYYY-MM-DD]` |
| Final report date | `[YYYY-MM-DD]` |
| Owner approval status | ☐ pending ☐ approved ☐ rejected |

## Milestone structure (suggested, outcome-neutral)

1. **Engagement start** — scope + NDA signed; deposit (if applicable).
2. **Draft report** — findings delivered for owner review.
3. **Remediation** — owner fixes on a dedicated remediation branch (never `main`).
4. **Retest** — auditor verifies fixes; final report.
5. **Final payment** — on delivery of the final report + retest (NOT contingent on a "pass").

> Keep compensation **outcome-neutral** (never pay more for a clean result) — see
> `CONFLICT_OF_INTEREST_CHECKLIST.md` (COI4).

## Notes

- Compare candidate quotes against the approved budget range (record the range in
  `OWNER_DECISION_LOG.md` once decided).
- Timelines should be realistic for a full consensus review; an unrealistically short quote for Scope C/D
  is a red flag (`AUDITOR_RED_FLAGS.md`).
