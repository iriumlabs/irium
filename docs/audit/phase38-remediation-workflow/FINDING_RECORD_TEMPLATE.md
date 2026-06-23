# Finding Record (Template)

Copy one per finding. **Empty template — no real findings exist.** Do not mark `Status` anything but a
placeholder until a real auditor finding and retest exist.

```
Finding ID:            F-[NNN]
Source report / date:  [auditor report ref] / [YYYY-MM-DD]
Severity:              [Critical | High | Medium | Low | Informational | Needs Design Decision]
Title:                 [short title]

Affected phase:        [28 | 29 | 30 | 31 | 32 | 33 | 34]
Affected commit:       [baseline commit, e.g. 78d5ca3]
Affected files:        [src/...]

Description:           [what is wrong]
Exploit scenario:      [how it could be abused]
Preconditions:         [what must be true for the issue / which gates active]
Impact:                [consensus split / inflation / liveness / Sybil / etc.]
Reproducibility:       [steps, or non-repro rationale]

Owner response:        [acknowledge | dispute (with evidence) | needs design decision]
Remediation plan:      [approach; or accepted-risk reference]
Branch:                [testnet/poawx-audit-remediation-F-NNN-...]
Commits:               [base -> fix]
Tests run:             [focused filter results]
Regression evidence:   [full lib X/0; poawx-sim Y/0; release build OK]
Auditor retest result: [pending | fixed | partially fixed | not fixed | accepted risk]
Status:                [Open]   <-- placeholder; never "Closed" without retest evidence
```

## Notes

- Keep `Finding ID` stable and unique; never reuse.
- "Affected commit" is the audited baseline (default `78d5ca3`) unless the finding is against a prior
  remediation base.
- For **Needs Design Decision**, write a short design note first (current behavior → why wrong → what
  changes → what else could break → tests) before any code, per the project change rules.
- A finding is **Closed** only via `RETEST_PROTOCOL.md` (auditor retest) or a signed accepted-risk
  record (`ACCEPTED_RISK_POLICY.md`).
