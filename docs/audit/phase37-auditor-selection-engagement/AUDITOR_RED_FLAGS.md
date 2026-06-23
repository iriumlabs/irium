# Auditor Red Flags

Disqualifying or caution signals when evaluating a candidate. Any hard red flag should remove a
candidate from the shortlist (record in the scorecard notes + `OWNER_DECISION_LOG.md`).

## Hard red flags (disqualify)

- **Promises "certified safe" / guaranteed-secure** before doing any review. No credible auditor
  guarantees safety.
- **No consensus-audit experience** for a consensus-overlay review (criterion C1/C5 ≈ 0).
- **Refuses to provide a written report.**
- **Refuses to retest** after remediation.
- **Asks for private keys, seed phrases, or production credentials.** Never provide these (see
  `COMMUNICATION_RULES.md`).
- **Wants direct mainnet access** — out of scope; PoAW-X is testnet/devnet only, mainnet hard-off.
- **Unclear or evasive conflict-of-interest disclosure.**
- **Refuses to document limitations / residual risk.**

## Caution signals (investigate, may disqualify)

- **Pushes promotional language** ("partner," "endorsed by us") before/around the audit.
- **Unrealistic timeline** for a full consensus review (Scope C/D) — suggests a shallow pass.
- **Outcome-contingent fees** (paid more for a "pass") — must be outcome-neutral.
- **Undisclosed subcontractors** doing the actual work.
- **Vague methodology** — can't explain how they verify replay/reorg determinism or test independently.
- **Over-broad NDA** that would suppress genuine findings beyond a responsible-disclosure window.

## Response

- A hard red flag → reject; note the reason.
- A caution signal → ask the relevant `DUE_DILIGENCE_QUESTIONS.md`, document the answer, decide.
- Never let a red-flag candidate influence any "audited" claim — none may be made regardless.
