# NDA Decision Guide

Helps the owner decide the NDA posture for the PoAW-X Phases 28–34 audit. **No automatic choice is made
here — the owner decides.** Current status: **NDA pending.**

## Options

### 1. Audit without NDA (fully open)
- The code is already on public branches; the design docs are public.
- Pros: maximum transparency; auditor can publish freely; simplest.
- Cons: any pre-disclosure of an unfixed vulnerability is immediately public.
- Fit: good if you want a fully public process and accept open disclosure of findings.

### 2. Audit with mutual NDA
- Both parties protect confidential materials shared during the engagement.
- Pros: protects any non-public material; standard for commercial engagements.
- Cons: must be careful the NDA never suppresses legitimate security findings.
- Fit: good default for a paid commercial engagement.

### 3. Limited NDA for pre-release vulnerabilities only
- NDA covers **only** unfixed vulnerabilities for a defined responsible-disclosure window; everything
  else (final report, methodology) is publishable.
- Pros: protects users during remediation without hiding the audit itself.
- Cons: needs a clearly defined disclosure window and publication terms.
- Fit: often the best balance for a security audit of live-ish testnet consensus.

## What should never be hidden

- The **existence** of the audit and its final report (once disclosure window elapses).
- **Genuine vulnerabilities** beyond a reasonable responsible-disclosure window.
- The auditor's **independent technical conclusions** (the project may dispute in writing, not suppress).
- Known **limitations** and **residual risks**.

## Public-disclosure expectations

- Define a responsible-disclosure window (e.g., fix-then-publish) in the engagement terms.
- Plan to publish the final report (or a summary) after remediation/retest.
- Never market the result as "audited" until the final report **and** remediation/retest are complete
  (see `COMMUNICATION_RULES.md`).

## Recommended default

**Owner decision required — no automatic NDA choice.** If a paid commercial engagement, a *limited NDA
for pre-release vulnerabilities* (option 3) is a common, balanced default; but the choice is the
owner's. Record the decision and rationale in `OWNER_DECISION_LOG.md`.
