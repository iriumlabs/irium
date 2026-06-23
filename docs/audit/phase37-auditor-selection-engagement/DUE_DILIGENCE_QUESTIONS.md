# Due-Diligence Questions for Candidates

Ask each candidate these before shortlisting. Capture answers alongside their scorecard. No auditor
contacted yet; these are for the owner to use when reaching out manually.

## Experience

1. What consensus systems have you audited? (Names, scope, public reports if any.)
2. Have you audited **Rust** blockchain node software? Which projects, and what did you find?
3. Have you reviewed **finality / reorg** logic (checkpointing, fork-choice, reorg safety)?
4. Have you reviewed **block extension / wire-compatibility** changes (serialization, optional fields,
   backward compatibility)?
5. Have you reviewed **cryptographic evidence** mechanisms (signatures, equivocation/double-sign proofs,
   commitments/digests)?

## Method

6. How do you approach **economic / incentive** analysis (inflation, grinding, centralization)?
7. Will you **re-run the test suite independently** and write your own tests/fuzzers?
8. How do you verify **replay/reorg determinism** and state-machine correctness?

## Engagement

9. What **deliverables** are included (threat model, code review, report, severity ratings)?
10. What is your **retest / remediation** process, and is it included?
11. Can you review and report **without** asserting mainnet/production readiness (this is a testnet/devnet
    experimental overlay)?
12. How do you handle **responsible disclosure** and report timelines?
13. What are your **availability**, **timeline**, and **fee structure** (fixed-fee preferred;
    outcome-neutral)?
14. Will you disclose any **conflicts of interest** and **subcontractors** up front?

## What good answers look like

- Concrete, verifiable references (public reports, named systems).
- Comfort with experimental/gated consensus and with documenting **limitations**.
- Independent test execution and a clear, severity-rated written report.
- Outcome-neutral compensation and a real retest step.
- No promises of "certified safe"; no requests for keys/production access (see `AUDITOR_RED_FLAGS.md`).
