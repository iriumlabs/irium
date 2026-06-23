# Auditor Selection Criteria (Weighted)

Use these weighted criteria to evaluate independent auditor candidates for the PoAW-X Phases 28–34
review. Score each candidate 0–5 per criterion in `CANDIDATE_SCORECARD_TEMPLATE.md`; the weighted total
guides shortlisting. Weights sum to 100. Testnet/devnet only; not audited; no auditor selected.

| # | Criterion | Weight | What "5" looks like |
|---|---|---|---|
| C1 | Blockchain consensus audit experience | 15 | Multiple public audits of L1/consensus systems |
| C2 | Rust systems / security experience | 12 | Deep Rust review of node software; memory/serialization safety |
| C3 | PoW / PoS / finality experience | 10 | Reviewed PoW + finality/checkpoint mechanisms |
| C4 | Cryptographic signature / evidence review | 10 | secp256k1/ECDSA, equivocation/double-sign proofs, digests |
| C5 | Reorg / replay / state-machine audit | 12 | Found reorg/replay state bugs before; rigorous on determinism |
| C6 | Economic / incentive review capability | 8 | Models inflation, grinding, centralization incentives |
| C7 | Reviews testnet-only experimental consensus | 5 | Comfortable reviewing pre-production, gated, evolving code |
| C8 | Independence / conflict-of-interest | 8 | No financial/promotional/relationship conflicts (see COI checklist) |
| C9 | Communication quality | 5 | Clear, responsive, asks sharp questions |
| C10 | Report quality | 6 | Public reports are precise, severity-rated, reproducible |
| C11 | Retest / remediation support | 5 | Includes remediation retest in engagement |
| C12 | Availability / timeline | 2 | Can start/deliver within the owner's window |
| C13 | Budget fit | 2 | Quote fits the approved budget range |
| | **Total** | **100** | |

## Scoring guidance

- 0 = none/unacceptable, 1–2 = weak, 3 = adequate, 4 = strong, 5 = excellent.
- **Weighted score** = Σ(criterion score × weight) / 5, max 100.
- Treat **C8 (independence)** as a gate: a serious conflict (see `CONFLICT_OF_INTEREST_CHECKLIST.md`)
  disqualifies regardless of total.
- Treat **C1/C5 (consensus + reorg/replay)** as the most important technical signals for this work.

## Notes

- These criteria are a decision aid, not a ranking of any real firm. Do **not** populate with invented
  candidates; the owner fills real candidates in the scorecard/shortlist.
- An auditor that cannot review **without** asserting mainnet readiness, or that promises a "certified
  safe" result, is a red flag (see `AUDITOR_RED_FLAGS.md`).
