# Auditor Questions — PoAW-X Phases 28–34

The specific questions we want the independent review to answer. Each maps to invariants in
`CONSENSUS_INVARIANTS_CHECKLIST.md` and steps in `AUDITOR_REVIEW_GUIDE.md`. Not audited yet.

1. **Are the optional ext sections wire-safe?**
   Are `DSE1` / `TKT1` / `DMC1` / `ADM1` byte-identical to the prior format when `None`, strictly parsed
   (length/version/dup/unknown-magic/caps), and is there any way malformed or adversarial ext data is
   accepted or causes non-deterministic state? (I9, I10)

2. **Are the gates sufficient to prevent mainnet behavior?**
   Can any code path enable a PoAW-X feature when `network_id == 0`, or with no env set? Is the hard-off
   convention applied consistently everywhere? (I1)

3. **Are replay/reorg transitions deterministic?**
   Do cold replay and reorg reconstruct all five derived states identically, and is `reorg_to_tip`
   cross-state consistent on both success and mid-reorg failure? (I7, I8, I16)

4. **Can local-only signals affect consensus anywhere?**
   Peer count, locally-rejected forks, mempool, node clock, uncommitted gossip, locally-cached
   double-sign evidence — can any of these influence block acceptance or the adaptive mode? (I5, I6)

5. **Are reward caps/fallback non-inflationary?**
   Can the manifest caps or the low-participation fallback ever make total payout exceed subsidy + fees,
   or be used to increase a payout? (I12)

6. **Can ticket registrations be spammed or replayed?**
   Is the Sybil cost (leading-zero bits) enforced, are epoch rate-limiting and expiry deterministic, and
   can a registration be replayed across epochs/forks? (I14)

7. **Can abandoned-fork state pollute the active chain?**
   After a reorg, can penalty/ticket/dominance/adaptive/checkpoint state carried only on the abandoned
   fork persist on the active chain? (I8)

8. **Can adaptive modes deadlock liveness?**
   Can any mode (especially Defense/Recovery and the additive effects) make valid blocks unproducible or
   the chain unable to progress? Is the Recovery window finite/deterministic? (I17)

9. **Are finality penalties safe against false positives?**
   Can a non-equivocating signer be wrongly excluded from finality, and is the suspended-signer exclusion
   deterministic across nodes/replay? (I13)

10. **Are the simulations aligned with consensus code?**
    Does `poawx-sim` faithfully reuse the real primitives, and are its abstractions (network timing,
    mempool, local signals) clearly non-consensus and not overstating guarantees? (Review step 11)

### Additional cross-cutting questions

- Is the **shared-parameter** requirement (dominance window/lookback feeding committed digests) a
  consensus-split risk if operators misconfigure it, and is it adequately documented? (I18)
- Are there interactions **between** features (e.g. adaptive Defense requiring committed-admission +
  finality) that could combine into an unexpected acceptance or liveness failure?
- Is the **non-retroactive timing** (H validated under state < H; H's data effective H+1) correct and
  free of off-by-one errors at activation boundaries? (I16)
