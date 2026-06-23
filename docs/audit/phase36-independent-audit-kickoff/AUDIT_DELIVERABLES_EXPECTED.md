# Expected Audit Deliverables — PoAW-X Phases 28–34

What we ask the independent auditor to produce. Testnet/devnet only; not audited yet.

1. **Threat-model review** — validate/extend the project threat model (`docs/audit/poaw-x/THREAT_MODEL.md`)
   against the Phase 28–34 additions: double-sign/equivocation, Sybil, dominance/centralization, reward
   manipulation, reorg/finality attacks, adaptive-mode abuse.

2. **Consensus-correctness review** — confirm `connect_block` acceptance is correct and that Phases
   28–34 only add strictness (no weakening of phase21d/21e/22a; non-inflation; mainnet hard-off).

3. **Replay/reorg review** — confirm cold replay and reorg reconstruct all derived state (checkpoint,
   penalty, ticket, dominance, adaptive) deterministically and cross-consistently, including mid-reorg
   failure restore and abandoned-fork isolation.

4. **Wire-compatibility review** — confirm `DSE1`/`TKT1`/`DMC1`/`ADM1` are byte-safe when absent,
   strictly parsed when present, and that the irx1-root folding is correct; ideally fuzz the
   deserializers.

5. **State-transition review** — confirm deterministic transitions for penalties, tickets, dominance,
   and adaptive modes (including activation-boundary / non-retroactive timing and finite Recovery
   window).

6. **Economic/incentive review** — assess the combined reward/fairness/ticket/dominance/adaptive
   incentives for inflation, grinding, fee/reward manipulation, and centralization pressure.

7. **Test-coverage review** — assess the existing suite (822/0 lib, 17/0 sim) for gaps; recommend
   additional property/fuzz/adversarial tests; the auditor should re-run independently.

8. **Final report** — findings (severity-rated, per `FINDINGS_TRACKER_TEMPLATE.md`), an executive
   summary, and an overall risk assessment. The report should explicitly state it is **not** a mainnet or
   public-testnet approval.

9. **Remediation retest** — after the project remediates findings on a dedicated remediation branch,
   re-test and record verdicts; close findings only with retest evidence.

## Acceptance criteria for the engagement

- All in-scope phases (28–34) and the four wire sections reviewed.
- Each `CONSENSUS_INVARIANTS_CHECKLIST.md` item given a Pass/Fail/N-A verdict.
- Each `AUDITOR_QUESTIONS.md` question answered.
- Findings filed with severity, repro, and recommendation.
- A clear statement of residual risk for any unresolved item.

Nothing in these deliverables authorizes a public testnet or mainnet launch; those are separate,
owner-gated decisions (see `docs/poaw-x-phase26-next-decision-tracker.md`).
