# Engagement Scope Options

Four scope levels for the PoAW-X Phases 28–34 review. The owner selects one (or a custom mix) before
outreach. Recommended for a consensus overlay of this kind: **Scope C or D**. Testnet/devnet only; not
audited.

## Scope A — Document & threat-model review only
- **Included:** review of the Phase 35/36 docs + threat model; sanity-check of claims vs. described
  design. No code review.
- **Excluded:** source-code review, tests, replay/reorg, economic analysis.
- **Deliverables:** a written assessment of the documentation + threat model; gaps/questions list.
- **Best use case:** a cheap first pass / feasibility check before committing to a full review.
- **Owner decision needed:** is a docs-only pass worth it, or go straight to code review?

## Scope B — Focused consensus code review (Phases 28–34)
- **Included:** code review of the in-scope modules + the four wire sections; mainnet-hard-off and
  invariant spot-checks.
- **Excluded:** independent test re-runs/fuzzing, deep replay/reorg modeling, economic analysis,
  remediation retest.
- **Deliverables:** findings report (severity-rated) on the consensus code.
- **Best use case:** budget-constrained; wants eyes on the code but not a full audit.
- **Owner decision needed:** acceptable to skip independent testing + retest?

## Scope C — Full consensus + tests + replay/reorg review
- **Included:** Scope B + independent test execution/fuzzing + thorough replay/reorg/state-machine
  review + wire-compatibility review.
- **Excluded:** deep economic/incentive modeling; remediation retest (optional add-on).
- **Deliverables:** full technical findings report + reproduction notes + coverage assessment.
- **Best use case:** the technical-correctness audit most appropriate for this work.
- **Owner decision needed:** add economic review and retest (→ Scope D)?

## Scope D — Full audit + economic/incentive review + retest
- **Included:** Scope C + economic/incentive analysis + a remediation **retest** after fixes.
- **Excluded:** mainnet/public-testnet sign-off (out of scope by policy), ops/wallet/exchange.
- **Deliverables:** full report, executive summary, severity-rated findings, economic assessment,
  retest verdicts, residual-risk statement.
- **Best use case:** the most complete review before considering any public-testnet planning.
- **Owner decision needed:** budget/timeline approval for the full engagement.

## Cross-cutting (all scopes)

- All scopes are **testnet/devnet only**; none authorizes mainnet or a public testnet.
- Map the chosen scope to `AUDIT_DELIVERABLES_EXPECTED.md` (Phase 36) and to the
  `BUDGET_TIMELINE_TEMPLATE.md`.
- Record the choice in `OWNER_DECISION_LOG.md`.
