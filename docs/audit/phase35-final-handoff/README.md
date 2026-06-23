# PoAW-X Phase 35 — Final Audit Handoff

**Auditor-facing entry point.** Testnet/devnet only; mainnet hard-off; off by default.
**Not audited, not production-ready, not mainnet-ready, not public-testnet live-ready.**

This folder is the starting point for an independent review of the PoAW-X consensus additions made in
Phases 28–34 (closing the six deferred items from the Phase 27 blueprint gap audit).

> **Phase 36 kickoff package:** the operational kickoff package (review guide, invariants checklist,
> repro commands, findings template, auditor questions, deliverables, outreach draft, status) is at
> `docs/audit/phase36-independent-audit-kickoff/README.md`. Auditor not yet selected; audit not yet
> started. The owner-facing auditor selection & engagement-prep package (Phase 37) is at
> `docs/audit/phase37-auditor-selection-engagement/README.md`.

## Where to start

1. `docs/poaw-x-phase35-final-closeout.md` — executive summary + status + remaining gates.
2. `docs/poaw-x-phase35-audit-readiness-package.md` — scope, code ranges, invariants, high-risk areas,
   suggested review order, test commands. **This is the main auditor guide.**
3. `docs/poaw-x-phase35-consensus-feature-matrix.md` — per-feature enforcement/replay/reorg/mainnet-off.
4. `docs/poaw-x-phase35-phases27-34-commit-map.md` — verified branch/commit lineage + diffstats + tests.
5. `docs/poaw-x-phase35-risk-register.md` — open risks.
6. `docs/poaw-x-phase35-public-testnet-readiness.md` — staged plan (planning-ready only).

## Branch heads (verified on `origin`)

| Phase | Branch (`testnet/poawx-…`) | HEAD |
|---|---|---|
| 27 | `phase27-full-blueprint-implementation` | `40db1aa` |
| 28 | `phase28-finalized-reorg-rejection` | `199ed24` |
| 29 | `phase29-double-sign-penalties` | `df0cc92` |
| 30 | `phase30-block-carried-doublesign-evidence` | `7e5f805` |
| 31 | `phase31-reward-manifest-wrapper-cap-fallback` | `fae91bb` |
| 32 | `phase32-onchain-ticket-store` | `8f2a64d` |
| 33 | `phase33-dominance-state-commitment` | `1a032de` |
| 34 | `phase34-adaptive-modes-consensus-integration` | `78d5ca3` |

`origin/main` is **unchanged** at `19c496dc5f2fa08981a109b10eeb257105c28c43` (PoAW-X never landed on
main; it is hard-off on mainnet regardless).

## Critical docs (per phase, for deep dives)

- Phase 28: `docs/poaw-x-phase28-finalized-reorg-rejection.md` (+ design)
- Phase 29: `docs/poaw-x-phase29-double-sign-penalties.md` (+ design)
- Phase 30: `docs/poaw-x-phase30-block-carried-doublesign-evidence.md` (+ design)
- Phase 31: `docs/poaw-x-phase31-reward-manifest-wrapper.md` (+ design)
- Phase 32: `docs/poaw-x-phase32-onchain-ticket-store.md` (+ design)
- Phase 33: `docs/poaw-x-phase33-dominance-state-commitment.md` (+ design)
- Phase 34: `docs/poaw-x-phase34-adaptive-consensus-integration.md` (+ design)
- Prior audit packages: `docs/audit/poaw-x/` and `docs/audit/poawx-phase26-*`.

## Test evidence

- Full library suite: **822 passed / 0 failed** (cumulative at Phase 34; was 748 at Phase 27).
- Simulator (`poawx-sim`): **17 passed / 0 failed**.
- Focused per-phase: 28=8, 29=12, 30=7, 31=9, 32=12, 33=9, 34=17 (all 0 failed).
- Commands: see `docs/poaw-x-phase35-audit-readiness-package.md` §5. Run library tests with
  `--test-threads=1` (some env-mutating tests are parallel-flaky).

## Known limitations

- No independent audit (this is the handoff).
- No public testnet; no combined-stack live multi-node soak; deep-scale sync not re-stressed post-34.
- Proposer auto-inclusion of double-sign evidence is future work; hard dominance caps deferred as
  policy; economic-incentive review pending; governance/mainnet-activation not started.
- See `docs/poaw-x-phase35-risk-register.md` for the full list.

## Contact / action checklist (placeholders — fill before sending)

- [ ] Audit owner / point of contact: _TBD_
- [ ] Auditor / firm: _TBD_
- [ ] Engagement scope confirmed against the audit-readiness package: _TBD_
- [ ] Findings tracker location: _TBD_ (reuse `docs/audit/…/FINDINGS_TRACKER.md` pattern)
- [ ] Remediation branch policy agreed: _TBD_
- [ ] Re-test protocol agreed: _TBD_
- [ ] Go/no-go owner for any next step (internal devnet → public testnet): _TBD_

**Nothing here authorizes a public testnet or mainnet launch.**
