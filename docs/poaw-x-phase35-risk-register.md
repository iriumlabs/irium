# PoAW-X Phase 35 — Risk Register (Phases 27–34 closeout)

Testnet/devnet only; mainnet hard-off; off by default. This register tracks the risks that remain
**open** at the end of the Phase 27–34 implementation track. It is not exhaustive and is not a
substitute for an independent audit.

Likelihood/Impact are qualitative (Low/Med/High). "Residual" = risk after the listed mitigation, with
the mitigation **not yet done** unless stated.

| # | Risk | Likelihood | Impact | Mitigation (status) | Residual |
|---|---|---|---|---|---|
| R1 | **No independent audit yet** — consensus additions unreviewed by an external party | High | High | Commission audit using `docs/poaw-x-phase35-audit-readiness-package.md` (NOT done) | High until done |
| R2 | **No public testnet yet** — combined stack never run publicly | High | High | Execute staged public-testnet plan (NOT done) | High until done |
| R3 | **No long-running public adversarial test** — no real-world attacker pressure on double-sign/dominance/adaptive paths | High | High | Monitored public testnet + adversarial program (NOT done) | High until done |
| R4 | **Activation/gate complexity** — many env activation heights + required flags must be set consistently across nodes; misconfiguration can split consensus or silently disable a protection | Med | High | Operator runbook + a single coordinated config profile; config-consistency checks (partial; needs runbook hardening) | Med |
| R5 | **Wire compatibility needs external review** — `DSE1`/`TKT1`/`DMC1`/`ADM1` trailing sections and irx1-root folding | Med | High | Audit + deserializer fuzzing (NOT done) | Med–High |
| R6 | **Deep-scale sync not live-stressed after Phase 34** — cold-resync/historical-admission paths (Phase 26D/26E) not re-validated with all 28–34 gates active | Med | High | Internal multi-node devnet soak incl. fresh-wipe/cold-resync (NOT done) | Med–High |
| R7 | **Optional builder auto-inclusion gaps** — proposers do not yet auto-include locally-cached double-sign evidence into candidate blocks | Med | Med | Implement builder inclusion (future work; tests currently inject evidence) | Med |
| R8 | **Hard dominance caps deferred as policy** — Phase 33 commits dominance state but does not hard-cap concentration; mitigation relies on fairness weighting + adaptive Defense | Med | Med | Decide/implement hard-cap policy if desired (deferred) | Med |
| R9 | **Economic incentive review still needed** — combined reward/fairness/ticket/dominance/adaptive incentives not analyzed end-to-end | Med | High | Independent economic review (NOT done) | Med–High |
| R10 | **Governance / mainnet activation not started** — no process for who/when/how PoAW-X would ever activate beyond testnet | Low (now) | High (later) | Define governance + activation framework before any mainnet consideration (NOT started) | High when approached |
| R11 | **Combined-stack interaction risk** — single-phase soaks passed, but the 28–34 features have not been live-soaked *together* | Med | High | Internal multi-node devnet of the full stack (NOT done) | Med–High |
| R12 | **Determinism depends on shared parameters** — dominance window/lookback (env) feed committed digests + adaptive concentration; divergent values across nodes → consensus split | Low–Med | High | Pin a single consensus parameter profile; document + verify in runbook (partial) | Med |
| R13 | **Test-suite parallelism flakiness** — some env-mutating tests must run `--test-threads=1`; CI must enforce this or see false failures | Low | Low | Document required flag (done in docs); enforce in CI (CI not in scope here) | Low |

## Posture

- These risks keep the system at **not audited / not production-ready / not mainnet-ready /
  public-testnet planning-ready only**.
- The highest-leverage next actions are **R1 (audit)** and **R6/R11 (combined internal multi-node
  devnet soak)** — both gate everything downstream. A documentation-only plan for the combined-stack
  soak (R6/R11) is prepared at `docs/devnet/phase39-preaudit-multinode-soak/README.md`; **Stage A was
  executed in Phase 41** (loopback single-node: 6-block all-gates chain + cold replay PASS —
  `docs/devnet/phase41-soak-execution/PHASE41_FINAL_SOAK_REPORT.md`). **Phase 42 extended the harness to
  emit the Phase 31–34 sections** (TKT1/DMC1/ADM1) and a local smoke mined blocks accepted under DMC +
  adaptive **required** (`docs/devnet/phase42-live-harness-phase31-34-sections/README.md`). R6/R11 remain
  **open**: genuine multi-node convergence/fresh-wipe needs an owner-approved Stage B (cross-host), and
  full ticket-store *eligibility* enforcement live is still future work (H→H+1 timing).
- Nothing in this register authorizes a public testnet or mainnet launch.
