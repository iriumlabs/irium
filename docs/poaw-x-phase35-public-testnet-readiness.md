# PoAW-X Phase 35 — Public-Testnet Readiness

**Status: public-testnet planning-ready ONLY. Not public-testnet live-ready. Not mainnet-ready. Not
audited.** This document is a plan, not an approval to launch anything.

Testnet/devnet only; PoAW-X hard-off on mainnet; all features off by default behind env gates.

> **Gating note (Phase 36):** the **independent audit** is the first gate below and its kickoff package
> is at `docs/audit/phase36-independent-audit-kickoff/README.md`. Auditor not yet selected; audit not yet
> started. Public testnet remains planning-ready only.

## 1. What is now implementation-complete enough for planning

The Phase 27 deferred consensus items are closed at branch level (Phases 28–34) and are
consensus-enforced, block-carried (where applicable), deterministic, replayable, and reorg-safe, with
748→822 passing library tests and a deterministic simulator (see
`docs/poaw-x-phase35-consensus-feature-matrix.md`). That is enough to **begin planning** a public
testnet — i.e., to write the plan, runbooks, monitoring, and rollback procedure — **not** to start one.

## 2. What must happen before a public testnet

These are gates (each must pass before the next), none of which is done:

1. **Independent audit** of Phases 28–34 + remediation of findings + re-test (R1).
2. **Internal multi-node devnet soak of the combined stack** with all gates active, including
   fresh-wipe/cold-resync and deep-scale sync (R6/R11). A documentation-only **soak plan** (scope,
   topology, safety boundaries, runbook draft, scenarios, metrics, pass/fail, abort/rollback) is prepared
   at `docs/devnet/phase39-preaudit-multinode-soak/README.md` — **soak not yet executed**; execution is a
   separate owner-approved phase.
3. **Economic-incentive review** of the combined system (R9).
4. **Operator runbook + single coordinated config profile** (consensus parameters pinned; R4/R12).
5. **Monitoring/metrics + rollback plan** validated on the internal devnet (sections 4–5 below).
6. **Explicit go/no-go decision** recorded against this checklist.

## 3. Suggested public-testnet phases (staged)

1. **Private replay audit** — auditors replay the chain + review code/wire against the audit package;
   no new network.
2. **Internal multi-node devnet** — operator-controlled nodes, all gates active, soak + adversarial
   injection (double-sign, dominance concentration, low participation → adaptive Defense/Caution),
   reorg + cold-resync drills.
3. **Closed external miner test** — a small set of invited, known miners; isolated network; tight
   monitoring; abort criteria defined up front.
4. **Public testnet announcement** — only after 1–3 pass; publish runbook, faucet/reset policy, and
   explicit "testnet, not mainnet, tokens have no value" framing.
5. **Monitored public testnet** — open participation under active monitoring with the rollback plan
   armed.

Each transition requires a recorded go/no-go.

## 4. Required monitoring / metrics

- Per-block: height, tip hash, irx1 root, accepted/rejected counts and reject reasons.
- Consensus features: finalized checkpoint height; double-sign evidence count + penalized/suspended
  signers; reward-cap/fallback activations; active ticket count + rate-limit/expiry events; dominance
  concentration (permille) + commitment validity; **adaptive mode (pre/post) + trigger + recovery
  window** + commitment validity.
- Network/sync: peer count, reorg depth/frequency, cold-resync time, fresh-wipe sync success, stalled-
  sync warnings.
- Config integrity: every node's activation-height/required-flag profile + dominance window/lookback
  (must match across nodes — divergence is a consensus-split risk, R12).
- Liveness/safety: block interval vs. target (LWMA unchanged), orphan rate, finality lag.

(These are operator/telemetry signals — they are **not** consensus inputs; adaptive consensus mode
derives only from chain-derived state.)

## 5. Rollback plan (must be validated on internal devnet first)

- **Gate disable:** because every feature is env-gated and off-by-default, the first-line rollback is to
  disable a feature's activation/required flag at a coordinated height across nodes (testnet only).
- **Testnet reset/rollback policy:** reuse/extend the existing testnet reset-rollback policy doc; define
  reset height, snapshot, and operator coordination.
- **Abort criteria:** consensus split, repeated cold-resync failure, unexpected reorg-below-finalized
  rejection storms, or any safety-invariant violation → halt new participation, freeze config, collect
  evidence, reset per policy.
- **No mainnet impact:** mainnet stays hard-off throughout; rollback never touches mainnet/prod.

## 6. Node / operator runbook gaps (to close before phase 3 above)

- A single, version-pinned **consensus config profile** (all activation heights + required flags +
  dominance window/lookback) with a verification command operators run before joining.
- Combined-stack startup/sync runbook (incl. fresh-wipe + cold-resync expectations).
- Monitoring dashboard wiring for the metrics in §4.
- Documented abort/rollback drill results from the internal devnet.

## 7. Statement

This document makes the project **public-testnet planning-ready only**. It does **not** declare the
software public-testnet live-ready, mainnet-ready, audited, or approved for launch. Starting a public
testnet requires completing §2 and a recorded go/no-go.
