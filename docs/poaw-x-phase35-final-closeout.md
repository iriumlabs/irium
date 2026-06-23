# PoAW-X Phase 35 — Final Closeout (Phases 27–34)

**Documentation-only consolidation.** No consensus logic was implemented in Phase 35.

Status at a glance:
- Production-ready: **no**
- Mainnet-ready: **no**
- Audited: **no**
- Public-testnet-ready: **not yet — planning-ready only**

Scope guard: testnet/devnet only; PoAW-X is **hard-off on mainnet** (`network_id == 0`) and every
feature below is additionally **off by default** behind explicit env activation gates. Nothing here
approves a mainnet launch.

> **Next (Phase 36):** the independent-audit kickoff package is at
> `docs/audit/phase36-independent-audit-kickoff/README.md`. Auditor not yet selected; audit not yet
> started.

---

## 1. Executive summary

The PoAW-X Phase 27–34 track took the Phase 27 "full blueprint" gap analysis and closed its six
deferred consensus items, each as its own scoped, gated, test-backed phase:

| Deferred item (Phase 27) | Closed in | Branch HEAD |
|---|---|---|
| 5A finalized-checkpoint reorg rejection | Phase 28 | `199ed24` |
| 5B double-sign → penalty wiring | Phases 29 (primitive) + 30 (consensus) | `df0cc92` / `7e5f805` |
| 1D reward manifest wrapper + caps + fallback | Phase 31 | `fae91bb` |
| 2E on-chain ticket store + rate-limit/expiry | Phase 32 | `8f2a64d` |
| 3C dominance-state commitment | Phase 33 | `1a032de` |
| 6F adaptive-mode consensus integration | Phase 34 | `78d5ca3` |

Each item is now **consensus-enforced, block-carried (where applicable), deterministic, replayable, and
reorg-safe**, validated by a growing library test suite (**748 → 822 passing**, 0 failing) plus a
deterministic off-chain simulator (`poawx-sim`, 11 → 17 scenarios/tests). Every feature is gated and
mainnet hard-off.

"Implementation-complete at branch level" is **not** the same as audited or production-ready. The
remaining work is independent audit, live multi-node testing, public-testnet planning/execution, and
governance — none of which is done.

## 2. What Phase 27 attempted

Phase 27 ("full blueprint implementation" branch `40db1aa`) consolidated the PoAW-X blueprint and the
off-chain simulator, and produced a gap audit (`docs/poaw-x-phase27-gap-audit.md`,
`docs/poaw-x-phase27-known-limitations.md`) listing six consensus-critical items it deliberately
**deferred** rather than implementing blind — because each would change consensus/reorg behavior and
needed its own design sign-off. Phase 27 was code+tests+simulation only; it did not run live nodes and
did not implement the deferred items.

## 3. What Phases 28–34 completed

- **Phase 28 — finalized-checkpoint reorg rejection.** `connect_block` derives a monotonic finalized
  checkpoint after finality validation; `reorg_to_tip` rejects any reorg whose fork point is below it
  (even a higher-work fork). Reconstructed on cold replay/rebuild. No new wire format.
- **Phase 29 — double-sign penalty primitive.** Validated `PoawxDoubleSignEvidenceV1` + deterministic,
  replayable penalty state + bounded local cache (local-only primitive; not yet consensus).
- **Phase 30 — block-carried double-sign evidence (consensus).** Evidence is carried in a trailing
  `DSE1` block section (committed into the irx1 root, cap 16, canonical/deduped), validated + applied in
  `connect_block` (effective from H+1, non-retroactive), reconstructed by replay / rebuilt on reorg, and
  **enforced** by excluding penalized signers from future finality.
- **Phase 31 — reward manifest wrapper + caps + fallback.** Versioned reward manifest with per-role caps
  and a low-participation fallback; additive cap gate is a strict superset of the existing exact-match
  payout check (never false-rejects a valid block).
- **Phase 32 — on-chain ticket store.** Block-carried ticket registrations (trailing `TKT1` section)
  build a deterministic, replayable, reorg-safe on-chain ticket store with epoch rate-limiting and
  expiry/pruning; optional eligibility enforcement.
- **Phase 33 — dominance-state commitment.** Block-carried `DMC1` commitment binding the pre/post
  digests of the (reorg-safe) anti-domination state; validated in `connect_block`.
- **Phase 34 — adaptive-mode consensus integration.** Deterministic, chain-derived adaptive mode
  (Normal/Caution/Defense/Recovery) committed per block via a trailing `ADM1` section; additive gated
  effects reuse Phase 28/30/32/33 checks; local-only signals are structurally excluded from consensus.

Test evidence and the full commit map are in `docs/poaw-x-phase35-phases27-34-commit-map.md` and
`docs/poaw-x-phase35-consensus-feature-matrix.md`.

## 4. Why this is still testnet/devnet only

- PoAW-X stays hard-off on mainnet (`network_id == 0`); every gate returns false there.
- Every feature is additionally off by default behind explicit env activation heights / required flags.
- No independent audit has been performed.
- No public testnet has been run; post-Phase-34 there has been no live multi-node soak of the combined
  consensus stack, and deep-scale sync has not been re-stressed with all gates active.
- Wire-format additions (`DSE1` / `TKT1` / `DMC1` / `ADM1` trailing sections) have not had external
  review.

## 5. Current status

| Dimension | Status |
|---|---|
| Production-ready | **No** |
| Mainnet-ready | **No** |
| Audited | **No** |
| Public-testnet-ready | **No — planning-ready only** |
| Implementation (branch level) | Phase 27 deferred items 5A/5B/1D/2E/3C/6F closed on their branches |
| Mainnet PoAW-X | Hard-off (`network_id == 0`); unchanged |
| `origin/main` | Unchanged at `19c496dc5f2fa08981a109b10eeb257105c28c43` |

## 6. Exact remaining gates before public testnet / mainnet

1. **Independent security audit** of the PoAW-X consensus additions (Phases 28–34), then remediation of
   any findings and re-test. (Not started.)
2. **Internal multi-node devnet soak** of the *combined* stack with all gates active (single-phase
   live soaks were done earlier; the full 28–34 combination has not been live-soaked together).
3. **Deep-scale / cold-resync stress** with all gates active (extends the Phase 26D/26E sync work).
4. **Public-testnet plan execution** — see `docs/poaw-x-phase35-public-testnet-readiness.md` (private
   replay audit → internal devnet → closed external miner test → announced public testnet → monitored
   run). Each is a gate, not a formality.
5. **Economic-incentive review** of the combined reward/fairness/ticket/dominance/adaptive system.
6. **Governance + mainnet-activation process** — explicit, separate approval; not in scope here and not
   approved.

**None of the above is complete. This document does not authorize a public testnet or a mainnet launch.**
