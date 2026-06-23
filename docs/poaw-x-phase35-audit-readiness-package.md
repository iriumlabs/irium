# PoAW-X Phase 35 — Audit-Readiness Package (Phases 28–34)

**This is an audit-ready package, not an audit. The code has NOT been independently audited.**
Testnet/devnet only; mainnet hard-off; off by default.

This document orients an independent reviewer to the PoAW-X consensus additions made in Phases 28–34. It
does not assert correctness — it points reviewers at the exact code, invariants, and risks to check.

> **Kickoff package (Phase 36):** the operational auditor-kickoff package built on top of this readiness
> doc is at `docs/audit/phase36-independent-audit-kickoff/` (review guide, invariants checklist, repro
> commands, findings template, questions, deliverables, status). Auditor not yet selected; audit not yet
> started. The owner-facing auditor **selection & engagement-prep** package (Phase 37) is at
> `docs/audit/phase37-auditor-selection-engagement/README.md`.

## 1. Audit scope

In scope (consensus-relevant additions on the linear chain `40db1aa..78d5ca3`):

- Finalized checkpoint + reorg-below-finalized rejection (Phase 28)
- Double-sign evidence + penalty state, block-carried evidence + finality exclusion (Phases 29–30)
- Reward manifest wrapper + caps + low-participation fallback (Phase 31)
- On-chain ticket store + rate-limit/expiry + eligibility (Phase 32)
- Dominance-state commitment (Phase 33)
- Adaptive-mode consensus integration (Phase 34)
- The trailing-optional block wire sections: `DSE1`, `TKT1`, `DMC1`, `ADM1`

Out of scope (unchanged by this track; do not assume reviewed here): LWMA-144, PoW target, SHA-256d
anchor work, base block reward, mainnet activation, pool, wallet/keys.

## 2. Code ranges (verified remote refs)

Review each phase as the diff from the previous HEAD:

| Phase | Range | Primary files |
|---|---|---|
| 28 | `40db1aa..199ed24` | `src/chain.rs` (finalized checkpoint, `reorg_to_tip`) |
| 29 | `199ed24..df0cc92` | `src/poawx_doublesign.rs`, `src/poawx_penalty.rs` |
| 30 | `df0cc92..7e5f805` | `src/poawx.rs` (`DSE1`), `src/chain.rs` (validate/apply/rebuild) |
| 31 | `7e5f805..fae91bb` | `src/poawx_reward.rs`, `src/chain.rs` |
| 32 | `fae91bb..8f2a64d` | `src/poawx_ticket.rs`, `src/poawx.rs` (`TKT1`), `src/chain.rs` |
| 33 | `8f2a64d..1a032de` | `src/poawx_dominance.rs`, `src/poawx.rs` (`DMC1`), `src/chain.rs` |
| 34 | `1a032de..78d5ca3` | `src/poawx_adaptive.rs`, `src/poawx.rs` (`ADM1`), `src/chain.rs` |

Whole-track consensus surface: `src/chain.rs` `connect_block` + `reorg_to_tip` + the per-phase
`validate_block_*` / `rebuild_*_from_chain` helpers, and the per-feature modules above plus
`src/poawx.rs` (`Phase20ReceiptExt` serialization).

## 3. Key invariants to verify

1. **Mainnet hard-off.** Every gate returns false when `network_id == 0`. Single convention:
   `if network_id == 0 { return false }` in each `*_gate`/`*_active`/`*_required`.
2. **Off by default.** With no env activation set, behavior is byte- and result-identical to pre-phase.
3. **Trailing-optional byte-identity.** `DSE1`/`TKT1`/`DMC1`/`ADM1` absent ⇒ serialized block bytes are
   identical to the prior format; present ⇒ folded into the irx1 receipt root.
4. **Non-retroactive derivation.** Block H validated under state from blocks `< H`; H's own
   evidence/registrations/commitments take effect from H+1.
5. **Deterministic replay.** Cold replay (`rebuild_to_tip`) reconstructs all derived state
   (checkpoint, penalty, ticket store, dominance, adaptive) purely from the chain.
6. **Reorg safety.** Derived state is snapshot/restored on failed reorg and rebuilt from the *active*
   chain on success; abandoned-fork data never persists.
7. **No weakening.** Phases 28–34 only *add* checks; phase21d/21e/22a and earlier gates are unchanged
   (Phase 31 cap gate is a strict superset of the exact-match payout check).
8. **Adaptive consensus uses only chain-derived signals.** `PoawxAdaptiveChainSignals` has no field for
   local-only data (peer count, rejected forks, mempool, clock, gossip).
9. **Commitment integrity.** `DMC1`/`ADM1` bind pre/post digests; tampering any field is rejected.

## 4. High-risk areas for auditors (look here first)

- **`reorg_to_tip` (`src/chain.rs`).** Ordering of disconnect → rebuild-to-ancestor → connect-new →
  restore-on-failure → rebuild-on-success across *five* derived states (checkpoint, penalty, ticket,
  dominance, adaptive). Cross-state consistency during a mid-reorg failure is the subtlest area.
- **Adaptive-state vs. underlying-cache consistency during reorg (Phase 34).** Signals are derived from
  `self.dominance` (consistent) + a bounded scan of committed blocks, deliberately *not* from the
  ticket/penalty caches (which are stale during the new-branch connect loop). Verify this reasoning.
- **Wire parsing of trailing sections (`src/poawx.rs`).** Strict length/version checks, duplicate-section
  rejection, unknown-magic rejection, and caps (`DSE1` ≤ 16) — fuzz the deserializers.
- **Finality suspended-signer exclusion (Phase 30).** Epoch handling in
  `is_eligible_for_finality` and committee derivation `committee_pkhs_at`.
- **Reward caps + fallback (Phase 31).** That the additive cap gate cannot false-reject a valid block
  and cannot be used to *increase* a payout.
- **Determinism of windowed metrics.** Dominance window/lookback are env parameters that feed committed
  digests (`DMC1`) and the adaptive concentration signal — all nodes must use identical values
  (operator coordination requirement; document, then verify the digest depends on them).

## 5. Test command summary

```
cargo test --lib -- --test-threads=1            # full suite (822/0 reported at Phase 34)
cargo test --bin poawx-sim -- --test-threads=1  # simulator (17/0)
# focused:
cargo test --lib phase28 -- --test-threads=1    # 8/0
cargo test --lib phase29 -- --test-threads=1    # 12/0
cargo test --lib phase30 -- --test-threads=1    # 7/0
cargo test --lib phase31 -- --test-threads=1    # 9/0
cargo test --lib phase32 -- --test-threads=1    # 12/0
cargo test --lib phase33 -- --test-threads=1    # 9/0
cargo test --lib phase34 -- --test-threads=1    # 17/0
cargo build --release --bin iriumd --bin poawx-live-proof-harness --bin poawx-sim
```

Note: some env-mutating tests are flaky under parallelism; run library tests with `--test-threads=1`.

## 6. Known limitations (carried)

- No independent audit (this package is the handoff, not a result).
- No public testnet; no live multi-node soak of the *combined* 28–34 stack; deep-scale sync not
  re-stressed with all gates active after Phase 34.
- Proposer/builder auto-inclusion of locally-cached double-sign evidence is future work (tests inject
  evidence directly).
- Hard dominance caps deferred as policy (Phase 33 commits state; it does not cap).
- Economic-incentive review of the combined system not done.
- Wire-format additions not externally reviewed.

## 7. Suggested auditor review order

1. Read `docs/poaw-x-phase35-final-closeout.md` and this package.
2. Confirm the mainnet-hard-off + off-by-default invariants (cheap, high-value).
3. Review the wire serialization in `src/poawx.rs` (`Phase20ReceiptExt`) and the four trailing sections.
4. Review `connect_block` per-phase `validate_block_*` in `src/chain.rs`, phase by phase (28→34).
5. Review `reorg_to_tip` and every `rebuild_*_from_chain` together for cross-state consistency.
6. Review per-feature modules (`poawx_doublesign`, `poawx_penalty`, `poawx_reward`, `poawx_ticket`,
   `poawx_dominance`, `poawx_adaptive`).
7. Re-run the focused + full test suites; consider fuzzing the deserializers.

**Reminder: not audited, not production-ready, not mainnet-ready.**
