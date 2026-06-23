# Auditor Review Guide — PoAW-X Phases 28–34

Suggested order. Each step lists what to confirm and where to look. Testnet/devnet only; mainnet
hard-off. Not audited.

### 1. Activation gates / mainnet hard-off
- Confirm every PoAW-X gate returns false when `network_id == 0`. Convention: `if network_id == 0 {
  return false }` in each `*_gate` / `*_active` / `*_required`.
- Confirm "off by default": with no env activation set, results are identical to pre-phase.
- Files: `src/activation.rs`, and the `*_gate`/`*_active`/`*_required` fns in each `poawx_*` module.

### 2. Block extension wire compatibility — `DSE1`, `TKT1`, `DMC1`, `ADM1`
- Confirm each trailing-optional section is **byte-identical to the prior format when `None`** (no
  marker emitted) and is folded into the irx1 receipt root when present.
- Confirm strict deserialization: length/version checks, duplicate-section rejection, unknown-magic
  rejection, and caps (`DSE1` ≤ 16). Consider fuzzing the deserializers.
- File: `src/poawx.rs` (`Phase20ReceiptExt::serialize`/`deserialize`).

### 3. phase21d/21e/22a invariants remain intact
- Confirm Phases 28–34 only *add* checks and do not weaken candidate-set (21d), candidate-admission
  (21e), or committed-admission (22a) validation. Phase 31's cap gate must be a strict superset of the
  existing exact-match payout check.
- File: `src/chain.rs` (the 21d/21e/22a validators are unchanged; verify by diff).

### 4. Finalized-checkpoint reorg rejection (Phase 28)
- Confirm the checkpoint is derived in `connect_block` after finality validation, advances
  monotonically, is reconstructed on cold replay, and that `reorg_to_tip` rejects any reorg whose fork
  point is below it (even higher-work). Confirm snapshot/restore on a failed reorg.

### 5. Block-carried double-sign evidence / penalty replay (Phases 29–30)
- Confirm evidence is validated and applied in `connect_block` (effective H+1, non-retroactive),
  penalized signers are excluded from finality, the penalty state is replay-reconstructed and rebuilt
  from the active chain on reorg, and that **local** (gossip-cached) evidence is non-consensus.

### 6. Reward manifest caps / fallback (Phase 31)
- Confirm the cap gate cannot increase a payout and cannot false-reject a valid block; confirm the
  low-participation fallback keeps total ≤ subsidy + fees (non-inflationary).

### 7. On-chain ticket store / Sybil / rate-limit / expiry (Phase 32)
- Confirm registrations are validated/deduped/ordered, Sybil cost (leading-zero bits) is enforced, epoch
  rate-limiting and expiry/pruning are deterministic, the store is replay/reorg-safe, and eligibility
  enforcement (when gated) is a strict superset.

### 8. Dominance commitment replay / reorg (Phase 33)
- Confirm `DMC1` binds pre/post digests of the reorg-safe anti-domination state; pre = current digest,
  post = digest after applying the block's role rewards; tampering any field rejects the block.

### 9. Adaptive modes — deterministic triggers / effects (Phase 34)
- Confirm the transition uses **only** chain-derived signals (`PoawxAdaptiveChainSignals` has no
  local-only field), constants are fixed (not per-node env), the `ADM1` commitment binds pre/post mode +
  state digests + metrics digest, effects are additive/gated (never weaken), and the post-mode governs
  H+1 (non-retroactive).

### 10. Cold replay / reorg / sync safety
- Confirm `rebuild_to_tip` reconstructs all five derived states (checkpoint, penalty, ticket, dominance,
  adaptive) from the chain alone, and that `reorg_to_tip` keeps them cross-consistent (disconnect →
  rebuild-to-ancestor → connect-new → restore-on-failure → rebuild-on-success). Abandoned-fork state
  must never persist on the active chain.

### 11. Simulation assumptions vs consensus
- Confirm `poawx-sim` reuses the real primitives and that any abstraction (network timing, mempool,
  local signals) is clearly non-consensus and does not overstate guarantees. The sim is a model, not a
  proof.

Record results in `FINDINGS_TRACKER_TEMPLATE.md`; work the `CONSENSUS_INVARIANTS_CHECKLIST.md`;
reproduce via `REPRO_COMMANDS.md`.
