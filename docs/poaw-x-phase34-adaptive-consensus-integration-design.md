# PoAW-X Phase 34 — Adaptive-Modes Consensus Integration (Design)

Status: **testnet/devnet only — mainnet hard-off**.
Production-ready: **no**. Mainnet-ready: **no**. Audited: **no**.

This document is the design for closing deferred Phase 27 item **6F**: integrate the
PoAW-X adaptive security modes (`Normal` / `Caution` / `Defense` / `Recovery`) into
deterministic, replayable, reorg-safe consensus validation **without changing PoW,
LWMA, the SHA-256d anchor rules, the base block reward, or mainnet consensus**, and
**without weakening** any of phase21d/21e/22a, Phase 30 (block-carried double-sign
penalties), Phase 31 (reward caps/fallback), Phase 32 (on-chain ticket store), or
Phase 33 (dominance-state commitment).

---

## 0. Critical consensus-safety rule

Adaptive modes may **only** depend on chain-derived, deterministic, replayable state.
Local observations — local peer count, locally-rejected forks, mempool contents, node
clock drift, local network conditions, uncommitted gossip — **must not** affect the
consensus mode. A trigger that is not chain-derived/replayable is documented as
operator guidance only, never as a consensus input.

Consequence for the design: the consensus path does **not** read the legacy
`NetworkSignals` struct (it carries local-only fields `recent_invalid_work` and
`recent_reorg_signal`). Instead a new, strictly chain-derived signal type
(`PoawxAdaptiveChainSignals`) is the only input to the consensus transition function.

---

## 1. Current adaptive-mode primitives (pre-Phase-34)

`src/poawx_adaptive.rs` (Phase 21A) is a **data-only** state machine:

- `enum AdaptiveMode { Normal, Caution, Defense, Recovery }`
- `struct NetworkSignals { active_miner_count, valid_role_count, recent_invalid_work,
  recent_reorg_signal, reward_concentration_permille, finality_available }`
- `struct AdaptivePolicy { mode, confirmation_multiplier, stricter_verification,
  require_ticket_threshold, require_finality, role_fallback }`
- `fn assess(&NetworkSignals, prior_mode) -> AdaptivePolicy` — deterministic, with
  Defense → Recovery → Normal hysteresis.
- Thresholds: `CAUTION_MIN_MINERS=3`, `CAUTION_MIN_ROLES=3`, `DEFENSE_INVALID_WORK=5`,
  `DEFENSE_REORG_SIGNAL=2`, `DEFENSE_CONCENTRATION_PERMILLE=700`.
- `adaptive_mode_gate(network_id, activation, height)` (mainnet `network_id==0` →
  hard-off) and `adaptive_mode_active(height)`.

This is consumed today only by the off-chain simulator (`poawx-sim`). It is **not** part
of consensus, and two of its inputs (`recent_invalid_work`, `recent_reorg_signal`) are
local-only. Phase 34 keeps `NetworkSignals`/`assess()` intact for the simulator and
operator reporting, and adds a **separate, consensus-grade** chain-derived path.

---

## 2. Modes (Phase 34 consensus meaning)

| Mode | When | Validation posture |
|------|------|--------------------|
| `Normal` | healthy participation, no concentration/penalty triggers | existing PoAW-X validation only |
| `Caution` | low chain-derived participation (few registered tickets / low role participation) | + require dominance commitment & ticket eligibility where their gates are active |
| `Defense` | chain-carried double-sign evidence above threshold, or dominance concentration above threshold | + Caution effects + require committed-admission & finality-proof (incl. suspended-signer exclusion) where those gates are active |
| `Recovery` | a deterministic window of blocks immediately after leaving `Defense` | keeps Defense-level effects until the window elapses, then re-derives `Caution`/`Normal` |

---

## 3. Trigger model

### 3.1 Consensus-safe triggers (the ONLY inputs to the consensus transition)

All read from `self.dominance` (kept consistent across connect/disconnect/reorg) and
from the committed blocks in `self.chain` (a bounded recent window). Captured in
`PoawxAdaptiveChainSignals`:

- `dominance_concentration_permille` — max recent reward share across miners, from
  `PersistentDominance::recent_reward_share_permille` (Phase 33 state). Drives Defense
  (concentration) and contributes to Caution.
- `active_role_participation` — count of distinct miners with recent rewards in the
  dominance window (chain-derived role participation). Drives Caution.
- `registered_ticket_count` — number of block-carried ticket registrations
  (`ticket_registrations`) within the recent committed-block window (chain-derived
  "registered ticket participation"). Drives Caution.
- `double_sign_evidence_count` — number of block-carried double-sign evidence entries
  (`double_sign_evidence`) within the recent committed-block window (chain-carried
  consensus evidence). Drives Defense.
- `finality_available` — whether a finality proof is present in the recent committed-block window
  (chain-derived, replayable). Recorded in the metrics digest for completeness; it is **not** a
  transition input in the current rules (the transition uses concentration / evidence / tickets /
  participation only), so it can never alone change the mode.

Why these sources and not the live `ticket_store` / `doublesign_penalty` caches: those
caches are intentionally **stale during the new-branch connect loop of a reorg** (the
existing code rebuilds them only *after* the loop). Reading them at validation time
would make the committed mode depend on transient cache state and break reorg replay.
`self.dominance` is reverted per disconnected block and re-applied per connected block,
so it is always consistent; the bounded scan of `self.chain` is likewise always
consistent. This keeps the adaptive transition correct in cold replay, live connect,
and reorg connect — with **no change to existing phase reorg behavior**.

### 3.2 Non-consensus triggers (operator/simulation only — never affect consensus mode)

- local peer count
- local network latency
- locally-rejected fork sightings
- local mempool conditions
- operator suspicion
- uncommitted gossip
- the legacy `NetworkSignals.recent_invalid_work` / `recent_reorg_signal`

These may appear in `poawx-sim` and in operator docs/telemetry, but are structurally
excluded from the consensus type `PoawxAdaptiveChainSignals` and from the consensus
transition function. A test (`phase34_local_signals_not_consensus`) asserts that the
consensus transition does not take these inputs and that changing them cannot move the
committed mode.

---

## 4. Where mode state is carried / committed

Mirror the proven Phase 33 trailing-optional extension pattern:

- New struct `PoawxAdaptiveCommitmentV1` in `src/poawx_adaptive.rs`.
- Carried as `Phase20ReceiptExt.adaptive_mode_commitment: Option<PoawxAdaptiveCommitmentV1>`.
- Serialized as a trailing **`ADM1`** magic-prefixed, fixed-size section, appended
  after the Phase 33 `DMC1` section. `None` ⇒ **byte-identical** to pre-Phase-34 exts
  (no marker, zero bytes). The existing precommit "0-flag if any trailing section
  present" logic is extended to include `adaptive_mode_commitment`.
- Deserialize adds an `ADM1` arm to the strict trailing-section loop (duplicate ⇒
  reject, unknown magic ⇒ reject — unchanged strictness).

Commitment fields (binds everything needed to verify the transition deterministically):

```
version: u8                       // ADAPTIVE_COMMITMENT_VERSION = 1
network_id: u8                    // must match expected network; mainnet (0) hard-off
block_height: u64                 // == H
pre_mode: u8                      // mode active FOR block H (derived from blocks < H)
post_mode: u8                     // mode committed by block H (active for H+1)
pre_state_digest: [u8;32]         // digest of adaptive state after block H-1
post_state_digest: [u8;32]        // digest of adaptive state after block H
metrics_digest: [u8;32]          // digest over the deterministic chain-derived signals used at H
```

Wire size = `1+1+8+1+1+32+32+32 = 108` bytes; domain separator
`b"IRIUM_POAWX_ADAPTIVE_STATE_V1"` is folded into the state digest.

---

## 5. State, timing, transitions

### 5.1 State

```
struct PoawxAdaptiveState { mode: PoawxAdaptiveMode, recovery_window_remaining: u32 }
```
- `digest()` = SHA256(domain || mode_byte || recovery_window_remaining_le). Stable
  across replay.
- Genesis/initial = `{ Normal, 0 }`.
- Held on `ChainState.adaptive_state` next to `dominance`/`ticket_store`/
  `doublesign_penalty`.

### 5.2 Timing (non-retroactive, replayable)

- **Block H is validated under `pre_mode`** = `self.adaptive_state.mode` (the state
  after H-1, i.e. derived from blocks < H). Stricter mode effects for H key off
  `pre_mode`.
- **Block H carries the commitment** binding `pre_state` (after H-1) and `post_state`
  (after H). `post_state` is computed from `pre_state` and the chain-derived signals as
  of H (dominance after applying H's role rewards — mirroring Phase 33 DMC1 `post` — and
  the recent committed-block window including H).
- **`post_mode` becomes active for H+1** (it is the `pre_mode` of H+1).

### 5.3 Deterministic transition

Fixed **consensus constants** (not per-node env — identical on every node):

- `ADAPTIVE_RECENT_WINDOW: u64 = 16` (blocks scanned for participation/evidence counts)
- `CAUTION_MIN_TICKETS: u32 = 3`
- `CAUTION_MIN_ROLE_PARTICIPATION: u32 = 3`
- `DEFENSE_CONCENTRATION_PERMILLE: u32 = 700` (reused from Phase 21A)
- `DEFENSE_EVIDENCE_COUNT: u32 = 1`
- `RECOVERY_WINDOW: u32 = 4`

```
fn next_state(prior, sig):
    defense = sig.dominance_concentration_permille >= DEFENSE_CONCENTRATION_PERMILLE
              || sig.double_sign_evidence_count >= DEFENSE_EVIDENCE_COUNT
    if defense:
        return { Defense, RECOVERY_WINDOW }
    if prior.mode == Defense:                 # first clean block after Defense
        return { Recovery, RECOVERY_WINDOW }
    if prior.mode == Recovery:
        rem = prior.recovery_window_remaining.saturating_sub(1)
        if rem > 0: return { Recovery, rem }  # still recovering
        # window elapsed -> fall through to base
    # base mode
    low = sig.registered_ticket_count < CAUTION_MIN_TICKETS
          || sig.active_role_participation < CAUTION_MIN_ROLE_PARTICIPATION
    return if low { { Caution, 0 } } else { { Normal, 0 } }
```

Determinism note: the concentration signal inherits the Phase 21C/33 requirement that
`IRIUM_POAWX_ANTI_DOMINATION_WINDOW`/`_LOOKBACK` are set identically across nodes (they
already feed the committed DMC1 digest). Adaptive thresholds/windows above are
hard-coded constants, so given the same chain every node computes the same mode.

---

## 6. Per-mode validation effects (additive, gated, never weakening)

Effects only **add** strictness; they never remove or relax an existing check, and only
apply when the relevant underlying gate is **active** (so they cannot fabricate
enforcement where the infrastructure is absent). Driven by `pre_mode` for block H.

- **Normal** — no extra requirement.
- **Caution** —
  - if `dominance_commitment_active(H)`: require the block to carry a `DMC1` commitment
    (correctness already validated by Phase 33's own check).
  - if `ticket_store_active(H)`: require ticket eligibility (run the existing Phase 32
    `validate_block_ticket_store_eligibility`, even if `ticket_store_required` is off).
- **Defense** — Caution effects, plus:
  - if `committed_admission_active(H)`: require the block to carry the `CAC1`
    committed-admission (correctness validated by phase22a, unchanged).
  - if `finality_committee_active(H)`: run the existing `validate_block_finality`, which
    requires a valid finality proof **and already rejects suspended/penalized signers**
    (Phase 30). This delivers "reject finality proofs containing suspended signers" and
    "finalized-checkpoint protection" with no new finality logic.
- **Recovery** — identical to Defense for the deterministic recovery window.

Anything not safely wireable here is documented as operator-recommendation / future
work (see §9), not faked.

No effect touches LWMA, PoW target, SHA-256d anchor work, the base reward, or mainnet.

---

## 7. Reorg & replay behavior

- `adaptive_state` lives on `ChainState`. **Cold replay** (`rebuild_to_tip`) connects
  from genesis via `connect_block`, so it reconstructs `adaptive_state` for free.
- **Reorg** (`reorg_to_tip`): snapshot `adaptive_state` before mutating; after the
  disconnect-to-ancestor loop call `rebuild_adaptive_state_from_chain()` so the
  new-branch connect loop sees the correct ancestor `pre_state`; on a failed reorg
  restore the snapshot; on success rebuild from the new active chain (same shape as the
  Phase 30/32 rebuilds). `rebuild_adaptive_state_from_chain` re-derives the state by a
  fresh deterministic replay over `self.chain` (reconstructing dominance with
  `from_env()` so the concentration signal matches connect-time exactly).
- The single helper `compute_adaptive_post_state(prior, signals)` is used by both
  `connect_block` and the rebuild, so the two paths cannot diverge.
- Abandoned-fork modes never pollute the active chain (rebuild is from the active chain
  only). Mode transitions are deterministic across nodes (fixed constants + chain-only
  inputs).

---

## 8. Gates (env; mainnet hard-off; off by default ⇒ zero regression)

- `IRIUM_POAWX_ADAPTIVE_MODE_ACTIVATION_HEIGHT` — existing; activates derivation +
  commitment validation at/after a height (mainnet `network_id==0` → always off).
- `IRIUM_POAWX_ADAPTIVE_COMMITMENT_REQUIRED` — new; when `1`, a block at/after
  activation must carry an `ADM1` commitment (otherwise validated-only-if-present).
  Mainnet hard-off.

`adaptive_commitment_enforced(H) = adaptive_mode_active(H) && adaptive_commitment_required()`.

---

## 9. Out of scope / future work

- Confirmation-multiplier / "stricter_verification" knobs from the legacy
  `AdaptivePolicy` remain operator/simulation hints, not consensus.
- Mode-driven dynamic reward changes — out of scope (would touch reward consensus).
- Mode-driven LWMA/PoW/target changes — explicitly forbidden, never done.
- Any trigger needing local-only data (peer count, rejected forks, mempool, clock) —
  operator guidance only.
- Public testnet launch, live nodes, mainnet — not in this phase.

---

## 10. Tests to add (lib + sim)

`phase34_normal_mode_stays_normal`, `phase34_low_ticket_count_enters_caution`,
`phase34_double_sign_penalty_enters_defense`, `phase34_dominance_concentration_enters_defense`,
`phase34_recovery_exits_after_clean_window`, `phase34_invalid_adaptive_commitment_rejected`
(wrong pre/post mode, wrong digest, invalid transition), `phase34_missing_commitment_rejected_only_when_enforced`,
`phase34_mode_effects_enforced`, `phase34_local_signals_not_consensus`,
`phase34_reorg_restores_adaptive_state`, `phase34_adaptive_state_replays_from_blocks`,
`phase34_mainnet_no_op`, plus `Phase20ReceiptExt` ADM1 round-trip / byte-identity-when-None,
and a deterministic `poawx-sim` adaptive-modes scenario test. Regression: full lib suite +
Phase 26/28/29/30/31/32/33 focused suites stay green.
