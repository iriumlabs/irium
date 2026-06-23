# PoAW-X Phase 34 — Adaptive-Modes Consensus Integration

Status: **testnet/devnet only — mainnet hard-off — off by default**.
Production-ready: **no**. Mainnet-ready: **no**. Audited: **no**.

Closes deferred Phase 27 item **6F** (adaptive modes: consensus/node integration). See the design in
`docs/poaw-x-phase34-adaptive-consensus-integration-design.md`.

Branch: `testnet/poawx-phase34-adaptive-modes-consensus-integration` (no PR/merge/tag/release).

---

## What this adds

A deterministic, replayable, reorg-safe PoAW-X **adaptive security mode** (`Normal` / `Caution` /
`Defense` / `Recovery`) that is part of consensus validation when enabled — derived ONLY from
chain-derived state, committed in every block, and used to turn on (never off) stricter validation built
from the already-shipped Phase 28/30/32/33 systems.

It does **not** change PoW, LWMA-144, the SHA-256d anchor rules, the base block reward, or mainnet, and
it does **not** weaken phase21d/21e/22a or Phase 30 (double-sign penalties) / Phase 31 (reward
caps/fallback) / Phase 32 (ticket store) / Phase 33 (dominance commitment).

## Where the commitment is carried

`Phase20ReceiptExt.adaptive_mode_commitment: Option<PoawxAdaptiveCommitmentV1>` — a trailing-optional
**`ADM1`** section (fixed 108 bytes), appended after the Phase 33 `DMC1` section. `None` is byte-identical
to pre-Phase-34 receipts (no marker emitted). It is folded into the receipt digest / irx1 root, so a
present commitment is tamper-evident. The commitment binds:

`version, network_id, block_height, pre_mode, post_mode, pre_state_digest, post_state_digest,
metrics_digest`.

## Mode transition (deterministic, chain-derived only)

State = `{ mode, recovery_window_remaining }`, advanced per block by `PoawxAdaptiveState::next(signals)`:

- **Defense** if `dominance_concentration_permille >= 700` (Phase 33 state) **or**
  `recent block-carried double-sign evidence >= 1` (Phase 30 evidence).
- Leaving Defense enters **Recovery** for a deterministic window (`RECOVERY_WINDOW = 4` blocks); relapse
  to Defense on renewed instability.
- After the recovery window, or with no instability: **Caution** if recent registered-ticket count `< 3`
  or recent distinct rewarded-miner participation `< 3`; otherwise **Normal**.

Constants (`ADAPTIVE_RECENT_WINDOW=16`, `CAUTION_MIN_TICKETS=3`,
`CAUTION_MIN_ROLE_PARTICIPATION=3`, `DEFENSE_EVIDENCE_COUNT=1`, `DEFENSE_CONCENTRATION_PERMILLE=700`,
`RECOVERY_WINDOW=4`) are fixed consensus constants — identical on every node — so a given chain yields
the same mode everywhere. Only the activation height + required flag are env-gated.

## Timing (non-retroactive)

- Block H is validated under the **pre-mode** = the adaptive state derived from blocks `< H`.
- Block H carries the commitment binding `pre` (after H-1) and `post` (after H, signals include H).
- `post_mode` becomes the pre-mode for **H+1**.

## Mode effects (additive, gated — never weakening)

Driven by the pre-mode for block H, only when the relevant underlying gate is already active:

- **Normal:** existing PoAW-X validation only.
- **Caution:** require the block to carry the Phase 33 dominance commitment (if active) and pass Phase 32
  ticket eligibility (if active) — even when those gates' own `*_REQUIRED` flags are off.
- **Defense / Recovery:** Caution effects + require the Phase 22A committed admission (if active) + run
  the Phase 28 finality validator (if active), which already rejects suspended/penalized signers
  (Phase 30) — delivering "reject finality proofs containing suspended signers" and finalized-checkpoint
  protection with no new finality logic.

## Local-only signals excluded from consensus

The consensus signal type (`PoawxAdaptiveChainSignals`) has **no field** for local peer count, locally
rejected forks, mempool contents, node clock drift, local network conditions, or uncommitted gossip — so
they cannot affect the consensus mode. The legacy `assess()` / `NetworkSignals` primitive (which does
have local fields like `recent_invalid_work` / `recent_reorg_signal`) is retained for the off-chain
`poawx-sim` and operator reporting **only**. Test `phase34_local_signals_not_consensus` demonstrates a
local reorg sighting flips the legacy primitive to Defense but cannot move the consensus mode.

## Reorg / replay

- Cold replay (`rebuild_to_tip`) reconstructs the adaptive state via `connect_block` from genesis.
- `reorg_to_tip` snapshots the adaptive state, rebuilds it to the common ancestor before connecting the
  new branch (so each new block's ADM1 validates against the correct pre-state), restores the snapshot
  on a failed reorg, and rebuilds it from the new active chain on success — the same shape as the Phase
  30/32 rebuilds. Abandoned-fork modes never pollute the active chain.
- `rebuild_adaptive_state_from_chain` and `connect_block` share the same signal/transition helpers, so
  the two paths cannot diverge.

## Gates (env; mainnet hard-off; off by default)

- `IRIUM_POAWX_ADAPTIVE_MODE_ACTIVATION_HEIGHT` — activate derivation + commitment validation.
- `IRIUM_POAWX_ADAPTIVE_COMMITMENT_REQUIRED=1` — require an ADM1 commitment on every block (else
  validated-only-if-present).

Mainnet (`network_id == 0`) is hard-off for both; with neither set there is zero behavior change.

## Tests

- Library (`phase34_*`, 17 tests): transitions (Normal/Caution/Defense/Recovery + relapse + window
  exit), invalid commitment (wrong pre/post mode, wrong state/metrics digest, wrong height/network,
  invalid transition), missing-commitment-rejected-only-when-enforced, mode effects enforced,
  local-signals-not-consensus, reorg restore/rebuild, replay-from-blocks, mainnet no-op, wire round-trip,
  byte-identity when absent.
- Simulator (`poawx-sim`): new `adaptive_modes` scenario reporting `adaptive_mode_pre/post`,
  `adaptive_trigger`, `active_ticket_count`, `dominance_concentration`, `penalty_count`,
  `recovery_window_remaining`, `mode_commitment_valid` over a Normal→Caution→Defense→Recovery→Normal
  lifecycle, plus a deterministic test.
- Regression: full lib suite green (822/0); Phase 26/28/29/30/31/32/33 focused suites green; sim suite
  green (17/0); release build of `iriumd` + `poawx-live-proof-harness` + `poawx-sim` OK.

## Out of scope / not done

- No live nodes, no public testnet, no mainnet, no firewall/sudo/wallet/key access.
- Confirmation-multiplier / generic "stricter verification" knobs remain operator/simulation hints, not
  consensus.
- Independent audit, live multi-machine validation, deep-scale sync — still open (carried from prior
  phases). **Not audited, not production-ready, not mainnet-ready.**
