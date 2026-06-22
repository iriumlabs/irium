# PoAW-X Phase 28 — Finalized-Checkpoint Reorg Rejection (Implemented)

Closes deferred Phase 27 item **5A**: once a PoAW-X block is finalized, the node rejects any reorg that
would replace/disconnect it. **Testnet/devnet only. Mainnet hard-off (`network_id == 0`). NOT audited /
production-ready / mainnet-ready.** Branch `testnet/poawx-phase28-finalized-reorg-rejection` (from
`40db1aa`).

## Invariant implemented

> If a finalized checkpoint exists at height `F` with hash `X`, any reorg whose common-ancestor (fork)
> height is below `F` — i.e. any reorg that would replace `X` — is rejected, **even if the competing
> fork has more work or is longer**. A fork that shares `X` at `F` and diverges strictly after `F` is
> evaluated under normal chain rules. A pure extension of the finalized chain is allowed. The
> checkpoint only advances (never backward) and is set **only** by a finality proof that passed
> `validate_block_finality`. With no checkpoint (`poawx_finalized_height == 0`, which includes all of
> mainnet), reorg behavior is unchanged.

Decision rule (pure, unit-tested): `reorg_violates_finalized(F, ancestor) = F > 0 && ancestor < F`.

## How it works

- **State (derived, not newly persisted):** `ChainState` gains `poawx_finalized_height: u64` and
  `poawx_finalized_hash: [u8; 32]` (in-memory; `0`/zeros = none).
- **Setting:** in `connect_block`, after `validate_block_finality` passes (gate on), the validated proof
  finalizes the block's parent (`expected_height - 1`, `prev_hash`). The checkpoint is advanced
  **monotonically** (`advance_finalized`) once the block is committed. Because it is derived inside
  `connect_block`, **cold replay (`load_persisted_blocks`) and `rebuild_to_tip` reconstruct it** — no
  new wire format, no new storage file, no `/tmp`/`.irium`.
- **Enforcement:** in `reorg_to_tip`, after computing the fork point `ancestor_height` and before any
  disconnect, the guard rejects the reorg when `reorg_violates_finalized(...)` is true (deterministic,
  consensus-level `Err`). `reorg_to_tip` is the single chokepoint — `disconnect_tip_block` has no other
  callers.
- **Rollback safety:** `reorg_to_tip` snapshots the finalized state on entry and restores it if the
  reorg fails mid-way (so a partially-applied new branch can't leave the checkpoint pointing off-chain).

## Files changed

- `src/chain.rs` — 2 `ChainState` fields + both initializers; `advance_finalized` (monotonic) +
  `reorg_violates_finalized` (pure); checkpoint advance in `connect_block` (captured after validation,
  applied after commit to respect borrows); guard + snapshot/restore in `reorg_to_tip`; 8 `phase28_*`
  tests.
- `src/bin/poawx-sim.rs` — `finality_attack` and `reorg` scenarios now model finalized-reorg rejection
  (`reorg_below_finalized_rejected`) and report it; +1 test.

## Tests

`cargo test --lib phase28 -- --test-threads=1` → **8 passed / 0 failed**:

- `phase28_finalized_checkpoint_set_by_valid_finality` — valid all-gates chain advances the checkpoint
  to the tip's parent.
- `phase28_rejects_reorg_replacing_finalized_checkpoint` — reorg below `F` rejected (`phase28` error);
  chain + checkpoint unchanged.
- `phase28_allows_fork_after_finalized_checkpoint` — fork sharing `F`, diverging after, not blocked by
  the guard.
- `phase28_no_finalized_checkpoint_preserves_existing_reorg` — no checkpoint ⇒ guard inactive.
- `phase28_reorg_violates_finalized_pure_boundary` — exhaustive boundary of the pure rule.
- `phase28_finalized_checkpoint_monotonic_no_backward` — checkpoint never decreases.
- `phase28_invalid_finality_does_not_lock_chain` — tampered finality is rejected and advances no
  checkpoint.
- `phase28_finalized_checkpoint_survives_replay` — replaying the blocks into a fresh state reconstructs
  the checkpoint and still rejects a conflicting reorg.

Regression: full lib suite **756 passed / 0 failed** (was 748; +8). `poawx-sim` bin **11/0** (+1).
Release builds of `iriumd`, `poawx-live-proof-harness`, `poawx-sim` all succeed.

## Answers to the spec's questions

- **Finalized reorg replacement rejected?** Yes — `reorg_to_tip` returns a `phase28` error before any
  disconnect; even a higher-work fork is rejected.
- **Fork after finalized still allowed?** Yes — `ancestor_height >= F` passes the guard and follows
  normal chain rules.
- **Cold replay / restart protection covered?** Yes — the checkpoint is derived in `connect_block`, so
  `load_persisted_blocks` and `rebuild_to_tip` reconstruct it; the replay test proves a reconstructed
  checkpoint still rejects a conflicting reorg.

## Safety boundaries

- No change to LWMA, PoW target, block reward, SHA-256d anchors, or any mainnet consensus.
- phase21d/21e/22a untouched; finality validation, threshold, and committee selection unchanged.
- The separate pre-existing `AnchorManager` checkpoint mechanism is not modified.
- Mainnet stays hard-off: the finality gate is off for `network_id == 0`, so the checkpoint stays
  `0`/zeros and the guard is a no-op.

## Still deferred (not in this phase)

- **5B — double-sign → penalty wiring:** conflicting finality votes are detected at the gossip layer but
  are still **not** recorded into `PenaltyRecord`/eligibility. Remains open (see
  `docs/poaw-x-phase27-known-limitations.md`).
- Items 1D, 2E, 3C, 6F from Phase 27 remain deferred.

**Production-ready: no. Mainnet-ready: no. Audited: no.**
