# PoAW-X Phase 28 — Finalized-Checkpoint Reorg Rejection: Design

Design for the most important deferred Phase 27 consensus gap (item 5A): once a PoAW-X block is
finalized, the node must reject any reorg that would replace/disconnect it. **Testnet/devnet only.
Mainnet hard-off (`network_id == 0`). NOT audited / production-ready / mainnet-ready.** Branch
`testnet/poawx-phase28-finalized-reorg-rejection` (from `40db1aa`).

## Existing finality state (audited)

- A block at height `H` carries, in each PoAW-X receipt's `Phase20ReceiptExt.finality_proof`, a
  `FinalityProofV1` that finalizes the block's **parent** (`block_hash = block.header.prev_hash`, the
  block at `H-1`). Validated by `ChainState::validate_block_finality` (`src/chain.rs:1046`), called from
  `connect_block` (`:867`) **only when** `poawx_finality::finality_committee_enforced(height)` is true
  (testnet/devnet gated; mainnet hard-off via `network_id == 0`).
- Validation is fail-closed: missing/below-threshold/wrong-committee/wrong-threshold proofs make
  `connect_block` reject the block. So a block connects with finality enforced **only** if its proof is
  valid.
- **There is no persisted or in-memory "finalized checkpoint" today.** Nothing records the highest
  finalized `(height, hash)`, and the reorg path does not consult finality. This is the gap.

## Existing reorg / chain-selection path (audited)

- `ChainState::process_block` (`src/chain.rs:2265`) is the entry. When a stored fork has strictly more
  cumulative work than the active tip (`cumulative > self.total_work`, `:2344`) it calls
  `reorg_to_tip(hash)` (`:2345`).
- `reorg_to_tip` (`:1545`): computes the fork point via `find_reorg_path` → `ancestor_height`; if
  `ancestor_height >= current_tip_height` it no-ops; otherwise it **disconnects** every block above
  `ancestor_height` (via `disconnect_tip_block`) and **connects** the new branch.
- `disconnect_tip_block` (`:924`) is called **only** inside `reorg_to_tip` and its rollback (verified:
  no other callers). So `reorg_to_tip` is the single chokepoint where finalized history could be
  removed.
- `rebuild_to_tip` (`:2205`) exists but has **no callers** (dead path); it replays from genesis via
  `connect_block`, so it reconstructs derived state anyway.
- Cold replay at startup: `load_persisted_blocks` (`:3106`) replays persisted blocks through
  `state.connect_block(...)` (`:3277`). So any state derived inside `connect_block` is rebuilt on
  restart with no extra work.

## Where the protection is enforced

A reorg disconnects exactly the blocks with height in `(ancestor_height, current_tip_height]`. A
finalized block at height `F` is therefore disconnected **iff `F > ancestor_height`**, i.e.
`ancestor_height < F`. Since the new branch diverges from the main chain at `ancestor_height < F`, it
cannot contain the finalized hash `X` at `F` (it has a competing block there). Conversely, if
`ancestor_height >= F`, every height `<= ancestor_height` (including `F`) is shared with the main chain,
so `X` at `F` is preserved.

**Single, deterministic guard in `reorg_to_tip`, before any disconnect:**

```
if poawx_finalized_height > 0 && ancestor_height < poawx_finalized_height {
    return Err("phase28: reorg would disconnect finalized checkpoint at height F");
}
```

## Finalized checkpoint state — derived, not newly persisted

Add two in-memory `ChainState` fields (mirroring how `dominance` is held and rebuilt by replay):

- `poawx_finalized_height: u64` (0 = none)
- `poawx_finalized_hash: [u8; 32]` (zeros = none)

Set inside `connect_block`, **after** `validate_block_finality` passes, under the same enforcement gate:

```
if finality_committee_enforced(expected_height) {
    self.validate_block_finality(&block, expected_height)?;
    if expected_height >= 1 {
        self.advance_finalized(expected_height - 1, block.header.prev_hash);
    }
}
```

`advance_finalized(h, hash)` is **monotonic** — it updates only if `h > poawx_finalized_height` (rule 4:
never backward). Because the checkpoint is derived inside `connect_block`, **cold replay and
`rebuild_to_tip` reconstruct it automatically** (rules 6/7) — no new wire format, no new storage file,
no `/tmp`/`.irium` usage.

### Reorg-failure rollback safety

During a reorg, new-branch `connect_block` calls may advance the checkpoint. If the reorg then fails and
rolls back (reconnecting old blocks), the monotonic setter would leave the checkpoint stuck at the
new-branch value (pointing to a hash no longer on chain). Therefore `reorg_to_tip` **snapshots**
`(poawx_finalized_height, poawx_finalized_hash)` at entry and **restores** the snapshot on the failure
path (after the rollback reconnects). On success the checkpoint reflects the new active chain.

## Exact invariant implemented

> If a finalized checkpoint exists at height `F` with hash `X`, any reorg whose fork point is below `F`
> (and therefore would replace `X`) is rejected — even if the competing fork has more work or is longer.
> A fork that shares `X` at `F` and diverges strictly after `F` is evaluated under normal chain rules.
> A pure extension of the finalized chain is allowed. The checkpoint only advances (never backward) and
> is set only by a finality proof that passed `validate_block_finality`. If no finalized checkpoint
> exists (`poawx_finalized_height == 0`, incl. all of mainnet), reorg behavior is unchanged.

## Mainnet safety

`finality_committee_enforced` returns false for `network_id == 0`, so on mainnet the checkpoint stays
`0`/zeros and the guard (`poawx_finalized_height > 0 && ...`) is a no-op. No change to LWMA, PoW target,
block reward, SHA-256d anchors, or any mainnet consensus. phase21d/21e/22a untouched. The anchor-
checkpoint mechanism (`AnchorManager`, `:2327`) is a separate, pre-existing system and is not modified.

## Tests to add (`phase28_*` in `src/chain.rs`)

1. `phase28_no_finalized_checkpoint_preserves_existing_reorg` — no finality ⇒ existing reorg unchanged.
2. `phase28_rejects_reorg_replacing_finalized_checkpoint` — finalize `F`; a heavier fork replacing `F`
   is rejected.
3. `phase28_allows_fork_after_finalized_checkpoint` — fork sharing `F`, diverging at `F+1`, follows
   normal rules.
4. `phase28_extension_after_finalized_checkpoint_allowed` — extension connects normally.
5. `phase28_invalid_finality_does_not_lock_chain` — invalid/below-threshold finality sets no checkpoint.
6. `phase28_finalized_checkpoint_monotonic_no_backward` — checkpoint never decreases.
7. `phase28_finalized_checkpoint_survives_replay` — `rebuild_to_tip`/replay reconstructs the checkpoint
   and still rejects a conflicting reorg.
8. mainnet/`network_id == 0` does not activate the protection (covered by gate + a focused assert).
9. Regression: phase26/phase27/finality suites still pass.

## Safety boundaries / what this does NOT do

- Does **not** wire double-sign detection into penalties (separate deferred item 5B — remains open).
- Does **not** change how finality proofs are validated, the threshold, or committee selection.
- Does **not** add persistence/wire formats; the checkpoint is derived from blocks.
- Does **not** let invalid finality lock the chain (checkpoint set only after valid proof; invalid proof
  ⇒ block rejected ⇒ no checkpoint).
- Does **not** touch mainnet, LWMA, PoW, reward, anchors, or phase21d/21e/22a.

## Smallest-safe-design conclusion

The architecture supports this cleanly with: 2 new in-memory fields, a monotonic setter, ~3 lines in
`connect_block`, and a guard + snapshot/restore in `reorg_to_tip`. No broad redesign is required.
