# PoAW-X Phase 28 — Draft Note (development only — not a release)

> **Draft / development only.** No git tag, no GitHub release, no binaries. **Testnet/devnet only.
> Mainnet hard-off (`network_id == 0`). NOT production-ready / mainnet-ready / audited.** No public
> testnet launch.

Branch: `testnet/poawx-phase28-finalized-reorg-rejection` (from `40db1aa`). `origin/main` unchanged
(`19c496dc5f2fa08981a109b10eeb257105c28c43`).

## What changed

- **Finalized-checkpoint reorg rejection** (closes deferred Phase 27 item 5A): once a PoAW-X block is
  finalized by a validated finality proof, the node rejects any reorg that would replace/disconnect it —
  even a higher-work or longer fork. A fork that diverges strictly after the finalized height still
  follows normal chain rules. The checkpoint is derived inside `connect_block` (so cold replay/rebuild
  reconstruct it), advances monotonically, and is enforced at the single reorg chokepoint
  (`reorg_to_tip`). Mainnet stays hard-off (no checkpoint, guard is a no-op).
- **Simulation:** `poawx-sim` `finality_attack` and `reorg` scenarios now model and report
  finalized-reorg rejection.

## Unchanged / safety

- No change to LWMA, PoW target, block reward, SHA-256d anchors, or any mainnet consensus.
- phase21d/21e/22a untouched; finality validation/threshold/committee selection unchanged; the
  pre-existing `AnchorManager` checkpoint mechanism is not modified.

## Still deferred

- Double-sign → penalty wiring (Phase 27 item 5B) and items 1D/2E/3C/6F remain open.

## Tests

- `phase28_*`: 8/0. Full lib suite: 756/0. `poawx-sim` bin: 11/0. Release builds: OK.

_Development only. Not a release. Not audited / production-ready / mainnet-ready._
