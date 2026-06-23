# PoAW-X Phase 26 Draft Changelog

> **Draft only — not a release.** No git tag, no GitHub release, no binaries. **NOT production-ready /
> mainnet-ready / audited.** Mainnet hard-off (`network_id == 0`); no public testnet launched.

Scope: branch `testnet/poawx-phase20-blueprint-completion-local`, source range `30bce64..0208368`
(8 source files, +1006/−47), docs through HEAD `93fd8f3`. `origin/main` unchanged
(`19c496dc5f2fa08981a109b10eeb257105c28c43`).

> **Superseded scope note (Phase 35):** this changelog covers Phase 26 only. The later consensus
> features (Phases 28–34: finalized-checkpoint reorg rejection, block-carried double-sign evidence +
> penalty exclusion, reward manifest caps/fallback, on-chain ticket store, dominance-state commitment,
> adaptive-mode integration) are summarized in `docs/poaw-x-phase35-final-closeout.md` and the per-phase
> draft notes under `docs/release-notes/poaw-x-phase{28..33}-draft-note.md`. Still draft-only; not
> production-ready / mainnet-ready / audited.

## Consensus / gate semantics

- **Changed (26B, `081a1bd`):** candidate-set gate (phase21d) now expects the **epoch seed**
  (`admission_epoch_seed` = grandparent hash; genesis at the activation boundary) instead of the
  immediate parent hash; the phase21e admitted-set lookup is keyed on the same epoch seed. This
  reconciles phase21d/21e with phase22a so multi-block all-gates chains are satisfiable.
- **Unchanged:** phase22a (`validate_block_committed_admission`) — byte-identical; the phase21e
  equality check (`cs.serialize() != admitted.serialize()`); phase21c/21f/21h/22d gates; PoW/LWMA/
  difficulty/target/reward/`constants.rs`.

## Candidate admissions

- **Added (26B, `081a1bd`):** pure helper `admission_epoch_seed(parent_prev_hash, block_prev_hash)` in
  `src/poawx_committed_admission.rs` (purely additive; `AdmissionCommitmentV1` unchanged).
- **Added (26D, `de13a83`):** durable persistence of validated candidate admissions to an isolated
  data-root file (`candidate_admissions_file()` in `src/storage.rs`), with atomic write; startup
  reload + **re-validation** (`reload_persisted_bytes` / `load_persisted` in `src/poawx_admission.rs`)
  before persisted-block replay (`src/bin/iriumd.rs`). Wrong-network / corrupt / tampered records are
  skipped, never panicked on.

## P2P / sync

- **Added (26E, `9de939f`):** `send_historical_admissions(...)` in `src/p2p.rs` — when serving block
  bodies during sync, a node also sends the matching admissions, **bounded to `16 × served_block_count`**
  and only on block-serve responses. Wired into the 4 block-serve sites (2 GetBlocks handlers + 2
  handshake-push paths). The receiver re-validates each admission via the normal `ingest_bytes` path.
  Purely additive (getblocks gating/locator untouched). No-op on mainnet (no admissions).

## Harness and tests

- **Changed (26B, `081a1bd`):** devnet/test block builder `build_devnet_all_gates_block` gained a
  `parent_prev_hash` parameter and seeds candidate set/admissions/AVR2 with the epoch seed (puzzle/
  finality keep `prev_hash`); dominance replay via `dom_at(...)`. The live-proof harness fetches the
  parent's `prev_hash`. **Builders are mainnet-hard-off and are NOT validators.**
- **Added tests:** `phase26b_multiblock_epoch_seed_soak`, `phase26b_stale_immediate_parent_seed_rejected`,
  `phase26b_committed_admission_root_and_replay_rejected`, `phase26d_cold_replay_with_persisted_admissions`,
  `phase26d_persist_reload_roundtrip`, `phase26d_reload_rejects_invalid_records`,
  `phase26e_fresh_sync_via_served_admissions`. Full lib suite: **748 passed / 0 failed**
  (`--test-threads=1`).

## Live validation

- **26C (`bfe16fd`):** three-system (Windows + VPS-1 + VPS-2) 6-block all-gates soak; all nodes at the
  same height/tip/irx1; spoke-originated block included.
- **26D (`abb2fd3`):** restart/keep-storage cold replay — node reloaded persisted admissions and
  rebuilt the chain to height 6 from disk; H7 propagated.
- **26E (`0208368`):** fully-wiped fresh node received served historical admissions and synced the
  6-block chain from scratch (~45 s), matching tip/irx1; H7 received live.
- Mainnet/prod + production pool alive and untouched throughout; isolated storage; no firewall change.

## Audit and readiness docs

- **26F (`c15c436`):** independent-audit package (`docs/audit/poawx-phase26-*`).
- **26G (`972bb9c`):** public-testnet readiness package (`docs/poaw-x-phase26g-public-testnet-*`).
- **26H (`1217c85`):** audit kickoff package (`docs/audit/phase26h-kickoff/`).
- **26I (`22dfde8`):** internal self-review (`docs/audit/phase26i-self-review/`) — not an audit.
- **26J (`0e196ba`):** external auditor handoff (`docs/audit/phase26j-external-handoff/`).
- **26K (`6c7681a`):** remediation workflow (`docs/audit/phase26k-remediation-workflow/`).
- **26L (`208d5ff`):** engagement tracker (`docs/audit/phase26l-engagement-tracker/`).
- **26M (`93fd8f3`):** program summary / index / commit map / next-decision tracker
  (`docs/poaw-x-phase26-*`).
- **26N (this):** draft release notes + draft changelog (`docs/release-notes/`).

## Non-goals / unchanged areas

- No mainnet enablement, real-value rewards, governance, or mainnet activation.
- No public-testnet launch.
- No git tag, GitHub release, or binary artifacts.
- phase22a, phase21e equality, PoW/LWMA/difficulty/target/reward, and mainnet hard-off all unchanged.
- No `main` change; `origin/main` unchanged throughout Phase 26.
