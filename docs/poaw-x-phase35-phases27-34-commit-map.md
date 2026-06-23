# PoAW-X Phases 27–34 — Commit Map

All commits below are **verified against the actual remote refs on `origin`** (via
`git ls-remote origin refs/heads/<branch>`) at Phase 35 authoring time. The track is a **linear chain**:
`40db1aa → 199ed24 → df0cc92 → 7e5f805 → fae91bb → 8f2a64d → 1a032de → 78d5ca3`.

`origin/main` is **unchanged** at `19c496dc5f2fa08981a109b10eeb257105c28c43` and was never touched by any
of these phases. All branches are pushed to `origin`. No PRs, merges, tags, releases, or force pushes.

Diffstats below are **incremental** (each phase vs. the previous phase's HEAD), except Phase 27 (see
note). Test counts are the **full-lib-suite** totals reported in each phase's own doc, plus the phase's
focused `phaseNN_*` count and the `poawx-sim` bin total.

| Phase | Branch (`testnet/poawx-…`) | Start | End (HEAD) | Commits | Files / lines (incremental) | Main feature | `phaseNN_*` / full lib / sim |
|---|---|---|---|---|---|---|---|
| 27 | `phase27-full-blueprint-implementation` | pre-27 testnet line | `40db1aa` | (consolidation) | large (full blueprint + simulator; see note) | Full-blueprint consolidation + `poawx-sim`; gap audit deferring 6 consensus items | baseline full lib **748/0**; sim **10** |
| 28 | `phase28-finalized-reorg-rejection` | `40db1aa` | `199ed24` | 4 | 6 files, +736/−14 | Finalized-checkpoint state + reorg-below-finalized rejection | **8** / **756** / **11** |
| 29 | `phase29-double-sign-penalties` | `199ed24` | `df0cc92` | 4 | 7 files, +939/−7 | Double-sign evidence + replayable penalty state (primitive) | **12** / **768** / **12** |
| 30 | `phase30-block-carried-doublesign-evidence` | `df0cc92` | `7e5f805` | 4 | 11 files, +1006/−12 | Block-carried `DSE1` evidence; consensus enforcement (finality exclusion) | **7** / **775** / **13** |
| 31 | `phase31-reward-manifest-wrapper-cap-fallback` | `7e5f805` | `fae91bb` | 4 | 8 files, +1041/−8 | Reward manifest wrapper + per-role caps + low-participation fallback | **9** / **784** / **14** |
| 32 | `phase32-onchain-ticket-store` | `fae91bb` | `8f2a64d` | 5 | 11 files, +1251/−10 | On-chain ticket store (`TKT1`) + epoch rate-limit + expiry | **12** / **796** / **15** |
| 33 | `phase33-dominance-state-commitment` | `8f2a64d` | `1a032de` | 5 | 11 files, +798/−8 | Block-carried `DMC1` dominance-state commitment | **9** / **805** / **16** |
| 34 | `phase34-adaptive-modes-consensus-integration` | `1a032de` | `78d5ca3` | 5 | 11 files, +1801/−28 | Adaptive-mode (`ADM1`) consensus integration; chain-derived only | **17** / **822** / **17** |

**Push status:** all eight branches are present on `origin` at the HEADs above (verified). Phase 34 was
pushed via interactive GitHub Credential Manager auth (Windows); earlier phases per their own docs.

## Notes

- **Phase 27 diffstat.** The `phase27` branch is a long-running consolidation of the entire PoAW-X
  blueprint line (it carries phases ~20–27), so its diff vs. `origin/main` is large (~259 files) and is
  **not** representative of "Phase 27 work alone." It is the base of the linear 28→34 chain. Phases
  28–34 are the small, auditable increments shown above.
- **Test totals are cumulative** (each phase's full-lib total includes all prior phases' tests). The
  per-phase `phaseNN_*` column is the focused count added by that phase. Phase 30's focused count (7) is
  lower than Phase 29's (12) because Phase 29 added the primitive's unit tests and Phase 30 added the
  consensus-path tests on top.
- **Wire-format additions** are all trailing-optional block sections (`None` ⇒ byte-identical to the
  prior format): `DSE1` (Phase 30), `TKT1` (Phase 32), `DMC1` (Phase 33), `ADM1` (Phase 34).
- **No source changes in Phase 35** — this is a docs-only consolidation branch
  (`phase35-final-closeout-audit-consolidation`).
