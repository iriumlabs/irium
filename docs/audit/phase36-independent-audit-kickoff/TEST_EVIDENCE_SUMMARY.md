# Test Evidence Summary — PoAW-X Phases 28–34

**Reported results from the project's own runs. Auditors should re-run independently** (see
`REPRO_COMMANDS.md`) — these numbers are evidence, not proof, and not an audit.

Test totals are **cumulative** (each phase's full-lib total includes all prior phases). The focused
`phaseNN_*` column is the count added by that phase. `poawx-sim` is the off-chain simulator bin.

| Phase | Focused `phaseNN_*` | Full lib suite | `poawx-sim` bin |
|---|---|---|---|
| (27 baseline) | — | 748 / 0 | 10 |
| 28 | 8 / 0 | 756 / 0 | 11 |
| 29 | 12 / 0 | 768 / 0 | 12 |
| 30 | 7 / 0 | 775 / 0 | 13 |
| 31 | 9 / 0 | 784 / 0 | 14 |
| 32 | 12 / 0 | 796 / 0 | 15 |
| 33 | 9 / 0 | 805 / 0 | 16 |
| 34 | 17 / 0 | **822 / 0** | **17** |

Focused suites at the Phase 34 head also reported green: `adaptive` 20/0, `dominance` 22/0, `ticket`
22/0, `reward` 18/0, `finality` 14/0 (and the phaseNN_* above). Release builds of `iriumd`,
`poawx-live-proof-harness`, and `poawx-sim` completed.

## Notes

- **Cumulative growth:** 748 → 756 → 768 → 775 → 784 → 796 → 805 → 822 (no regressions reported; 0
  failures at every phase).
- **Phase 30's focused count (7) < Phase 29's (12):** Phase 29 added the primitive's unit tests; Phase
  30 added the consensus-path tests on top (block-carried + finality exclusion).
- **Determinism:** run `--test-threads=1` (some tests mutate process env). The `poawx-sim` adaptive-mode
  scenario asserts byte-identical output across repeated runs.
- **Coverage gaps the auditor should weigh:** no live multi-node soak of the *combined* 28–34 stack;
  deep-scale/cold-resync not re-stressed with all gates active after Phase 34; deserializer fuzzing not
  performed. See `docs/poaw-x-phase35-risk-register.md`.

**Status: not audited, not production-ready, not mainnet-ready.**
