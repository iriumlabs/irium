# Phase 43 — Baseline Test Evidence (before the enhanced soak)

Run at the Phase 43 branch (source == Phase 42 head `693d76d`). Library tests `--test-threads=1`.

| Suite | Result |
|---|---|
| `phase42` | 7 / 0 |
| `phase34` | 17 / 0 |
| `phase33` | 9 / 0 |
| `phase32` | 12 / 0 |
| `phase31` | 10 / 0 |
| `phase30` | 7 / 0 |
| `phase29` | 12 / 0 |
| `phase28` | 8 / 0 |
| full lib | **829 / 0** |
| `poawx-sim` | 17 / 0 |
| release build (iriumd + poawx-live-proof-harness + poawx-sim) | Finished OK |

All green; gate cleared to proceed to the enhanced Stage A soak. Not audited / not production-ready /
not mainnet-ready.
