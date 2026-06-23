# Phase 41 — Baseline Test Evidence (before any devnet run)

Run on the Windows repo at the Phase 41 branch (source identical to the Phase 34 audited baseline
`78d5ca3`; Phases 35–40 were docs-only). Library tests run with `--test-threads=1`.

## Results

| Suite | Result |
|---|---|
| `cargo test phase28 --lib` | **8 passed / 0 failed** |
| `cargo test phase29 --lib` | **12 passed / 0 failed** |
| `cargo test phase30 --lib` | **7 passed / 0 failed** |
| `cargo test phase31 --lib` | **9 passed / 0 failed** |
| `cargo test phase32 --lib` | **12 passed / 0 failed** |
| `cargo test phase33 --lib` | **9 passed / 0 failed** |
| `cargo test phase34 --lib` | **17 passed / 0 failed** |
| `cargo test --lib` (full) | **822 passed / 0 failed** |
| `cargo test --bin poawx-sim` | **17 passed / 0 failed** |
| `cargo build --release` (iriumd, poawx-live-proof-harness, poawx-sim) | binaries present/current |

## Notes

- All focused suites + the full library suite + the simulator are green; no regressions.
- Binaries `target/release/iriumd.exe` and `target/release/poawx-live-proof-harness.exe` are present and
  current (source unchanged since the Phase 34 build).
- This baseline is the gate for proceeding to the Stage A loopback devnet; it passed.

Status: not audited / not production-ready / not mainnet-ready; PoAW-X hard-off on mainnet.
