# Remediation Test Matrix

Minimum tests to run for a fix, by affected area. Always run the **full regression** in addition to the
focused suite. Run library tests with `--test-threads=1` (env-mutating tests are parallel-flaky).

## By affected area → focused suites

| Affected area | Focused test filter(s) |
|---|---|
| Finality / reorg (Phase 28) | `cargo test --lib phase28 -- --test-threads=1`; `finality` |
| Double-sign evidence / penalties (29/30) | `cargo test --lib phase29 -- --test-threads=1`; `phase30` |
| Reward manifest / caps / fallback (31) | `cargo test --lib phase31 -- --test-threads=1`; `reward` |
| Ticket store / Sybil / rate-limit / expiry (32) | `cargo test --lib phase32 -- --test-threads=1`; `ticket` |
| Dominance commitment (33) | `cargo test --lib phase33 -- --test-threads=1`; `dominance` |
| Adaptive modes (34) | `cargo test --lib phase34 -- --test-threads=1`; `adaptive` |
| Wire compatibility (DSE1/TKT1/DMC1/ADM1) | affected `phaseNN` + serialization tests in `poawx` |
| Replay / reorg / cold sync | `phase28`/`phase30`/`phase32`/`phase33`/`phase34` replay+reorg tests |
| Simulation suite | `cargo test --bin poawx-sim -- --test-threads=1` |
| Activation / mainnet hard-off | each phase's `*_gate` / `*_no_op` tests (all phases) |

## Minimum commands for every remediation

```bash
# 1. Focused tests for the affected area (see table)
cargo test --lib <phaseNN> -- --test-threads=1

# 2. Full library regression (must stay green; baseline 822/0 at Phase 34)
cargo test --lib -- --test-threads=1

# 3. Simulator
cargo test --bin poawx-sim -- --test-threads=1

# 4. Release build
cargo build --release --bin iriumd --bin poawx-live-proof-harness --bin poawx-sim

# 5. Docs check (no broken pointers introduced)
grep -RIn "production-ready: yes\|mainnet-ready: yes\|audited: yes" docs || true

# 6. Branch diff check (scope of the fix)
git diff --stat <base-commit>..HEAD
git diff --name-only <base-commit>..HEAD
```

## Acceptance bar for a fix

- Affected focused suite: **green**.
- Full lib suite: **green, no regressions** (≥ the baseline count for that branch).
- `poawx-sim`: **green**.
- Release build: **OK**.
- Fix is **additive / non-weakening** (does not relax phase21d/21e/22a or Phase 30–34; does not change
  PoW/LWMA/base-reward/mainnet; mainnet stays hard-off).
- Diff scope matches the finding (no unrelated changes).

Record the results in the finding record and the branch template; then proceed to `RETEST_PROTOCOL.md`.
