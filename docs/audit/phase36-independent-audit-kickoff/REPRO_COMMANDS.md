# Repro Commands — PoAW-X Phases 28–34

For auditors to independently build, test, and diff. Testnet/devnet only; **do not run live nodes**;
mainnet stays hard-off. Commands assume a POSIX shell; on Windows use Git Bash or adapt paths.

## 1. Clone / fetch

```bash
git clone https://github.com/iriumlabs/irium.git
cd irium
git fetch origin
```

## 2. Checkout the audit heads

```bash
git checkout testnet/poawx-phase34-adaptive-modes-consensus-integration   # full consensus stack (78d5ca3)
# docs/consolidation head:
git checkout testnet/poawx-phase35-final-closeout-audit-consolidation      # 17f8a77
```

## 3. Verify commit hashes (must match)

```bash
git rev-parse origin/testnet/poawx-phase28-finalized-reorg-rejection          # 199ed24…
git rev-parse origin/testnet/poawx-phase29-double-sign-penalties              # df0cc92…
git rev-parse origin/testnet/poawx-phase30-block-carried-doublesign-evidence  # 7e5f805…
git rev-parse origin/testnet/poawx-phase31-reward-manifest-wrapper-cap-fallback # fae91bb…
git rev-parse origin/testnet/poawx-phase32-onchain-ticket-store               # 8f2a64d…
git rev-parse origin/testnet/poawx-phase33-dominance-state-commitment         # 1a032de…
git rev-parse origin/testnet/poawx-phase34-adaptive-modes-consensus-integration # 78d5ca3…
git rev-parse origin/main                                                      # 19c496d… (unchanged)
```

## 4. Focused tests (run on the Phase 34 head)

```bash
cargo test --lib phase28 -- --test-threads=1   # expect 8/0
cargo test --lib phase29 -- --test-threads=1   # expect 12/0
cargo test --lib phase30 -- --test-threads=1   # expect 7/0
cargo test --lib phase31 -- --test-threads=1   # expect 9/0
cargo test --lib phase32 -- --test-threads=1   # expect 12/0
cargo test --lib phase33 -- --test-threads=1   # expect 9/0
cargo test --lib phase34 -- --test-threads=1   # expect 17/0
```

## 5. Full library + simulator tests

```bash
cargo test --lib -- --test-threads=1            # expect 822/0 at Phase 34 head
cargo test --bin poawx-sim -- --test-threads=1  # expect 17/0
```

> Run library tests with `--test-threads=1`: some tests mutate process env (network id / activation
> gates) and are flaky under parallelism. This is a test-harness property, not a consensus issue.

## 6. Release build

```bash
cargo build --release --bin iriumd --bin poawx-live-proof-harness --bin poawx-sim
```

## 7. Diffs against origin/main and per phase

```bash
# Per-phase incremental diffs (what each phase changed):
git diff --stat 40db1aa..199ed24    # Phase 28
git diff --stat 199ed24..df0cc92    # Phase 29
git diff --stat df0cc92..7e5f805    # Phase 30
git diff --stat 7e5f805..fae91bb    # Phase 31
git diff --stat fae91bb..8f2a64d    # Phase 32
git diff --stat 8f2a64d..1a032de    # Phase 33
git diff --stat 1a032de..78d5ca3    # Phase 34

# Whole-stack vs the long-running testnet base:
git diff --stat 40db1aa..78d5ca3
```

(Note: `git diff origin/main..78d5ca3` is very large — the testnet branch carries the entire PoAW-X line
since ~Phase 20. Use the per-phase ranges above to review the in-scope increments.)

## 8. Known formatting caveat

There is a **pre-existing `rustfmt` deviation in `src/bin/poawx-live-proof-harness.rs`** (a
devnet/testnet harness binary, not a consensus validator). `cargo fmt --check` may flag it. The Phase
28–34 consensus files are formatted; this harness file's formatting is unrelated to consensus and was
intentionally not reformatted. Do not treat a global `cargo fmt --check` failure on that file as a
finding.
