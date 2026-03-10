#!/usr/bin/env bash
set -euo pipefail

: "${IRIUM_RPC_TOKEN:=trialtoken}"
: "${ASSERT_TIMEOUT_SECS:=180}"

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

export PATH="$HOME/opt/bitcoin-core/bin:$HOME/.cargo/bin:$PATH"

echo "[gate] rust lib tests"
cargo test --lib

echo "[gate] iriumd tests"
cargo test --bin iriumd -- --nocapture --test-threads=1

echo "[gate] coordinator tests"
cargo test --manifest-path tools/atomic-swap-coordinator/Cargo.toml -- --nocapture

echo "[gate] cargo check --tests"
cargo check --tests

echo "[gate] dual-chain strict assertions"
IRIUM_RPC_TOKEN="$IRIUM_RPC_TOKEN" ASSERT_TIMEOUT_SECS="$ASSERT_TIMEOUT_SECS" scripts/run_atomic_swap_dual_chain_assert.sh

echo "[gate] monitoring checks"
IRIUM_RPC_TOKEN="$IRIUM_RPC_TOKEN" scripts/check_atomic_swap_monitoring.sh

echo "[gate] PASS"
