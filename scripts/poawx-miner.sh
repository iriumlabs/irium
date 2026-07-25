#!/usr/bin/env bash
#
# poawx-miner.sh — one-command seamless PoAW-X mining.
#
# Runs the light-miner enrollment loop (poawx-role-worker) so THIS miner is selected by the
# chain for the compute/verify/support roles and paid its share on-chain — optionally
# alongside a SHA-256d miner. Works against your OWN node (loopback) or a pool / Irium Core
# node that opted in with IRIUM_POAWX_REMOTE_ENROLLMENT=1.
#
# You need only a 32-byte key (your payout identity) — NOT a full node. The role-worker holds
# your key locally and produces its own VRF proof + sybil ticket per block; the node/pool
# relays it. A pool cannot forge this, so your rewards are bound to your own address.
#
# Required:
#   IRIUM_POAWX_MINER_SECRET_HEX   your 32-byte key, 64 hex chars (payout identity; keep private)
#   IRIUM_NODE_RPC                 node RPC, e.g. http://127.0.0.1:38300 (your node) or the pool's
# Optional:
#   IRIUM_RPC_TOKEN                bearer token if the target node requires one
#   IRIUM_POAWX_ROLES             space-separated roles to enroll for (default "compute").
#                                  A pool spreads miners across roles; a solo miner may set
#                                  "compute verify support" — the chain selects distinct
#                                  participants per role, so one key wins at most one role/block.
#   IRIUM_POAWX_ROLE_WORKER_BIN    path to poawx-role-worker (default: next to this script's target)
#   IRIUM_POAWX_POLL_SECS          re-enroll poll interval (default 10)
#   IRIUM_POAWX_MINER_CMD          optional companion SHA-256d miner command to run alongside
#                                  (e.g. "irium-miner-gpu --pool stratum+tcp://pool.irium.org:3335 --wallet Q...")
#
set -euo pipefail

: "${IRIUM_POAWX_MINER_SECRET_HEX:?set IRIUM_POAWX_MINER_SECRET_HEX (your 32-byte key, 64 hex chars)}"
: "${IRIUM_NODE_RPC:?set IRIUM_NODE_RPC (node or pool RPC base URL)}"

ROLES="${IRIUM_POAWX_ROLES:-compute}"
POLL="${IRIUM_POAWX_POLL_SECS:-10}"

# Resolve the role-worker binary: explicit override, else same dir as this script, else PATH.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKER="${IRIUM_POAWX_ROLE_WORKER_BIN:-}"
if [ -z "$WORKER" ]; then
  for c in "$here/poawx-role-worker" "$here/../target/release/poawx-role-worker" "poawx-role-worker"; do
    if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then WORKER="$c"; break; fi
  done
fi
[ -n "$WORKER" ] || { echo "poawx-miner: cannot find poawx-role-worker (set IRIUM_POAWX_ROLE_WORKER_BIN)" >&2; exit 1; }

pids=()
cleanup() {
  echo "[poawx-miner] shutting down..."
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

echo "[poawx-miner] node=$IRIUM_NODE_RPC roles=[$ROLES] worker=$WORKER poll=${POLL}s"

# One stay-enrolled loop per role. The role-worker's own loop mode re-enrolls each new height
# and retries transient errors, so these run unattended.
for role in $ROLES; do
  case "$role" in compute|verify|support) ;; *) echo "poawx-miner: bad role '$role' (compute|verify|support)" >&2; exit 1;; esac
  IRIUM_POAWX_ROLE_SECRET_HEX="$IRIUM_POAWX_MINER_SECRET_HEX" \
  IRIUM_NODE_RPC="$IRIUM_NODE_RPC" \
  IRIUM_RPC_TOKEN="${IRIUM_RPC_TOKEN:-}" \
  IRIUM_POAWX_ROLE_WORKER_LOOP=1 \
  IRIUM_POAWX_ROLE_WORKER_POLL_SECS="$POLL" \
    "$WORKER" "$role" &
  pids+=($!)
  echo "[poawx-miner] enrolled role=$role (pid $!)"
done

# Optional companion SHA-256d miner (supplies the base proof-of-work / pool shares).
if [ -n "${IRIUM_POAWX_MINER_CMD:-}" ]; then
  echo "[poawx-miner] launching companion miner: $IRIUM_POAWX_MINER_CMD"
  bash -c "$IRIUM_POAWX_MINER_CMD" &
  pids+=($!)
fi

# If any child exits, bring the rest down so a supervisor (systemd) can restart the unit cleanly.
wait -n
echo "[poawx-miner] a child process exited; shutting down the rest" >&2
cleanup
