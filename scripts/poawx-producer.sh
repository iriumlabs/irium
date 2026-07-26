#!/bin/bash
# Irium PoAW-X block producer launcher + AUTOMATIC role participation.
# Runs the block miner (proposer role) AND automatically does the 3 worker roles'
# work (compute/verify/support) with the SAME key, submitting its candidacy to each
# PEER producing node (IRIUM_POAWX_PEER_NODES). When a peer wins a block it then pays
# THIS host its role share -> automatic cross-reward, no manual enrollment/registration.
# With no peers (or none reachable) blocks simply self-fill: the sole miner keeps the
# full 50 IRM, and a missing/offline worker role always falls back to self-fill so the
# chain never stalls. Reuses the proven poawx-role-worker role-work code in-service.
set -uo pipefail

SECRET_FILE="${IRIUM_POAWX_SECRET_FILE:?IRIUM_POAWX_SECRET_FILE not set}"
MINER_BIN="${IRIUM_POAWX_MINER_BIN:-/home/irium/mainnet/bin/irium-miner-poawx-v1.9.133-9e724e4}"
ROLE_WORKER_BIN="${IRIUM_POAWX_ROLE_WORKER_BIN:-}"
PEER_NODES="${IRIUM_POAWX_PEER_NODES:-}"   # comma-separated peer RPC bases, e.g. http://IP:38300

[ -r "$SECRET_FILE" ] || { echo "poawx-producer: secret file not readable: $SECRET_FILE" >&2; exit 1; }
[ -x "$MINER_BIN" ]   || { echo "poawx-producer: miner binary not executable: $MINER_BIN" >&2; exit 1; }

export IRIUM_MINER_THREADS="${IRIUM_MINER_THREADS:-1}"
export IRIUM_NODE_RPC="${IRIUM_NODE_RPC:-http://127.0.0.1:38300}"
export IRIUM_POAWX_MINE_POW_MAX_ITERS="${IRIUM_POAWX_MINE_POW_MAX_ITERS:-1000000}"
export IRIUM_POAWX_MINER_SECRET_HEX="$(cat "$SECRET_FILE")"

# --- automatic role participation (compute/verify/support) toward each peer node ---
if [ -n "$PEER_NODES" ] && [ -n "$ROLE_WORKER_BIN" ] && [ -x "$ROLE_WORKER_BIN" ]; then
  _SECRET_HEX="$(cat "$SECRET_FILE")"
  IFS=',' read -ra _PEERS <<< "$PEER_NODES" || true
  for _peer in "${_PEERS[@]}"; do
    _peer="$(echo "$_peer" | tr -d '[:space:]')"
    [ -z "$_peer" ] && continue
    for _role in compute verify support; do
      env -i \
        IRIUM_POAWX_ROLE_SECRET_HEX="$_SECRET_HEX" \
        IRIUM_NODE_RPC="$_peer" \
        IRIUM_POAWX_ROLE_WORKER_LOOP=1 \
        IRIUM_POAWX_ROLE_WORKER_POLL_SECS=6 \
        "$ROLE_WORKER_BIN" "$_role" >/dev/null 2>&1 &
    done
  done
  echo "poawx-producer: automatic role participation started (peers: $PEER_NODES)"
fi

exec "$MINER_BIN" --poawx --threads "$IRIUM_MINER_THREADS"
