#!/bin/bash
# Irium PoAW-X block producer launcher + AUTOMATIC role participation.
# Runs the block miner (proposer role) AND automatically does the 3 worker roles'
# work (compute/verify/support), submitting its candidacy to each PEER producing
# node (IRIUM_POAWX_PEER_NODES). When a peer wins a block it then pays THIS host's
# workers their role shares -> automatic cross-reward, no manual enrollment.
# With no peers (or none reachable) blocks simply self-fill: the sole miner keeps
# the full 50 IRM, and a missing/offline worker role always falls back to self-fill
# so the chain never stalls. Reuses the proven poawx-role-worker role-work code.
#
# --- why each role gets its OWN key -------------------------------------------
# The mainnet per-identity role-bundle limit is HARD-FIXED at 8 bundles / 60s
# keyed on the payout pkh (env-ignored on network_id==0, poawx_role_bundle.rs).
# Running all 3 roles under ONE key trips that limit on burst heights, so those
# roles are dropped ("role bundle: identity rate limited") and the block
# self-fills. A distinct key per role submits ~1 bundle/height (<< 8/60s) so the
# split does not fail on rate limits, AND it makes each role a DISTINCT on-chain
# payee -- the PoAW-X 4-worker split. Every worker key is recoverable from the
# producer secret:
#   worker_secret = sha256("IRIUM_POAWX_WORKER_v1|<role>|<producer_secret_hex>")
#
# --- why the workers are SUPERVISED -------------------------------------------
# Previously each worker was launched once with `&` and its output sent to
# /dev/null. A worker that died stayed dead until the next producer restart, and
# nothing said so -- the only symptom was blocks quietly self-filling. That is the
# silent-failure mode this project has been burned by before. Each worker now runs
# under a supervisor that restarts it if it exits, and worker output goes to the
# journal so a failing role is visible instead of silently unpaid.
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

# Poll cadence for the role workers. Small so burst heights (blocks found faster
# than one poll) are not skipped; well under the producer's fan-out wait. The
# role-work fetch is a plain read; only the per-height bundle POST is
# rate-limited, and that stays ~1/height per distinct key.
_POLL="${IRIUM_POAWX_ROLE_WORKER_POLL_SECS:-2}"
# Seconds to wait before restarting a worker that exited (crash-loop guard).
_RESPAWN_DELAY="${IRIUM_POAWX_ROLE_WORKER_RESPAWN_SECS:-5}"

_WORKER_PIDS=()

# Keep one role worker alive forever: run it, and if it ever exits, say so
# loudly and start it again. Never gives up -- a permanently failing role must
# keep complaining in the journal rather than silently stop being paid.
supervise_worker() {
  local role="$1" peer="$2" wsecret="$3"
  while true; do
    env -i \
      IRIUM_POAWX_ROLE_SECRET_HEX="$wsecret" \
      IRIUM_NODE_RPC="$peer" \
      IRIUM_POAWX_ROLE_WORKER_LOOP=1 \
      IRIUM_POAWX_ROLE_WORKER_POLL_SECS="$_POLL" \
      "$ROLE_WORKER_BIN" "$role" 2>&1 | sed -u "s/^/[role:${role}] /"
    echo "poawx-producer: role worker '${role}' -> ${peer} EXITED (rc=$?); respawning in ${_RESPAWN_DELAY}s" >&2
    sleep "$_RESPAWN_DELAY"
  done
}

# Stop the supervisors (and their workers) when the producer goes away, so a
# restart does not leave a second set of workers behind.
cleanup_workers() {
  local pid
  for pid in "${_WORKER_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null
  done
}
trap cleanup_workers EXIT INT TERM

# --- automatic role participation (compute/verify/support) toward each peer node ---
if [ -n "$PEER_NODES" ] && [ -n "$ROLE_WORKER_BIN" ] && [ -x "$ROLE_WORKER_BIN" ]; then
  _SECRET_HEX="$(cat "$SECRET_FILE")"
  IFS=',' read -ra _PEERS <<< "$PEER_NODES" || true
  for _peer in "${_PEERS[@]}"; do
    _peer="$(echo "$_peer" | tr -d '[:space:]')"
    [ -z "$_peer" ] && continue
    for _role in compute verify support; do
      # distinct, deterministic per-role key (see header)
      _wsecret="$(printf '%s' "IRIUM_POAWX_WORKER_v1|${_role}|${_SECRET_HEX}" | sha256sum | cut -d' ' -f1)"
      supervise_worker "$_role" "$_peer" "$_wsecret" &
      _WORKER_PIDS+=("$!")
    done
  done
  echo "poawx-producer: automatic role participation started (supervised, distinct per-role keys, poll=${_POLL}s, peers: $PEER_NODES)"
fi

# Run the miner in the foreground but NOT via exec: the shell must stay alive to
# supervise the workers and to run the cleanup trap. Mirror the miner's exit code
# so systemd still sees the real result.
"$MINER_BIN" --poawx --threads "$IRIUM_MINER_THREADS"
_rc=$?
echo "poawx-producer: miner exited rc=${_rc}" >&2
exit "$_rc"
