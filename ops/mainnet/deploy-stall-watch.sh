#!/usr/bin/env bash
# ops/mainnet/deploy-stall-watch.sh
# Deploy-window stall detector for Stage 3a (and any live pool/daemon change).
# Polls the mainnet node template height every 30s from the moment a deploy step
# starts serving a new binary. If the height does not advance for > STALL_SECS
# (default 480s = 8 min), it ALARMS to stdout/stderr and exits non-zero so the
# operator triggers rollback R-any well within the plan's ~10-minute intent.
#
# Read-only: it only queries getblocktemplate. It NEVER restarts services,
# swaps binaries, or performs a rollback itself -- rollback stays a human/plan
# decision. Run it in a side terminal for the duration of a deploy step.
#
# Usage:  deploy-stall-watch.sh [label]
# Env:    NODE_RPC (default http://127.0.0.1:38300), STALL_SECS (default 480),
#         POLL_SECS (default 30), MAX_MINUTES (default 60 then auto-exit).
set -u
NODE_RPC=${NODE_RPC:-http://127.0.0.1:38300}
STALL_SECS=${STALL_SECS:-480}
POLL_SECS=${POLL_SECS:-30}
MAX_MINUTES=${MAX_MINUTES:-60}
LABEL=${1:-deploy}

tok() { systemctl show iriumd.service -p Environment --value 2>/dev/null | tr ' ' '\n' | sed -n 's/^IRIUM_RPC_TOKEN=//p' | tail -n1; }
height() { curl -s --max-time 6 -H "Authorization: Bearer $(tok)" "$NODE_RPC/rpc/getblocktemplate" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('height',-1))" 2>/dev/null; }

start_ts=$(date +%s)
last_h=$(height)
last_change=$start_ts
echo "[stall-watch:$LABEL] start height=$last_h STALL_SECS=$STALL_SECS POLL_SECS=$POLL_SECS"
if [ -z "$last_h" ] || [ "$last_h" = "-1" ]; then
  echo "[stall-watch:$LABEL] ALARM: node template unreachable at start"; exit 2
fi

while true; do
  sleep "$POLL_SECS"
  now=$(date +%s)
  h=$(height)
  if [ -z "$h" ] || [ "$h" = "-1" ]; then
    stalled=$(( now - last_change ))
    echo "[stall-watch:$LABEL] WARN: template unreachable (stalled ${stalled}s at h=$last_h)"
  elif [ "$h" != "$last_h" ]; then
    echo "[stall-watch:$LABEL] ok: height $last_h -> $h"
    last_h=$h; last_change=$now
  fi
  stalled=$(( now - last_change ))
  if [ "$stalled" -gt "$STALL_SECS" ]; then
    echo "[stall-watch:$LABEL] ALARM: height stuck at $last_h for ${stalled}s (> ${STALL_SECS}s). TRIGGER ROLLBACK R-any NOW."
    exit 1
  fi
  if [ $(( (now - start_ts) / 60 )) -ge "$MAX_MINUTES" ]; then
    echo "[stall-watch:$LABEL] done: ${MAX_MINUTES}m elapsed, height advancing normally (last=$last_h). Exiting clean."
    exit 0
  fi
done
