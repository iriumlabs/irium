#!/usr/bin/env bash
set -euo pipefail
SECRET_FILE=/home/irium/.irium/state/poawx_miner_secret.hex
NODE_RPC=${IRIUM_NODE_RPC:-http://127.0.0.1:38300}
MINER_BIN=/home/irium/mainnet/bin/irium-miner-poawx
WORK_DIR=/tmp/irium-poawx-receipt-producer
mkdir -p "$WORK_DIR"
node_token() {
  systemctl show iriumd.service -p Environment --value 2>/dev/null \
    | tr " " "\n" \
    | sed -n "s/^IRIUM_RPC_TOKEN=//p" \
    | tail -n 1
}
while true; do
  RPC_TOKEN=$(node_token || true)
  AUTH=()
  if [ -n "${RPC_TOKEN:-}" ]; then
    AUTH=(-H "Authorization: Bearer $RPC_TOKEN")
  fi
  tmpl="$WORK_DIR/template.json"
  if ! curl -fsS --max-time 5 "${AUTH[@]}" "$NODE_RPC/rpc/getblocktemplate" -o "$tmpl" >/dev/null 2>&1; then
    sleep 5
    continue
  fi
  read -r mode pending height < <(python3 - "$tmpl" <<"PY"
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print(d.get("poawx_mode",""), len(d.get("poawx_pending_receipts") or []), d.get("height",0))
except Exception:
    print("", 0, 0)
PY
)
  if [ "$mode" != "active" ] || [ "${pending:-0}" != "0" ]; then
    sleep 5
    continue
  fi
  raw="$WORK_DIR/receipt.raw"
  json_out="$WORK_DIR/receipt.json"
  if IRIUM_POAWX_MINER_SECRET_HEX=$(cat "$SECRET_FILE") \
     IRIUM_NODE_RPC="$NODE_RPC" \
     IRIUM_RPC_TOKEN="${RPC_TOKEN:-}" \
     IRIUM_POAWX_EXPORT_RECEIPT_JSON=1 \
     IRIUM_POAWX_SKIP_HEADER_POW=1 \
     IRIUM_POAWX_MINE_POW_MAX_ITERS=${IRIUM_POAWX_MINE_POW_MAX_ITERS:-8000000} \
     timeout 180 "$MINER_BIN" --poawx > "$raw" 2>"$WORK_DIR/miner.err"; then
    if python3 - "$raw" "$json_out" <<"PY"
import json,sys
from pathlib import Path
raw=Path(sys.argv[1]).read_text()
start=raw.find("{"); end=raw.rfind("}")
if start < 0 or end < start:
    raise SystemExit(1)
obj=json.loads(raw[start:end+1])
Path(sys.argv[2]).write_text(json.dumps(obj,separators=(",",":")))
print(obj.get("height",0))
PY
    then
      receipt_h=$(python3 - "$json_out" <<"PYH"
import json,sys
print(json.load(open(sys.argv[1])).get("height",0))
PYH
      )
      if [ "$receipt_h" = "$height" ]; then
        curl -fsS --max-time 10 "${AUTH[@]}" -H "Content-Type: application/json" --data-binary "@$json_out" "$NODE_RPC/poawx/receipt" >/dev/null \
          && echo "[$(date -Is)] posted PoAW-X receipt height=$receipt_h"
        systemctl restart irium-stratum.service irium-stratum-443.service irium-stratum-legacy.service irium-stratum-solo.service || true
      else
        echo "[$(date -Is)] skipped receipt height=$receipt_h template_height=$height"
      fi
    fi
  else
    echo "[$(date -Is)] receipt generation failed for template_height=$height" >&2
  fi
  sleep 5
done
