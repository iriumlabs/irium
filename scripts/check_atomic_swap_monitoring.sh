#!/usr/bin/env bash
set -euo pipefail

: "${COORD_URL:=http://127.0.0.1:39093}"
: "${IRIUM_STATUS_URL:=http://127.0.0.1:58480/status}"
: "${IRIUM_RPC_URL:=http://127.0.0.1:58400}"
: "${IRIUM_RPC_TOKEN:=}"
: "${BTC_RPC_USER:=irium}"
: "${BTC_RPC_PASSWORD:=iriumpass}"
: "${BTC_WALLET:=iriumswap}"
: "${SWAP_COORD_DB:=/home/irium/irium-pilot/swap-coordinator.db}"
: "${STUCK_MINUTES:=20}"
: "${RISK_WINDOW_MINUTES:=15}"

checks=()
alerts=()

add_check(){ checks+=("$1"); }
add_alert(){ alerts+=("$1"); }

AUTH=()
if [[ -n "$IRIUM_RPC_TOKEN" ]]; then
  AUTH=(-H "Authorization: Bearer $IRIUM_RPC_TOKEN")
fi

curl -fsS --max-time 4 "$COORD_URL/healthz" >/dev/null && add_check "coordinator_health:ok" || add_alert "coordinator_failure:healthz_unreachable"
curl -fsS --max-time 4 "$IRIUM_STATUS_URL" >/dev/null && add_check "irium_node_status:ok" || add_alert "node_disconnect:irium_status_unreachable"
curl -fsS --max-time 4 "${IRIUM_RPC_URL}/status" "${AUTH[@]}" >/dev/null && add_check "irium_rpc:ok" || add_alert "rpc_reconnect_failure:irium_rpc_unreachable"

BTC_CLI=""
if command -v bitcoin-cli >/dev/null 2>&1; then
  BTC_CLI="$(command -v bitcoin-cli)"
elif [[ -x "$HOME/opt/bitcoin-core/bin/bitcoin-cli" ]]; then
  BTC_CLI="$HOME/opt/bitcoin-core/bin/bitcoin-cli"
fi
if [[ -n "$BTC_CLI" ]] && "$BTC_CLI" -regtest -rpcuser="$BTC_RPC_USER" -rpcpassword="$BTC_RPC_PASSWORD" -rpcwallet="$BTC_WALLET" getblockcount >/dev/null 2>&1; then
  add_check "btc_rpc:ok"
else
  [[ -n "$BTC_CLI" ]] && add_alert "rpc_reconnect_failure:btc_rpc_unreachable" || add_alert "rpc_reconnect_failure:btc_cli_missing"
fi

stuck_count=0
risk_count=0
if [[ -f "$SWAP_COORD_DB" ]] && command -v python3 >/dev/null 2>&1; then
  read -r stuck_count risk_count < <(python3 - <<PY
import sqlite3
conn = sqlite3.connect("$SWAP_COORD_DB")
cur = conn.cursor()
cur.execute("""
SELECT COUNT(*) FROM swaps
WHERE state IN ('\"irium_htlc_created\"','\"irium_htlc_confirmed\"','\"btc_htlc_created\"','\"btc_htlc_confirmed\"','\"claim_initiated\"','\"refund_pending\"')
  AND datetime(updated_at) < datetime('now', ?)
""", (f"-{int('$STUCK_MINUTES')} minutes",))
stuck = cur.fetchone()[0]
cur.execute("""
SELECT COUNT(*) FROM swaps
WHERE state NOT IN ('\"claimed\"','\"refunded\"','\"failed\"','\"expired\"')
  AND datetime(expires_at) <= datetime('now', ?)
""", (f"+{int('$RISK_WINDOW_MINUTES')} minutes",))
risk = cur.fetchone()[0]
print(stuck, risk)
PY
)
  add_check "stuck_swap_scan:python3_sqlite"
else
  add_alert "monitoring_db_scan_unavailable"
fi

[[ "$stuck_count" =~ ^[0-9]+$ ]] && (( stuck_count > 0 )) && add_alert "stuck_swap_states:${stuck_count}" || true
[[ "$risk_count" =~ ^[0-9]+$ ]] && (( risk_count > 0 )) && add_alert "timeout_risk_conditions:${risk_count}" || true

checks_json='[]'
alerts_json='[]'
if (( ${#checks[@]} > 0 )); then
  checks_json=$(printf '%s\n' "${checks[@]}" | jq -R . | jq -s .)
fi
if (( ${#alerts[@]} > 0 )); then
  alerts_json=$(printf '%s\n' "${alerts[@]}" | jq -R . | jq -s .)
fi

jq -n --arg ts "$(date -Iseconds)" --argjson checks "$checks_json" --argjson alerts "$alerts_json" '{timestamp:$ts, checks:$checks, alerts:$alerts, ok: ($alerts|length==0)}'

if (( ${#alerts[@]} > 0 )); then
  exit 2
fi
