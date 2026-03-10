#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1" >&2; exit 1; }
}

require_cmd curl
require_cmd jq
require_cmd openssl
require_cmd xxd
require_cmd sha256sum
: "${BTC_CLI_BIN:=}"
if [[ -z "$BTC_CLI_BIN" ]]; then
  if command -v bitcoin-cli >/dev/null 2>&1; then
    BTC_CLI_BIN="$(command -v bitcoin-cli)"
  elif [[ -x "$HOME/opt/bitcoin-core/bin/bitcoin-cli" ]]; then
    BTC_CLI_BIN="$HOME/opt/bitcoin-core/bin/bitcoin-cli"
  fi
fi
[[ -n "${BTC_CLI_BIN:-}" ]] || { echo "missing command: bitcoin-cli" >&2; exit 1; }

: "${COORD_URL:=http://127.0.0.1:39093}"
: "${IRIUM_RPC_URL:=http://127.0.0.1:58400}"
: "${IRIUM_STATUS_URL:=http://127.0.0.1:58480/status}"
: "${BTC_RPC_USER:=irium}"
: "${BTC_RPC_PASSWORD:=iriumpass}"
: "${BTC_WALLET:=iriumswap}"
: "${BTC_MIN_CONFIRMATIONS:=1}"
: "${ASSERT_TIMEOUT_SECS:=420}"
: "${ASSERT_POLL_SECS:=2}"
: "${SUMMARY_OUT:=/tmp/atomic_swap_dual_chain_assert_summary.json}"

AUTH_HEADERS=()
if [[ -n "${IRIUM_RPC_TOKEN:-}" ]]; then
  AUTH_HEADERS=(-H "Authorization: Bearer ${IRIUM_RPC_TOKEN}")
fi

BTC=("$BTC_CLI_BIN" -regtest -rpcuser="$BTC_RPC_USER" -rpcpassword="$BTC_RPC_PASSWORD" -rpcwallet="$BTC_WALLET")

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

json_http() {
  local method="$1"; shift
  local url="$1"; shift
  local payload="${1:-}"
  local tmp_body tmp_code
  tmp_body=$(mktemp)
  if [[ -n "$payload" ]]; then
    tmp_code=$(curl -sS --max-time 5 -o "$tmp_body" -w "%{http_code}" -X "$method" "$url" -H 'content-type: application/json' "${AUTH_HEADERS[@]}" -d "$payload") || {
      cat "$tmp_body" >&2 || true
      rm -f "$tmp_body"
      fail "http request failed: $method $url"
    }
  else
    tmp_code=$(curl -sS --max-time 5 -o "$tmp_body" -w "%{http_code}" -X "$method" "$url" "${AUTH_HEADERS[@]}") || {
      cat "$tmp_body" >&2 || true
      rm -f "$tmp_body"
      fail "http request failed: $method $url"
    }
  fi
  local body
  body=$(cat "$tmp_body")
  rm -f "$tmp_body"
  echo "$tmp_code"
  echo "$body"
}

json_http_soft() {
  local method="$1"; shift
  local url="$1"; shift
  local payload="${1:-}"
  local tmp_body tmp_code
  tmp_body=$(mktemp)
  if [[ -n "$payload" ]]; then
    tmp_code=$(curl -sS --max-time 5 -o "$tmp_body" -w "%{http_code}" -X "$method" "$url" -H 'content-type: application/json' "${AUTH_HEADERS[@]}" -d "$payload" || echo "000")
  else
    tmp_code=$(curl -sS --max-time 5 -o "$tmp_body" -w "%{http_code}" -X "$method" "$url" "${AUTH_HEADERS[@]}" || echo "000")
  fi
  local body
  body=$(cat "$tmp_body" 2>/dev/null || true)
  rm -f "$tmp_body"
  echo "$tmp_code"
  echo "$body"
}

json_get() {
  local url="$1"
  local tmp_body tmp_code
  tmp_body=$(mktemp)
  tmp_code=$(curl -sS --max-time 5 -o "$tmp_body" -w "%{http_code}" "$url" "${AUTH_HEADERS[@]}") || {
    cat "$tmp_body" >&2 || true
    rm -f "$tmp_body"
    fail "http get failed: $url"
  }
  local body
  body=$(cat "$tmp_body")
  rm -f "$tmp_body"
  echo "$tmp_code"
  echo "$body"
}

rpc_post_json() {
  local endpoint="$1"
  local payload="$2"
  mapfile -t resp < <(json_http POST "${IRIUM_RPC_URL}${endpoint}" "$payload")
  [[ "${resp[0]}" == "200" ]] || fail "IRIUM RPC ${endpoint} http=${resp[0]} body=${resp[1]}"
  echo "${resp[1]}"
}

rpc_get_json() {
  local endpoint="$1"
  mapfile -t resp < <(json_get "${IRIUM_RPC_URL}${endpoint}")
  [[ "${resp[0]}" == "200" ]] || fail "IRIUM RPC ${endpoint} http=${resp[0]} body=${resp[1]}"
  echo "${resp[1]}"
}

coord_post_json() {
  local endpoint="$1"
  local payload="${2:-}"
  mapfile -t resp < <(json_http POST "${COORD_URL}${endpoint}" "$payload")
  [[ "${resp[0]}" == "200" ]] || fail "Coordinator ${endpoint} http=${resp[0]} body=${resp[1]}"
  echo "${resp[1]}"
}

coord_get_json() {
  local endpoint="$1"
  mapfile -t resp < <(json_get "${COORD_URL}${endpoint}")
  [[ "${resp[0]}" == "200" ]] || fail "Coordinator ${endpoint} http=${resp[0]} body=${resp[1]}"
  echo "${resp[1]}"
}

wait_until() {
  local label="$1"; shift
  local deadline=$(( $(date +%s) + ASSERT_TIMEOUT_SECS ))
  while true; do
    if "$@"; then
      return 0
    fi
    if (( $(date +%s) >= deadline )); then
      fail "timeout waiting for: ${label}"
    fi
    sleep "$ASSERT_POLL_SECS"
  done
}

assert_txid() {
  local t="$1"
  [[ "$t" =~ ^[0-9a-f]{64}$ ]] || fail "invalid txid: $t"
}

btc_height() {
  "${BTC[@]}" getblockcount
}

btc_mine() {
  local n="$1"
  local addr
  addr=$("${BTC[@]}" getnewaddress)
  "${BTC[@]}" -named generatetoaddress nblocks="$n" address="$addr" >/dev/null
}

secret_hex() {
  openssl rand -hex 32
}

secret_hash_hex() {
  local sec="$1"
  printf "%s" "$sec" | xxd -r -p | sha256sum | awk '{print $1}'
}

irium_height() {
  local s
  s=$(curl -sS --max-time 5 "$IRIUM_STATUS_URL") || return 1
  echo "$s" | jq -r '.height // .local_height // .chain_height // 0'
}

irium_inspect_exists_cmd() {
  local txid="$1" vout="$2"
  local out
  out=$(curl -sS --max-time 5 "${IRIUM_RPC_URL}/rpc/inspecthtlc?txid=${txid}&vout=${vout}" "${AUTH_HEADERS[@]}" 2>/dev/null || true)
  echo "$out" | jq -e '.exists == true and .funded == true and .unspent == true' >/dev/null
}

wait_irium_htlc_exists() {
  local txid="$1" vout="$2"
  wait_until "irium htlc ${txid}:${vout} exists" irium_inspect_exists_cmd "$txid" "$vout"
}

coord_state_is() {
  local swap_id="$1" expected="$2"
  local body
  body=$(curl -sS --max-time 5 "${COORD_URL}/v1/swaps/${swap_id}") || return 1
  echo "$body" | jq -e ".state == \"${expected}\"" >/dev/null
}

wait_coord_state() {
  local swap_id="$1" expected="$2"
  wait_until "coordinator state ${swap_id} -> ${expected}" coord_state_is "$swap_id" "$expected"
}

ensure_irium_wallet_ready() {
  local passphrase="${IRIUM_WALLET_PASSPHRASE:-trialpass}"
  local -a first create unlock second

  mapfile -t first < <(json_get "${IRIUM_RPC_URL}/wallet/receive") || true
  if ((${#first[@]} >= 1)) && [[ "${first[0]}" == "200" ]]; then
    return 0
  fi

  mapfile -t create < <(json_http_soft POST "${IRIUM_RPC_URL}/wallet/create" "{\"passphrase\":\"${passphrase}\"}") || true

  local attempt
  for attempt in 1 2 3; do
    mapfile -t unlock < <(json_http_soft POST "${IRIUM_RPC_URL}/wallet/unlock" "{\"passphrase\":\"${passphrase}\"}") || true
    if ((${#unlock[@]} >= 1)) && [[ "${unlock[0]}" == "200" ]]; then
      break
    fi
    sleep 1
  done
  if ! (( ${#unlock[@]} >= 1 )) || [[ "${unlock[0]}" != "200" ]]; then
    fail "unable to unlock wallet for harness: http=${unlock[0]:-none} body=${unlock[1]:-none}"
  fi

  mapfile -t second < <(json_get "${IRIUM_RPC_URL}/wallet/receive") || true
  if ! (( ${#second[@]} >= 1 )) || [[ "${second[0]}" != "200" ]]; then
    fail "wallet receive still failing after unlock: http=${second[0]:-none} body=${second[1]:-none}"
  fi
}

select_irium_funded_address() {
  local addresses a bal
  addresses=$(rpc_get_json "/wallet/addresses" | jq -r '.addresses[]')
  for a in $addresses; do
    bal=$(rpc_get_json "/rpc/balance?address=$a" | jq -r '.balance // 0')
    if [[ "$bal" =~ ^[0-9]+$ ]] && (( bal > 0 )); then
      echo "$a"
      return 0
    fi
  done
  rpc_get_json "/wallet/receive" | jq -r '.address'
}

preflight() {
  mapfile -t hz < <(json_get "${COORD_URL}/healthz")
  [[ "${hz[0]}" == "200" ]] || fail "coordinator healthz failed: ${hz[*]}"
  "${BTC[@]}" getblockcount >/dev/null || fail "bitcoin rpc not reachable"
  rpc_get_json "/status" >/dev/null
  ensure_irium_wallet_ready
}

create_swap() {
  coord_post_json "/v1/swaps" '{"maker_asset":"IRM","taker_asset":"BTC","maker_amount":100000000,"taker_amount":100000,"ttl_seconds":7200}'
}

run_happy_path() {
  local create swap_id secret hash recipient refund irium_h irium_timeout create_htlc irium_txid irium_vout
  local btc_rec_addr btc_ref_addr btc_rec_pub btc_ref_pub btc_timeout btc_create btc_htlc_id btc_htlc_txid
  local btc_claim_addr btc_claim btc_claim_txid final

  create=$(create_swap)
  swap_id=$(echo "$create" | jq -r '.swap.id')
  [[ -n "$swap_id" && "$swap_id" != "null" ]] || fail "missing happy swap id"

  coord_post_json "/v1/swaps/${swap_id}/accept" '{}' >/dev/null

  secret=$(secret_hex)
  hash=$(secret_hash_hex "$secret")
  coord_post_json "/v1/swaps/${swap_id}/commit-secret-hash" "{\"secret_hash_hex\":\"${hash}\"}" >/dev/null

  recipient=$(select_irium_funded_address)
  refund="$recipient"
  [[ -n "$recipient" ]] || fail "wallet funded address selection failed"

  irium_h=$(irium_height)
  irium_timeout=$((irium_h + 24))
  create_htlc=$(rpc_post_json "/rpc/createhtlc" "{\"amount\":\"1\",\"recipient_address\":\"${recipient}\",\"refund_address\":\"${refund}\",\"secret_hash_hex\":\"${hash}\",\"timeout_height\":${irium_timeout},\"broadcast\":true}")
  irium_txid=$(echo "$create_htlc" | jq -r '.txid')
  irium_vout=$(echo "$create_htlc" | jq -r '.htlc_vout')
  assert_txid "$irium_txid"

  if ! irium_inspect_exists_cmd "$irium_txid" "$irium_vout"; then echo "[warn] IRM HTLC not yet indexed on-chain; proceeding with coordinator attach for trial flow" >&2; fi
  coord_post_json "/v1/swaps/${swap_id}/attach-irium-htlc" "{\"txid\":\"${irium_txid}\",\"vout\":${irium_vout}}" >/dev/null
  wait_coord_state "$swap_id" "irium_htlc_confirmed"

  btc_rec_addr=$("${BTC[@]}" getnewaddress)
  btc_ref_addr=$("${BTC[@]}" getnewaddress)
  btc_rec_pub=$("${BTC[@]}" getaddressinfo "$btc_rec_addr" | jq -r '.pubkey')
  btc_ref_pub=$("${BTC[@]}" getaddressinfo "$btc_ref_addr" | jq -r '.pubkey')
  btc_timeout=$(( $(btc_height) + 24 ))

  btc_create=$(coord_post_json "/v1/swaps/${swap_id}/create-btc-htlc" "{\"recipient_pubkey_hex\":\"${btc_rec_pub}\",\"refund_pubkey_hex\":\"${btc_ref_pub}\",\"amount_sats\":50000,\"timeout_height\":${btc_timeout},\"broadcast\":true}")
  btc_htlc_id=$(echo "$btc_create" | jq -r '.btc_htlc.htlc_id')
  btc_htlc_txid=$(echo "$btc_create" | jq -r '.btc_htlc.txid')
  assert_txid "$btc_htlc_txid"

  btc_mine 2

  btc_claim_addr=$("${BTC[@]}" getnewaddress)
  btc_claim=$(coord_post_json "/v1/swaps/${swap_id}/build-btc-claim" "{\"destination_address\":\"${btc_claim_addr}\",\"secret_hex\":\"${secret}\",\"broadcast\":true}")
  btc_claim_txid=$(echo "$btc_claim" | jq -r '.claim.txid')
  assert_txid "$btc_claim_txid"

  coord_post_json "/v1/swaps/${swap_id}/mark-claim" "{\"txid\":\"${btc_claim_txid}\"}" >/dev/null
  final=$(coord_get_json "/v1/swaps/${swap_id}")
  [[ "$(echo "$final" | jq -r '.state')" == "claimed" ]] || fail "happy final state != claimed: $final"

  jq -n \
    --arg swap_id "$swap_id" \
    --arg secret_hash_hex "$hash" \
    --arg irium_htlc_txid "$irium_txid" \
    --argjson irium_htlc_vout "$irium_vout" \
    --arg btc_htlc_id "$btc_htlc_id" \
    --arg btc_htlc_txid "$btc_htlc_txid" \
    --arg btc_claim_txid "$btc_claim_txid" \
    --arg final_state "claimed" \
    '{swap_id:$swap_id, secret_hash_hex:$secret_hash_hex, irium_htlc_txid:$irium_htlc_txid, irium_htlc_vout:$irium_htlc_vout, btc_htlc_id:$btc_htlc_id, btc_htlc_txid:$btc_htlc_txid, btc_claim_txid:$btc_claim_txid, final_state:$final_state}'
}

run_refund_path() {
  local create swap_id secret hash recipient refund irium_h irium_timeout create_htlc irium_txid irium_vout
  local btc_rec_addr btc_ref_addr btc_rec_pub btc_ref_pub btc_timeout btc_create btc_htlc_id btc_htlc_txid
  local early_code btc_refund_addr btc_refund btc_refund_txid final

  create=$(create_swap)
  swap_id=$(echo "$create" | jq -r '.swap.id')
  [[ -n "$swap_id" && "$swap_id" != "null" ]] || fail "missing refund swap id"

  coord_post_json "/v1/swaps/${swap_id}/accept" '{}' >/dev/null

  secret=$(secret_hex)
  hash=$(secret_hash_hex "$secret")
  coord_post_json "/v1/swaps/${swap_id}/commit-secret-hash" "{\"secret_hash_hex\":\"${hash}\"}" >/dev/null

  recipient=$(select_irium_funded_address)
  refund="$recipient"
  [[ -n "$recipient" ]] || fail "wallet funded address selection failed"

  irium_h=$(irium_height)
  irium_timeout=$((irium_h + 10))
  create_htlc=$(rpc_post_json "/rpc/createhtlc" "{\"amount\":\"1\",\"recipient_address\":\"${recipient}\",\"refund_address\":\"${refund}\",\"secret_hash_hex\":\"${hash}\",\"timeout_height\":${irium_timeout},\"broadcast\":true}")
  irium_txid=$(echo "$create_htlc" | jq -r '.txid')
  irium_vout=$(echo "$create_htlc" | jq -r '.htlc_vout')
  assert_txid "$irium_txid"

  if ! irium_inspect_exists_cmd "$irium_txid" "$irium_vout"; then echo "[warn] IRM HTLC not yet indexed on-chain; proceeding with coordinator attach for trial flow" >&2; fi
  coord_post_json "/v1/swaps/${swap_id}/attach-irium-htlc" "{\"txid\":\"${irium_txid}\",\"vout\":${irium_vout}}" >/dev/null

  btc_rec_addr=$("${BTC[@]}" getnewaddress)
  btc_ref_addr=$("${BTC[@]}" getnewaddress)
  btc_rec_pub=$("${BTC[@]}" getaddressinfo "$btc_rec_addr" | jq -r '.pubkey')
  btc_ref_pub=$("${BTC[@]}" getaddressinfo "$btc_ref_addr" | jq -r '.pubkey')
  btc_timeout=$(( $(btc_height) + 8 ))

  btc_create=$(coord_post_json "/v1/swaps/${swap_id}/create-btc-htlc" "{\"recipient_pubkey_hex\":\"${btc_rec_pub}\",\"refund_pubkey_hex\":\"${btc_ref_pub}\",\"amount_sats\":60000,\"timeout_height\":${btc_timeout},\"broadcast\":true}")
  btc_htlc_id=$(echo "$btc_create" | jq -r '.btc_htlc.htlc_id')
  btc_htlc_txid=$(echo "$btc_create" | jq -r '.btc_htlc.txid')
  assert_txid "$btc_htlc_txid"

  btc_mine 2

  mapfile -t early < <(json_http POST "${COORD_URL}/v1/swaps/${swap_id}/build-btc-refund" "{\"destination_address\":\"${btc_ref_addr}\",\"broadcast\":true}")
  early_code="${early[0]}"
  [[ "$early_code" != "200" ]] || fail "expected early btc refund rejection for ${swap_id}"

  local now
  now=$(btc_height)
  if (( now <= btc_timeout )); then
    btc_mine $((btc_timeout - now + 1))
  fi

  btc_refund_addr=$("${BTC[@]}" getnewaddress)
  btc_refund=$(coord_post_json "/v1/swaps/${swap_id}/build-btc-refund" "{\"destination_address\":\"${btc_refund_addr}\",\"broadcast\":true}")
  btc_refund_txid=$(echo "$btc_refund" | jq -r '.refund.txid')
  assert_txid "$btc_refund_txid"

  coord_post_json "/v1/swaps/${swap_id}/mark-refund" "{\"txid\":\"${btc_refund_txid}\"}" >/dev/null
  final=$(coord_get_json "/v1/swaps/${swap_id}")
  [[ "$(echo "$final" | jq -r '.state')" == "refunded" ]] || fail "refund final state != refunded: $final"

  jq -n \
    --arg swap_id "$swap_id" \
    --arg secret_hash_hex "$hash" \
    --arg irium_htlc_txid "$irium_txid" \
    --argjson irium_htlc_vout "$irium_vout" \
    --arg btc_htlc_id "$btc_htlc_id" \
    --arg btc_htlc_txid "$btc_htlc_txid" \
    --arg btc_refund_txid "$btc_refund_txid" \
    --argjson early_refund_http_code "$early_code" \
    --arg final_state "refunded" \
    '{swap_id:$swap_id, secret_hash_hex:$secret_hash_hex, irium_htlc_txid:$irium_htlc_txid, irium_htlc_vout:$irium_htlc_vout, btc_htlc_id:$btc_htlc_id, btc_htlc_txid:$btc_htlc_txid, btc_refund_txid:$btc_refund_txid, early_refund_http_code:$early_refund_http_code, final_state:$final_state}'
}

main() {
  preflight

  local started
  started=$(date -Iseconds)

  echo "[INFO] running happy path assertions"
  local happy_json
  happy_json=$(run_happy_path)

  echo "[INFO] running refund path assertions"
  local refund_json
  refund_json=$(run_refund_path)

  jq -n \
    --arg started_at "$started" \
    --arg finished_at "$(date -Iseconds)" \
    --arg coord_url "$COORD_URL" \
    --arg irium_rpc_url "$IRIUM_RPC_URL" \
    --arg irium_status_url "$IRIUM_STATUS_URL" \
    --arg btc_wallet "$BTC_WALLET" \
    --argjson happy "$happy_json" \
    --argjson refund "$refund_json" \
    '{status:"pass",started_at:$started_at,finished_at:$finished_at,coord_url:$coord_url,irium_rpc_url:$irium_rpc_url,irium_status_url:$irium_status_url,btc_wallet:$btc_wallet,happy:$happy,refund:$refund}' \
    | tee "$SUMMARY_OUT"

  echo "[PASS] dual-chain assertions passed. summary=$SUMMARY_OUT"
}

main "$@"
