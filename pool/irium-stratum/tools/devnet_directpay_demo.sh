#!/bin/bash
# Live isolated-devnet direct-payout demo: node + pool + delegated miner, with
# proposer-VRF enforcement OFF. Proves the pool produces a block the node accepts
# via submit_block_extended, paying the miner directly on-chain. ISOLATED storage
# + ports; mainnet (:38300) and rig (:38500) untouched; torn down at end.
set -u
D=/home/irium/tmp/d15-wt
NODE=$D/target/release/iriumd
POOL=$D/pool/irium-stratum/target/release/irium-stratum
MINER=$D/target/release/irium-miner
WALLET=$D/target/release/irium-wallet
WIF2HEX=/home/irium/tmp/wif2hex/target/release/wif2hex
ROOT=/home/irium/tmp/devnet-directpay
RPC=42111; STATUS=42108; P2P=42110; STRAT=42133; DELEG=42140
TOK=dp-token
rm -rf "$ROOT"; mkdir -p "$ROOT/data" "$ROOT/blocks" "$ROOT/state"
NLOG="$ROOT/node.log"; PLOG="$ROOT/pool.log"; MLOG="$ROOT/miner.log"; RLOG="$ROOT/register.log"

cleanup() { for f in "$ROOT"/node.pid "$ROOT"/pool.pid "$ROOT"/miner.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done; }
trap cleanup EXIT

# PoAW-X gates that do NOT require the pool to hold an ECVRF prover; proposer-VRF OFF.
GATE=(
  IRIUM_NETWORK=devnet
  IRIUM_POAWX_MODE=active IRIUM_POAWX_ACTIVATION_HEIGHT=1
  IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS=4 IRIUM_POAWX_PUZZLE_BITS=4
  IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT=1 IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT=1
  IRIUM_POAWX_DELEGATION_ACTIVATION_HEIGHT=1
  # proposer-VRF intentionally UNSET => proposer_vrf_enforced == false
)

echo "############ STAGE 1: node up (isolated, proposer-VRF OFF, delegation active) ############"
# cwd MUST be the repo so the node finds ./bootstrap/trust (anchor allowlist).
( cd "$D" && env "${GATE[@]}" \
  IRIUM_DATA_DIR="$ROOT/data" IRIUM_BLOCKS_DIR="$ROOT/blocks" IRIUM_STATE_DIR="$ROOT/state" \
  IRIUM_WALLET_FILE="$ROOT/wallet.json" \
  IRIUM_NODE_HOST=127.0.0.1 IRIUM_NODE_PORT=$RPC \
  IRIUM_STATUS_HOST=127.0.0.1 IRIUM_STATUS_PORT=$STATUS \
  IRIUM_P2P_BIND=127.0.0.1:$P2P IRIUM_RPC_TOKEN=$TOK \
  "$NODE" >"$NLOG" 2>&1 ) &
NPID=$!; echo "$NPID" > "$ROOT/node.pid"
B="http://127.0.0.1:$RPC"; AUTH="Authorization: Bearer $TOK"
for i in $(seq 1 50); do grep -qiE "blocks dir|listening|rpc.*(bound|listen)" "$NLOG" && break; sleep 0.5; done
if ! grep -q "$ROOT/blocks" "$NLOG"; then echo "[FATAL] node storage NOT isolated - aborting"; grep -iE "blocks|data.dir|\.irium" "$NLOG" | head; exit 9; fi
echo "node pid=$NPID isolated OK"

echo "############ isolated wallet -> miner identity (addr + secret) ############"
curl -s -X POST -H "$AUTH" -H 'Content-Type: application/json' -d '{"passphrase":"dptest123"}' "$B/wallet/create" >/dev/null 2>&1
curl -s -X POST -H "$AUTH" -H 'Content-Type: application/json' -d '{"passphrase":"dptest123"}' "$B/wallet/unlock" >/dev/null 2>&1
MINER_ADDR=$(curl -s -H "$AUTH" "$B/wallet/receive" 2>/dev/null | grep -oE '"address"[: ]*"[^"]+"' | head -1 | sed -E 's/.*"address"[: ]*"([^"]+)".*/\1/')
WIF=$(curl -s -H "$AUTH" "$B/wallet/export_wif?address=$MINER_ADDR" 2>/dev/null | grep -oE '"wif"[: ]*"[^"]+"' | head -1 | sed -E 's/.*"wif"[: ]*"([^"]+)".*/\1/')
MINER_SECRET=$("$WIF2HEX" "$WIF" 2>/dev/null)
if [ -z "$MINER_ADDR" ] || [ ${#MINER_SECRET} -ne 64 ]; then echo "[FATAL] miner identity failed addr=$MINER_ADDR seclen=${#MINER_SECRET}"; exit 1; fi
echo "miner addr=$MINER_ADDR secret6=${MINER_SECRET:0:6}..."

echo "############ STAGE 1b: pool up (stage_d ON, native_rewardable ON, delegation server) ############"
( cd "$D" && env "${GATE[@]}" \
  IRIUM_RPC_BASE="$B" IRIUM_RPC_TOKEN=$TOK \
  STRATUM_BIND=127.0.0.1:$STRAT \
  IRIUM_STRATUM_POAWX=1 IRIUM_STRATUM_NATIVE_REWARDABLE_ENABLED=1 \
  IRIUM_POAWX_STAGE_D_PRODUCTION=1 IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS=1 \
  IRIUM_POAWX_PRODUCER_TRACE=1 \
  STRATUM_DEFAULT_DIFF=0.0001 IRIUM_STRATUM_VARDIFF_ENABLED=0 \
  IRIUM_POAWX_DELEGATION_BIND=127.0.0.1:$DELEG \
  IRIUM_POAWX_DELEGATE_KEY_PATH="$ROOT/pool_delegate.hex" \
  IRIUM_POAWX_PROPOSER_KEY_FILE="$ROOT/pool_proposer.hex" \
  IRIUM_POAWX_DELEGATIONS_PATH="$ROOT/pool_delegations.json" \
  "$POOL" >"$PLOG" 2>&1 ) &
PPID=$!; echo "$PPID" > "$ROOT/pool.pid"
DB="http://127.0.0.1:$DELEG"
sleep 5
echo "--- pool startup tail ---"; tail -10 "$PLOG"
echo "--- /poawx/pool-identity (D1: expect proposer_pubkey advertised) ---"
POOLID=$(curl -s "$DB/poawx/pool-identity"); echo "$POOLID"
echo "$POOLID" | grep -q proposer_pubkey && echo "[OK] D1 advertises proposer_pubkey" || echo "[WARN] no proposer_pubkey advertised"

echo "############ STAGE 2: register miner delegation with the pool ############"
env "${GATE[@]}" IRIUM_POAWX_DELEGATION_SECRET_HEX="$MINER_SECRET" \
  "$WALLET" poawx-register --pool "$DB" --addr "$MINER_ADDR" --worker rig1 --expiry-height 1000000 --fee-bps 0 >"$RLOG" 2>&1
echo "--- register result ---"; tail -15 "$RLOG"
echo "--- /poawx/delegation-status?pkh (delegation stored?) ---"
curl -s "$DB/poawx/delegation-status"; echo

echo "############ STAGE 3: delegated miner mines the pool jobs ############"
env "${GATE[@]}" \
  IRIUM_STRATUM_URL="127.0.0.1:$STRAT" \
  IRIUM_STRATUM_USER="$MINER_ADDR.rig1" IRIUM_STRATUM_PASS=x \
  "$MINER" >"$MLOG" 2>&1 &
MPID=$!; echo "$MPID" > "$ROOT/miner.pid"
echo "miner pid=$MPID mining (up to 150s, stop at first accepted block)..."
BEST=0
for i in $(seq 1 50); do
  sleep 3
  H=$(curl -s -H "$AUTH" "$B/rpc/getblocktemplate" 2>/dev/null | grep -oE '"height"[: ]*[0-9]+' | grep -oE '[0-9]+' | head -1); H=${H:-1}
  [ $((H-1)) -gt $BEST ] && BEST=$((H-1))
  [ "$BEST" -ge 1 ] && { echo "block accepted -> tip=$BEST at ~$((i*3))s"; break; }
done
kill $MPID 2>/dev/null; rm -f "$ROOT/miner.pid"

echo "############ RESULTS ############"
echo "--- pool: mode-1 / multi-role / submit evidence ---"
grep -iE "mode-1|multi-role|stage_d|submit_block_extended|accepted|proposer|delegation|reject|error" "$PLOG" | tail -20
echo "--- miner: stratum evidence ---"
grep -iE "stratum|subscribe|notify|share|submit|accepted|reject|error" "$MLOG" | tail -15
echo "--- node: block acceptance ---"
grep -iE "submit_block_extended|accepted|connect_block|height|reject" "$NLOG" | tail -15
echo "--- chain tip + coinbase payout check ---"
TIP=$(curl -s -H "$AUTH" "$B/rpc/getblocktemplate" 2>/dev/null | grep -oE '"height"[: ]*[0-9]+' | grep -oE '[0-9]+' | head -1); TIP=$((${TIP:-1}-1))
echo "chain tip height: $TIP (miner addr $MINER_ADDR should own the PRIMARY coinbase output)"
if [ "$TIP" -ge 1 ]; then curl -s -H "$AUTH" "$B/rpc/block?height=$TIP" 2>/dev/null | head -c 1200; echo; fi
echo "############ DONE (teardown on exit) ############"
