#!/usr/bin/env bash
set -euo pipefail

EU_HOST="${EU_HOST:-157.173.116.134}"
EU_USER="${EU_USER:-irium}"
EU_SSH_KEY="${EU_SSH_KEY:-/home/irium/.ssh/id_ed25519_pilot}"
PILOT_REPO="${PILOT_REPO:-/home/irium/irium-pilot}"
VPS_NODE_STATUS_URL="${VPS_NODE_STATUS_URL:-http://127.0.0.1:58480/status}"
EU_NODE_STATUS_URL="${EU_NODE_STATUS_URL:-http://157.173.116.134:58481/status}"
COORD_HEALTH_URL="${COORD_HEALTH_URL:-http://127.0.0.1:39093/healthz}"
SSH_OPTS=(-i "$EU_SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new)

echo "[1] commit parity"
VPS_COMMIT=$(git -C "$PILOT_REPO" rev-parse HEAD)
EU_COMMIT=$(ssh "${SSH_OPTS[@]}" "${EU_USER}@${EU_HOST}" "git -C '$PILOT_REPO' rev-parse HEAD")
echo "vps=$VPS_COMMIT"
echo "eu=$EU_COMMIT"
[[ "$VPS_COMMIT" == "$EU_COMMIT" ]] || { echo "FAIL: commit mismatch"; exit 1; }

echo "[2] services"
systemctl is-active --quiet irium-pilot-node || { echo "FAIL: irium-pilot-node inactive on vps"; exit 1; }
systemctl is-active --quiet irium-pilot-coordinator || { echo "FAIL: irium-pilot-coordinator inactive on vps"; exit 1; }
ssh "${SSH_OPTS[@]}" "${EU_USER}@${EU_HOST}" "systemctl is-active --quiet irium-pilot-node" || { echo "FAIL: irium-pilot-node inactive on eu"; exit 1; }

echo "[3] health endpoints"
curl -fsS "$COORD_HEALTH_URL" >/dev/null || { echo "FAIL: coordinator health"; exit 1; }
curl -fsS "$VPS_NODE_STATUS_URL" >/dev/null || { echo "FAIL: vps pilot node status"; exit 1; }
curl -fsS "$EU_NODE_STATUS_URL" >/dev/null || { echo "FAIL: eu pilot node status"; exit 1; }

echo "[4] runtime path checks"
VPS_EXE=$(readlink -f /proc/$(ss -lntp | awk '/:58400/{print $NF}' | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -n1)/exe)
EU_EXE=$(ssh "${SSH_OPTS[@]}" "${EU_USER}@${EU_HOST}" "readlink -f /proc/\$(ss -lntp | awk '/:58401/{print \$NF}' | sed -n 's/.*pid=\\([0-9]*\\).*/\\1/p' | head -n1)/exe")
echo "vps_exe=$VPS_EXE"
echo "eu_exe=$EU_EXE"
[[ "$VPS_EXE" == "$PILOT_REPO/target/release/iriumd" ]] || { echo "FAIL: vps not running repo pilot binary"; exit 1; }
[[ "$EU_EXE" == "$PILOT_REPO/target/release/iriumd" ]] || { echo "FAIL: eu not running repo pilot binary"; exit 1; }

echo "[5] no /tmp runtime"
if pgrep -fa '/tmp/htlc-tcbm/target/release/iriumd|iriumd \(deleted\)' >/dev/null; then
  echo "FAIL: vps has /tmp or deleted iriumd runtime"
  exit 1
fi
if ssh "${SSH_OPTS[@]}" "${EU_USER}@${EU_HOST}" "pgrep -fa '/tmp/htlc-tcbm/target/release/iriumd|iriumd \\(deleted\\)' >/dev/null"; then
  echo "FAIL: eu has /tmp or deleted iriumd runtime"
  exit 1
fi

echo "[6] mainnet activation safety"
if systemctl show iriumd -p Environment | grep -q 'IRIUM_HTLCV1_ACTIVATION_HEIGHT='; then
  echo "FAIL: production iriumd environment has HTLC activation set"
  exit 1
fi
if ssh "${SSH_OPTS[@]}" "${EU_USER}@${EU_HOST}" "systemctl show iriumd -p Environment | grep -q 'IRIUM_HTLCV1_ACTIVATION_HEIGHT='"; then
  echo "FAIL: EU production iriumd environment has HTLC activation set"
  exit 1
fi

echo "PASS: pilot hosts verification succeeded"
