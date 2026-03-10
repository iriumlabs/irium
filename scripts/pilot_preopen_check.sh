#!/usr/bin/env bash
set -euo pipefail

EU_HOST="${EU_HOST:-157.173.116.134}"
EU_USER="${EU_USER:-irium}"
EU_SSH_KEY="${EU_SSH_KEY:-/home/irium/.ssh/id_ed25519_pilot}"
PILOT_REPO="${PILOT_REPO:-/home/irium/irium-pilot}"
SSH_OPTS=(-i "$EU_SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new)

VPS_COMMIT=$(git -C "$PILOT_REPO" rev-parse HEAD)
EU_COMMIT=$(ssh "${SSH_OPTS[@]}" "${EU_USER}@${EU_HOST}" "git -C '$PILOT_REPO' rev-parse HEAD")
BRANCH=$(git -C /home/irium/irium-phase3 rev-parse --abbrev-ref HEAD)

echo "branch=$BRANCH"
echo "vps_commit=$VPS_COMMIT"
echo "eu_commit=$EU_COMMIT"
[[ "$VPS_COMMIT" == "$EU_COMMIT" ]] || { echo "FAIL commit parity"; exit 1; }

systemctl is-active --quiet irium-pilot-node || { echo "FAIL vps pilot node"; exit 1; }
systemctl is-active --quiet irium-pilot-coordinator || { echo "FAIL vps pilot coordinator"; exit 1; }
ssh "${SSH_OPTS[@]}" "${EU_USER}@${EU_HOST}" "systemctl is-active --quiet irium-pilot-node" || { echo "FAIL eu pilot node"; exit 1; }

curl -fsS http://127.0.0.1:39093/healthz >/dev/null || { echo "FAIL coordinator health"; exit 1; }
curl -fsS http://127.0.0.1:58480/status >/dev/null || { echo "FAIL vps status"; exit 1; }
curl -fsS http://157.173.116.134:58481/status >/dev/null || { echo "FAIL eu status"; exit 1; }

if ps -eo pid,args | grep -E '/tmp/htlc-tcbm/target/release/iriumd|iriumd \(deleted\)' | grep -v grep >/dev/null; then
  echo "FAIL tmp runtime on vps"; exit 1
fi
if ssh "${SSH_OPTS[@]}" "${EU_USER}@${EU_HOST}" "ps -eo pid,args | grep -E '/tmp/htlc-tcbm/target/release/iriumd|iriumd \\(deleted\\)' | grep -v grep >/dev/null"; then
  echo "FAIL tmp runtime on eu"; exit 1
fi

echo "PASS pilot preopen checks"
