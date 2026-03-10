#!/usr/bin/env bash
set -euo pipefail

PILOT_BRANCH="${PILOT_BRANCH:-testing-codes-before-merging}"
EU_HOST="${EU_HOST:-157.173.116.134}"
EU_USER="${EU_USER:-irium}"
EU_SSH_KEY="${EU_SSH_KEY:-/home/irium/.ssh/id_ed25519_pilot}"
PILOT_REPO="${PILOT_REPO:-/home/irium/irium-pilot}"
ALLOW_DIRTY="${ALLOW_DIRTY:-0}"
PIN_COMMIT="${PIN_COMMIT:-}"

require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1" >&2; exit 1; }; }
require_cmd git
require_cmd ssh
SSH_OPTS=(-i "$EU_SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new)

cd /home/irium/irium-phase3
if [[ "$ALLOW_DIRTY" != "1" ]] && [[ -n "$(git status --porcelain)" ]]; then
  echo "refusing deploy: dirty tree on code-master (set ALLOW_DIRTY=1 to override)" >&2
  exit 1
fi

git checkout "$PILOT_BRANCH"
git pull --ff-only origin "$PILOT_BRANCH"
git push origin "$PILOT_BRANCH"

COMMIT="${PIN_COMMIT:-$(git rev-parse HEAD)}"
echo "deploying commit: $COMMIT"

if [[ ! -d "$PILOT_REPO/.git" ]]; then
  git clone https://github.com/iriumlabs/irium.git "$PILOT_REPO"
fi

git -C "$PILOT_REPO" fetch origin
git -C "$PILOT_REPO" switch "$PILOT_BRANCH" || git -C "$PILOT_REPO" switch -c "$PILOT_BRANCH" --track "origin/$PILOT_BRANCH"
git -C "$PILOT_REPO" checkout "$COMMIT"

source "$HOME/.cargo/env" 2>/dev/null || true
cargo build --release --bin iriumd --bin irium-miner --manifest-path "$PILOT_REPO/Cargo.toml"
cargo build --manifest-path "$PILOT_REPO/tools/atomic-swap-coordinator/Cargo.toml" --release

sudo mkdir -p /etc/irium-pilot
sudo install -m 0644 "$PILOT_REPO/systemd/irium-pilot-node.service" /etc/systemd/system/irium-pilot-node.service
sudo install -m 0644 "$PILOT_REPO/systemd/irium-pilot-coordinator.service" /etc/systemd/system/irium-pilot-coordinator.service
if [[ ! -f /etc/irium-pilot/node.env ]]; then
  sudo install -m 0644 "$PILOT_REPO/configs/pilot/vps-node.env.example" /etc/irium-pilot/node.env
fi
if [[ ! -f /etc/irium-pilot/coordinator.env ]]; then
  sudo install -m 0644 "$PILOT_REPO/configs/pilot/vps-coordinator.env.example" /etc/irium-pilot/coordinator.env
fi
sudo systemctl daemon-reload
sudo systemctl enable irium-pilot-node irium-pilot-coordinator
sudo systemctl restart irium-pilot-node irium-pilot-coordinator

ssh "${SSH_OPTS[@]}" "${EU_USER}@${EU_HOST}" "set -euo pipefail
  BR='$PILOT_BRANCH'
  COMMIT='$COMMIT'
  REPO='$PILOT_REPO'
  if [[ ! -d \"\$REPO/.git\" ]]; then git clone https://github.com/iriumlabs/irium.git \"\$REPO\"; fi
  git -C \"\$REPO\" fetch origin
  git -C \"\$REPO\" switch \"\$BR\" || git -C \"\$REPO\" switch -c \"\$BR\" --track \"origin/\$BR\"
  git -C \"\$REPO\" checkout \"\$COMMIT\"
  source \"\$HOME/.cargo/env\" 2>/dev/null || true
  cargo build --release --bin iriumd --bin irium-miner --manifest-path \"\$REPO/Cargo.toml\"
  sudo mkdir -p /etc/irium-pilot
  sudo install -m 0644 \"\$REPO/systemd/irium-pilot-node.service\" /etc/systemd/system/irium-pilot-node.service
  if [[ ! -f /etc/irium-pilot/node.env ]]; then
    sudo install -m 0644 \"\$REPO/configs/pilot/eu-node.env.example\" /etc/irium-pilot/node.env
  fi
  sudo systemctl daemon-reload
  sudo systemctl enable irium-pilot-node
  sudo systemctl restart irium-pilot-node
"

VPS_COMMIT=$(git -C "$PILOT_REPO" rev-parse HEAD)
EU_COMMIT=$(ssh "${SSH_OPTS[@]}" "${EU_USER}@${EU_HOST}" "git -C '$PILOT_REPO' rev-parse HEAD")
[[ "$VPS_COMMIT" == "$EU_COMMIT" ]] || { echo "commit mismatch: vps=$VPS_COMMIT eu=$EU_COMMIT" >&2; exit 1; }

echo "deploy complete"
echo "vps_commit=$VPS_COMMIT"
echo "eu_commit=$EU_COMMIT"
