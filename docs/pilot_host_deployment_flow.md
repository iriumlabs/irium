# Pilot Host Deployment Flow (Master -> GitHub -> Hosts)

This flow is mandatory for BTC testnet <-> IRM pilot hosts.

## Rules
- `irium-vps` is the only code master.
- All changes are committed and pushed from `irium-vps`.
- All other hosts (`irium-eu`, etc.) only run code cloned/pulled from GitHub.
- Do not run long-lived services from `/tmp` build directories.
- Do not run deleted/stale binaries.

## 1) Build and push from irium-vps
```bash
ssh irium-vps '
  set -e
  cd ~/irium-phase3
  git checkout testing-codes-before-merging
  git pull --ff-only origin testing-codes-before-merging
  source "$HOME/.cargo/env" 2>/dev/null || true
  cargo build --release --bin iriumd --bin irium-miner
  git add <changed-files>
  git commit -m "🔧 <message>"
  git push origin testing-codes-before-merging
  git rev-parse HEAD
'
```

## 2) Pull and build on irium-eu
```bash
ssh irium-eu '
  set -e
  cd ~/irium
  git fetch origin
  git switch testing-codes-before-merging || git switch -c testing-codes-before-merging --track origin/testing-codes-before-merging
  git pull --ff-only origin testing-codes-before-merging
  source "$HOME/.cargo/env" 2>/dev/null || true
  cargo build --release --bin iriumd --bin irium-miner
  git rev-parse HEAD
'
```

## 3) Restart trial runtime safely on irium-eu
```bash
ssh irium-eu '
  set -e
  pkill -f "/tmp/htlc" || true
  pkill -f "IRIUM_NODE_PORT=58401" || true
  cd ~/irium
  nohup env \
    IRIUM_NODE_CONFIG=/home/irium/.htlc-devtrial/node2.json \
    IRIUM_WALLET_FILE=/home/irium/.htlc-devtrial/node2/wallet.core.json \
    IRIUM_HTLCV1_ACTIVATION_HEIGHT=5 \
    IRIUM_NODE_HOST=0.0.0.0 \
    IRIUM_STATUS_HOST=0.0.0.0 \
    IRIUM_NODE_PORT=58401 \
    IRIUM_STATUS_PORT=58481 \
    IRIUM_RPC_TOKEN=trialtoken \
    ./target/release/iriumd \
    > /home/irium/.htlc-devtrial/logs/node2.log 2>&1 &
  sleep 2
  ss -lntp | egrep ":58401|:58481"
'
```

## 4) Verify commit hash and binary path on both hosts
```bash
ssh irium-vps 'cd ~/irium-phase3 && git rev-parse HEAD'
ssh irium-eu  'cd ~/irium && git rev-parse HEAD'

ssh irium-vps 'p=$(pgrep -f "IRIUM_NODE_PORT=58400|target/release/iriumd" | head -n1); readlink -f /proc/$p/exe; pwdx $p'
ssh irium-eu  'p=$(ss -lntp | awk "/:58401/{print \$NF}" | sed -n "s/.*pid=\([0-9]*\).*/\1/p" | head -n1); readlink -f /proc/$p/exe; pwdx $p'
```

Expected:
- both hosts report the same commit hash (from GitHub branch)
- runtime executable path is under repo checkout (`~/irium.../target/release/iriumd`)
- no `/tmp` runtime process remains

## Standardized pilot ops artifacts
- Deploy/update script (run on code-master VPS): `scripts/deploy_pilot_from_vps.sh`
- Host verification script (run on code-master VPS): `scripts/verify_pilot_hosts.sh`
- Service layout: `docs/pilot_service_layout.md`
- Rollback: `docs/pilot_rollback_procedure.md`
- Branch policy: `docs/pilot_branch_strategy.md`

## Standardized pilot ops artifacts
- Deploy/update script (run on code-master VPS): `scripts/deploy_pilot_from_vps.sh`
- Host verification script (run on code-master VPS): `scripts/verify_pilot_hosts.sh`
- Service layout: `docs/pilot_service_layout.md`
- Rollback: `docs/pilot_rollback_procedure.md`
- Branch policy: `docs/pilot_branch_strategy.md`
