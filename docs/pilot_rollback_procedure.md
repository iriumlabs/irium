# Pilot Rollback Procedure

## Inputs
- rollback commit: `<GOOD_COMMIT>`
- branch: `testing-codes-before-merging`
- VPS host and EU host SSH access

## VPS rollback
```bash
cd /home/irium/irium-pilot
git fetch origin
git checkout <GOOD_COMMIT>
source "$HOME/.cargo/env" 2>/dev/null || true
cargo build --release --bin iriumd --bin irium-miner
cargo build --manifest-path tools/atomic-swap-coordinator/Cargo.toml --release
sudo systemctl restart irium-pilot-node irium-pilot-coordinator
```

## EU rollback
```bash
cd /home/irium/irium-pilot
git fetch origin
git checkout <GOOD_COMMIT>
source "$HOME/.cargo/env" 2>/dev/null || true
cargo build --release --bin iriumd --bin irium-miner
sudo systemctl restart irium-pilot-node
```

## Verify rollback
```bash
git -C /home/irium/irium-pilot rev-parse HEAD
systemctl is-active irium-pilot-node
curl -fsS http://127.0.0.1:58480/status >/dev/null   # VPS
curl -fsS http://127.0.0.1:58481/status >/dev/null   # EU
```

## Safety checks
- production `iriumd.service` unchanged
- no `/tmp` runtime process remains
- pilot commit hash matches intended rollback commit on both hosts
