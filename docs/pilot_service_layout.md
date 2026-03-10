# Pilot Service Layout

## Standard paths
- VPS pilot checkout: `/home/irium/irium-pilot`
- EU pilot checkout: `/home/irium/irium-pilot`

No long-lived pilot runtime is allowed from `/tmp`.

## Systemd units
- `irium-pilot-node.service`
  - WorkingDirectory: `/home/irium/irium-pilot`
  - ExecStart: `/home/irium/irium-pilot/target/release/iriumd`
  - EnvironmentFile: `/etc/irium-pilot/node.env`
- `irium-pilot-coordinator.service` (VPS only)
  - WorkingDirectory: `/home/irium/irium-pilot/tools/atomic-swap-coordinator`
  - ExecStart: `/home/irium/irium-pilot/tools/atomic-swap-coordinator/target/release/atomic-swap-coordinator`
  - EnvironmentFile: `/etc/irium-pilot/coordinator.env`

## Host roles
- VPS: pilot Irium node + coordinator
- EU: pilot Irium node

## Logs
- `journalctl -u irium-pilot-node -f`
- `journalctl -u irium-pilot-coordinator -f`
