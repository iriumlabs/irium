# Safety Boundaries

Non-negotiable boundaries for the (future) soak execution. Plan only — nothing is executed in Phase 39.

## Mainnet / prod protection

- **Inventory mainnet processes before any test** (per host): record the exact PIDs of running mainnet
  `iriumd`, any production pool/stratum, and wallet processes. Keep this inventory for the duration.
- **Never stop, restart, or signal a mainnet/prod process.** Devnet nodes run as separate processes with
  separate storage and ports.
- Verify mainnet is still running **before and after** the soak (and after cleanup).

## Network

- **No broad firewall rules.** If cross-host P2P is approved, add only **source-restricted, single-port,
  TCP** allow rules for the specific peer IPs; remove them at cleanup.
- **No UDP.** **No public RPC. No public stratum. No external miners.**
- RPC loopback-only on every node.

## Storage

- **No default storage.** **No `/tmp`. No `~/.irium`. No `%USERPROFILE%\.irium`.**
- Use only the explicit isolated storage roots in `STORAGE_AND_PORT_PLAN.md`; the node binary's
  storage-isolation guard must reject default/`/tmp`/`.irium` paths.

## Credentials

- **No real wallets. No real private keys.** Devnet/dev keys only (never printed/committed).
- No sudo/firewall actions without explicit owner approval; passwords are typed by the owner into a real
  terminal prompt, never passed as arguments, echoed, or stored.

## Cleanup

- **Exact-PID-only** process termination (stop devnet nodes by their own pidfiles); never kill by name,
  never touch mainnet/pool/wallet PIDs.
- **Exact-path-only** deletion (remove only the Phase 39 storage roots/log dirs); never `rm -rf` a parent
  or a default path.
- Preserve logs (copy out) **before** deleting storage.

## Abort / rollback

- Abort immediately on any divergence, unexpected public-port exposure, mainnet-process disturbance, or
  irreversible-cleanup risk (`ABORT_AND_ROLLBACK.md`).
- On abort: stop devnet nodes by pidfile, preserve logs, remove any temporary firewall rule that was
  created, verify mainnet still running, and report partial results.
