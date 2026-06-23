# Storage & Port Plan

Explicit, isolated storage roots and a port-allocation plan. Plan only — nothing created in Phase 39.
**No default storage, no `/tmp`, no `~/.irium`, no `%USERPROFILE%\.irium`.**

## Storage roots (isolated; created only at execution time)

| Host | Storage root | Log dir |
|---|---|---|
| Windows (Node A) | `C:\Users\Ibrahim\irium-poawx-windows-test\phase39-devnet\nodeA\` | `…\phase39-devnet\nodeA\logs\` |
| VPS-1 (Node B) | `/home/irium/phase39-devnet/nodeB/` | `/home/irium/phase39-devnet/nodeB/logs/` |
| VPS-2 (Node C) | `/home/irium/phase39-devnet/nodeC/` | `/home/irium/phase39-devnet/nodeC/logs/` |
| Windows observer (Node D, optional) | `C:\Users\Ibrahim\irium-poawx-windows-test\phase39-devnet\nodeD\` | `…\nodeD\logs\` |

Rules:
- Each node gets its **own** root under `phase39-devnet/`; never shared, never default.
- The node's storage-isolation guard must **reject** default/`/tmp`/home-`.irium` paths (fail closed).
- Pidfiles live under each node's root (e.g., `…\nodeA\node.pid`) for exact-PID cleanup.

## Port allocation (placeholders; fill at execution; avoid mainnet/pool collisions)

| Node | P2P | RPC (loopback) | Status |
|---|---|---|---|
| A (Windows) | `[FILL]` | `127.0.0.1:[FILL]` | `[FILL]` |
| B (VPS-1) | `[FILL]` | `127.0.0.1:[FILL]` | `[FILL]` |
| C (VPS-2) | `[FILL]` | `127.0.0.1:[FILL]` | `[FILL]` |
| D (observer) | `[FILL/local]` | `127.0.0.1:[FILL]` | `[FILL]` |

- Verify none of these collide with a running mainnet node or production pool/stratum on the same host
  (`SAFETY_BOUNDARIES.md` inventory).

## Firewall approval table (only if cross-host P2P approved)

| Rule | Host | Port | Source (restricted) | Approved? | Added? | Removed at cleanup? |
|---|---|---|---|---|---|---|
| Devnet P2P allow | VPS-1 | `[P2P]` | `[Windows IP, VPS-2 IP]` | ☐ | ☐ | ☐ |
| Devnet P2P allow | VPS-2 | `[P2P]` | `[Windows IP, VPS-1 IP]` | ☐ | ☐ | ☐ |

- TCP only, single port, source-restricted to exact peer IPs. No UDP. No broad/any-source rules.

## Cleanup table

| Host | Stop (pidfile) | Delete (exact path) | Logs preserved to | Done? |
|---|---|---|---|---|
| A | `…\nodeA\node.pid` | `…\phase39-devnet\nodeA\` | `[archive path]` | ☐ |
| B | `…/nodeB/node.pid` | `/home/irium/phase39-devnet/nodeB/` | `[archive path]` | ☐ |
| C | `…/nodeC/node.pid` | `/home/irium/phase39-devnet/nodeC/` | `[archive path]` | ☐ |
| D | `…\nodeD\node.pid` | `…\phase39-devnet\nodeD\` | `[archive path]` | ☐ |

- Preserve logs **before** deleting any storage root. Never delete a parent directory.
