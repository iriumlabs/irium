# Topology (Planned)

Planned internal devnet topology. **Not deployed in Phase 39.** All inter-host P2P is
**approval-gated** (`OWNER_APPROVAL_CHECKLIST.md`); the default first step is **loopback-only** on a
single host before any cross-host networking.

## Nodes

| Role | Host | RPC | P2P | Notes |
|---|---|---|---|---|
| Node A (local) | Windows local | **loopback-only** (`127.0.0.1`) | local | primary dev/control node |
| Node B (VPS-1) | VPS-1 (internal devnet) | loopback-only | source-restricted (approval-gated) | spoke/hub per approval |
| Node C (VPS-2) | VPS-2 (internal devnet) | loopback-only | source-restricted (approval-gated) | spoke |
| Node D (optional) | Windows local-only observer | loopback-only | local | only if safe; observer/no-mine |

## Networking rules

- **RPC: loopback-only on every node.** No public RPC.
- **No public stratum. No external miners.**
- **Cross-host P2P only if explicitly approved later**, and then **source-restricted** (allow only the
  specific peer IPs on the chosen devnet P2P port), TCP only, no UDP.
- Default plan: validate as much as possible **loopback-only on one host first**, then expand to VPS
  nodes only after owner approval of firewall/ports.

## Placeholders (owner fills before execution)

| Item | Value |
|---|---|
| Windows current public IP | `[FILL — re-check at execution time; it changes]` |
| VPS-1 IP | `[FILL]` |
| VPS-2 IP | `[FILL]` |
| Devnet P2P port (A/B/C) | `[FILL — distinct from any mainnet/pool ports]` |
| Devnet RPC port (A/B/C) | `[FILL — loopback-only]` |
| Devnet status port (A/B/C) | `[FILL]` |
| Hub addnode target | `[FILL — e.g. VPS-1 IP:devnet-P2P-port]` |
| Windows storage root | `[see STORAGE_AND_PORT_PLAN.md]` |
| VPS-1 storage root | `[see STORAGE_AND_PORT_PLAN.md]` |
| VPS-2 storage root | `[see STORAGE_AND_PORT_PLAN.md]` |
| Log directory (per host) | `[FILL — under the storage root, not default]` |

## Safety notes

- Devnet ports must **not** collide with any running mainnet node or production pool/stratum on the same
  host (inventory first — `SAFETY_BOUNDARIES.md`).
- The Windows public IP changes between sessions; re-verify it at execution time and update any
  source-restricted firewall rule accordingly (only if cross-host P2P is approved).
- This file is a plan; no IPs/ports are committed as real values here.
