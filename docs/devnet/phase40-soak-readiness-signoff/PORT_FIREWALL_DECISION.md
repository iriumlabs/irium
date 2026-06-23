# Port & Firewall Decision

Posture for ports and firewall. **No firewall changes are made in Phase 40.** Decision pending.

## Rules

- **No firewall changes in Phase 40** (this is a docs/sign-off phase).
- If cross-host P2P is later approved (Option B/C stage 2): **source-restricted TCP only** — allow only
  the exact peer IPs on the single chosen devnet P2P port.
- **No UDP.**
- **No public RPC.** RPC is loopback-only (`127.0.0.1`) on every node.
- **No public stratum.**
- **No `0.0.0.0/0`** / any-source rules. Ever.
- **Windows dynamic IP must be re-checked immediately before any cross-host execution** and any
  source-restricted rule updated to the current IP (it changes between sessions).

## Port / rule table (placeholders; fill at execution; avoid mainnet/pool collisions)

| Node | P2P port | RPC (loopback) | Status port | Notes |
|---|---|---|---|---|
| A (Windows) | `[FILL]` | `127.0.0.1:[FILL]` | `[FILL]` | |
| B (VPS-1) | `[FILL]` | `127.0.0.1:[FILL]` | `[FILL]` | |
| C (VPS-2) | `[FILL]` | `127.0.0.1:[FILL]` | `[FILL]` | |

| Firewall rule (only if approved) | Host | Port | Source (exact IPs) | Approved? | Added? | Removed? |
|---|---|---|---|---|---|---|
| Devnet P2P allow | VPS-1 | `[P2P]` | `[Windows IP, VPS-2 IP]` | ☐ | ☐ | ☐ |
| Devnet P2P allow | VPS-2 | `[P2P]` | `[Windows IP, VPS-1 IP]` | ☐ | ☐ | ☐ |

## Rule-removal checklist (cleanup)

- [ ] Remove each temporary source-restricted devnet P2P rule added for this soak (exact rule only).
- [ ] Confirm no `0.0.0.0/0` / public rule was ever added.
- [ ] Confirm no UDP / public RPC / public stratum was exposed.
- [ ] Confirm all other firewall rules unchanged.
- [ ] Re-verify mainnet/prod reachability rules untouched.

Owner performs any sudo/firewall action manually; passwords typed into a real terminal, never echoed,
stored, or passed as arguments.
