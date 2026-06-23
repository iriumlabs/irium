# Command Dry-Run Checklist (NON-EXECUTED)

Verify each command/path **without running anything that starts nodes**. This prepares the future
execution phase; **no node is started in Phase 40.** Confirm exact flags against the agreed build at
execution time.

| # | Item to verify | Verified? | Notes |
|---|---|---|---|
| 1 | Build command: `cargo build --release --bin iriumd --bin poawx-live-proof-harness --bin poawx-sim` | ☐ | builds, no run |
| 2 | Storage-root creation targets only the isolated `phase40-devnet\…` paths | ☐ | never default/`/tmp`/`.irium` |
| 3 | Node start command placeholders resolved (data-dir, rpc, p2p, pidfile flags) | ☐ | exact flags TBD; **do not run** |
| 4 | Pidfile paths are inside each node's isolated root | ☐ | `…\nodeA\node.pid` etc. |
| 5 | Log paths are inside each node's isolated root's log dir | ☐ | |
| 6 | RPC bind is loopback-only (`127.0.0.1:<port>`) for every node | ☐ | no public RPC |
| 7 | Peer-connect command targets the approved addnode (only if cross-host approved) | ☐ | source-restricted |
| 8 | Stop command uses **exact pidfile PIDs only** | ☐ | never kill by name; never mainnet PIDs |
| 9 | Cleanup command deletes **exact paths only** (the Phase 40 roots) | ☐ | never a parent/default path |
| 10 | Gate env is a single pinned profile, identical across nodes | ☐ | activation+required+dominance window/lookback |

## Rules

- This checklist is for **verification only**. The build command (item 1) may be run to confirm it
  compiles, but **no node-start / mining / P2P / RPC command is run** in Phase 40.
- Any command that would start a node, open a port, or change a firewall rule is **out of scope** here
  and belongs to the owner-approved execution phase.
- Re-verify the Windows public IP and any source-restricted rule immediately before cross-host execution.
