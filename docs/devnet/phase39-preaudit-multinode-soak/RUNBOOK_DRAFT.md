# Runbook (DRAFT — NOT EXECUTED IN PHASE 39)

> **Draft command sequence only.** Do **not** run any of this in Phase 39. Exact binary flags are
> `[placeholders]` to be confirmed against the agreed build before a separate, owner-approved execution
> phase. No dangerous commands are included; all storage paths are the isolated Phase 39 roots.

## 0. Pre-checks
Complete `PRECHECK_CHECKLIST.md` and `OWNER_APPROVAL_CHECKLIST.md` first. Inventory mainnet PIDs. Also
require the Phase 40 go/no-go to be **Go** and `FINAL_OWNER_APPROVAL_TEMPLATE.md` signed
(`docs/devnet/phase40-soak-readiness-signoff/EXECUTION_GO_NO_GO.md`).

## 1. Build binaries (from the agreed commit)
```
cargo build --release --bin iriumd --bin poawx-live-proof-harness --bin poawx-sim
```

## 2. Prepare storage roots (isolated; per host)
```
# create the explicit Phase 39 roots only (never default/.irium/tmp)
#   Windows: C:\Users\Ibrahim\irium-poawx-windows-test\phase39-devnet\nodeA\
#   VPS:     /home/irium/phase39-devnet/nodeB|nodeC/
```

## 3. Gate env (identical on every node)
```
# Set IRIUM_NETWORK=devnet and the Phase 28–34 activation/required flags + dominance window/lookback
# to a SINGLE pinned profile (see PRECHECK item 11–12). [exact vars confirmed at execution time]
```

## 4. Start Node A (Windows, loopback RPC)
```
iriumd [--network devnet] [--data-dir <nodeA root>] [--rpc 127.0.0.1:<port>] [--p2p <port>] \
       [--pidfile <nodeA>\node.pid]   # exact flags TBD
```

## 5. Start Node B (VPS-1) and Node C (VPS-2)
```
# same pattern, each with its own isolated root + ports + pidfile; RPC loopback-only
# cross-host P2P ONLY if approved (source-restricted) — otherwise validate loopback-only on A first
```

## 6. Connect peers (only if cross-host P2P approved)
```
# point spokes at the hub via the agreed addnode target (VPS-1 IP:devnet-P2P-port)
# P2P timing env (optional, non-consensus) may speed convergence as in prior soaks
```

## 7. Run the local proof harness (all gate env set so built sections match the node)
```
poawx-live-proof-harness [gate env identical to node] [--rpc 127.0.0.1:<nodeA rpc>]   # flags TBD
```

## 8. Mine / submit N blocks
```
# produce all-gates blocks (e.g., 20) via the harness; submit to Node A
```

## 9. Verify convergence
```
# query each node's status (loopback RPC): height, tip hash, irx1 root must match across A/B/C
```

## 10. Fresh-wipe sync
```
# fully wipe Node C's storage root, restart brand-new, confirm it syncs to tip (incl. served admissions)
```

## 11. Cold restart / replay
```
# restart a node on its EXISTING storage; confirm it reconstructs all derived state and reaches tip
```

## 12. Controlled reorg scenario (only if safe + approved)
```
# drive a reorg whose fork point is below the finalized checkpoint; confirm it is REJECTED
```

## 13. Stop nodes (exact pidfiles)
```
# stop each devnet node by its OWN pidfile only; never touch mainnet/pool/wallet PIDs
```

## 14. Cleanup (exact paths)
```
# preserve logs first, then delete ONLY the Phase 39 storage roots; remove any temp firewall rule
# verify mainnet still running
```

## Notes
- Every step has exact-PID / exact-path discipline (`SAFETY_BOUNDARIES.md`).
- Capture evidence per `METRICS_AND_EVIDENCE.md` and `EVIDENCE_LOG_TEMPLATE.md` as you go.
- If anything diverges or looks unsafe, follow `ABORT_AND_ROLLBACK.md`.
