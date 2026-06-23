# Mainnet Safety Pre-Check

Run this checklist (read-only) immediately before any soak execution. Nothing is executed in Phase 40.
The soak must never touch mainnet/prod.

| # | Check | Done? | Notes |
|---|---|---|---|
| 1 | List mainnet `iriumd` PIDs on each host (record exact PIDs) | ☐ | keep for the duration |
| 2 | Verify mainnet P2P/RPC ports in use (so devnet ports don't collide) | ☐ | |
| 3 | Verify production pool / stratum services + ports | ☐ | VPS-1 hosts prod pool |
| 4 | Verify chosen **devnet** ports do **not** overlap any mainnet/pool port | ☐ | per host |
| 5 | Verify PoAW-X is hard-off on mainnet (`network_id == 0` ⇒ all gates false) | ☐ | unchanged by this soak |
| 6 | Verify devnet storage roots do **not** overlap mainnet/prod storage paths | ☐ | `STORAGE_ROOTS_SIGNOFF.md` |
| 7 | Confirm plan performs **no** mainnet process stop/restart/signal | ☐ | exact-PID devnet-only ops |
| 8 | Confirm cleanup cannot target any mainnet/prod path (exact-path-only) | ☐ | Phase 39 cleanup table |
| 9 | Confirm devnet uses `IRIUM_NETWORK=devnet` (never mainnet) | ☐ | |
| 10 | Record mainnet liveness baseline (to re-verify after soak + cleanup) | ☐ | before/after match |

## Rules

- This is a **read-only** precheck — listing/inspecting processes and ports, not changing anything.
- If any item is uncertain (e.g., a mainnet PID can't be confirmed, or a port overlap is possible),
  it is a **No-Go** (`EXECUTION_GO_NO_GO.md`).
- Re-verify mainnet liveness (item 10) **after** the soak and **after** cleanup.
