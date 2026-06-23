# Phase 42 — Smoke Cleanup

All Phase 42 devnet processes were stopped by **exact PID** (verified as my repo's
`target\release\iriumd.exe` before stopping). No `pkill`/`killall`/name-matching. The installed Irium
Core production node was never targeted.

## Processes stopped (exact PID, verified path)

| PID | Identity | Action |
|---|---|---|
| 20316 | `…\irium-poawx-windows-test\target\release\iriumd.exe` (my devnet node, mining run) | stopped (for cold replay) |
| 18868 | same path (my devnet node, cold-replay run) | stopped (final cleanup) |

## Post-cleanup verification

- Remaining `iriumd`: **only PID 4908** (`AppData\Local\Irium Core\iriumd.exe --http-rpc`, the production
  node) — alive and **untouched**.
- My devnet ports 41048 / 41051: **none listening**.
- Runtime storage `C:\Users\Ibrahim\irium-poawx-windows-test\phase42-devnet\` **removed by exact path**
  (evidence summarized into `LOCAL_SMOKE_EVIDENCE.md` first; never a default/`/tmp`/`.irium` path).
- No firewall rules created (loopback-only). No credentials printed/stored.

Mainnet/prod safety: confirmed — the Irium Core production node was alive before, during, and after, and
was never signaled.
