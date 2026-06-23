# Phase 43 — Cleanup

All Phase 43 devnet processes stopped by **exact PID** (verified as this repo's
`target\release\iriumd.exe` before stopping). No `pkill`/`killall`/name-matching. The Irium Core
production node was never targeted.

## Processes stopped (exact PID, verified path)

| PID | Identity | Action |
|---|---|---|
| 19164 | `…\irium-poawx-windows-test\target\release\iriumd.exe` (mining run) | stopped (for cold replay) |
| 17484 | same path (cold-replay run) | stopped (final cleanup) |

## Post-cleanup verification

- Remaining `iriumd`: **only PID 4908** (`AppData\Local\Irium Core\iriumd.exe --http-rpc`, production) —
  **alive and untouched**.
- Phase 43 ports 41148 / 41151: **none listening**.
- Runtime storage `C:\Users\Ibrahim\irium-poawx-windows-test\phase43-devnet\` **removed by exact path**
  (evidence summarized into the markdown docs first; never a default/`/tmp`/`.irium` path).
- No firewall rules created (loopback-only). No credentials printed/stored.

Mainnet/prod safety confirmed: the production node was alive before, during, and after; never signaled.
Evidence docs preserved.
