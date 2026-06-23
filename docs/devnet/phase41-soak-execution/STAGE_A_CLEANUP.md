# Phase 41 — Stage A Cleanup

All Stage A devnet processes were stopped by **exact PID** (verified as our release `iriumd.exe` before
stopping). No `pkill`/`killall`/name-matching was used. No mainnet/prod process existed on Windows, so
none was touched.

## Processes stopped (exact PID, verified)

| PID | Identity (verified `CommandLine`) | Action |
|---|---|---|
| 15528 | `…\target\release\iriumd.exe` (node A, P2P run) | `Stop-Process -Id 15528 -Force` |
| 1884 | `…\target\release\iriumd.exe` (node B, fresh) | `Stop-Process -Id 1884 -Force` |

(Earlier node-A incarnations 1664 and 6856 were each stopped by exact PID during the run for the cold
replay / P2P restart steps.)

## Post-cleanup verification

- `Get-CimInstance Win32_Process -Filter "Name='iriumd.exe'"` → **no iriumd running**.
- Listening ports 41028–41033 (Phase 41 loopback range) → **none listening** (no Phase 41 listeners
  remain).
- No firewall rules were created in Stage A (loopback-only) → none to remove.
- Mainnet/prod: none was running on Windows; **untouched** (re-confirmed: no iriumd of any kind running).

## Storage / logs

- Evidence captured into `STAGE_A_LOCAL_LOOPBACK_EVIDENCE.md` (heights, hashes, results) — the durable
  evidence of record.
- The Phase 41 runtime storage/log tree
  (`C:\Users\Ibrahim\irium-poawx-windows-test\phase41-devnet\`) is a transient, **non-default, isolated**
  runtime artifact (never committed to git). After summarizing results into the evidence doc it is
  removed by exact path to keep the working tree docs-only; it was never under any default/`/tmp`/`.irium`
  path.

No evidence (the markdown docs) was deleted.
