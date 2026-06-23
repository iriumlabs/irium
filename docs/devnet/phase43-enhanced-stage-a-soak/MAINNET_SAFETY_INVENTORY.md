# Phase 43 — Mainnet Safety Inventory (read-only, before any devnet command)

Captured via **read-only** process/port queries on the Windows host before the enhanced Stage A soak. No
process was stopped, started, or signaled. Stage A is **local-only on Windows** (loopback); VPS-1/VPS-2
are not contacted.

## Windows host — production/mainnet processes

- **Irium Core production node — RUNNING, MUST NOT TOUCH:**
  - PID **4908**, `"\\?\C:\Users\Ibrahim\AppData\Local\Irium Core\iriumd.exe" --http-rpc`
  - Started 2026-06-24 04:03:07. This is the installed Irium Core desktop/production node — a **different
    binary** (`AppData\Local\Irium Core\iriumd.exe`) from this repo's `target\release\iriumd.exe`, with
    its own storage and (mainnet) network.
- **Miners / pool / stratum:** none running.

## Ports

- Phase 43 devnet ports (loopback **41148–41153**): **none in use** → free for my isolated devnet node.
- The production node uses its own default HTTP/RPC port (not in the 4114x–4115x range); **no overlap.**

## Confirmations

- Phase 43 devnet **ports** (loopback 41148–41153) do not overlap the production node or any listener. ✓
- Phase 43 devnet **storage** is isolated under `…\phase43-devnet\` (never default/`/tmp`/`.irium`). ✓
- **No mainnet/prod process will be stopped or restarted.** The Irium Core node (PID 4908) is left
  fully untouched and will be re-verified alive after the soak + cleanup. ✓
- My devnet node will run with **no P2P** (no `IRIUM_P2P_BIND`) and loopback RPC, so it cannot contact the
  production node (different network magic regardless). ✓

Status: not audited / not mainnet-ready / not production-ready; PoAW-X hard-off on mainnet; internal
devnet soak only.
