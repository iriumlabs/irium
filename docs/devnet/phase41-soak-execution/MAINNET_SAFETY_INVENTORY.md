# Phase 41 — Mainnet Safety Inventory (read-only, before any devnet command)

Captured via **read-only** process/port queries on the Windows host before Stage A. No process was
stopped, started, or signaled. Stage A is **local-only on Windows**; VPS-1/VPS-2 are not used in Stage A.

## Windows host

- **Irium-related processes running:** **NONE.** A read-only `Win32_Process` scan for
  `iriumd|irium|poawx|minerd|cpuminer|stratum` returned **no matches** — there is no Windows mainnet
  node, miner, pool, or stratum process running.
- **Listening TCP ports:** only standard Windows/OS services (135 RPC-EPM, 139/445 SMB, 5040, 5354
  mDNS, 6463, 7393, 27015, 49664–49670 dynamic RPC). **No irium ports in use.**
- **Implication:** there is no Windows mainnet/prod irium process that Stage A could disturb. Phase 41
  devnet ports will be chosen in the 41xxx range (loopback-only), which does not overlap any listed port.

## VPS-1 / VPS-2

- **Not accessed for Stage A.** Stage A is local-only (loopback on Windows); no SSH, no remote commands.
- Per prior phases, VPS-1 hosts a mainnet node + production pool and VPS-2 hosts a mainnet node; these
  are **out of scope for Stage A** and are **not touched**. Any VPS use is Stage B only and requires a
  separate, reaffirmed owner approval (`STAGE_B_GO_NO_GO.md`), including a fresh mainnet inventory on
  each VPS at that time.

## Confirmations

- Phase 41 devnet **ports** (loopback 41xxx) do **not** overlap any in-use Windows port. ✓
- Phase 41 devnet **storage** is isolated under `…\phase41-devnet\` (never default/`/tmp`/`.irium`). ✓
- **No mainnet/prod process will be stopped or restarted.** ✓ (none is even running on Windows)
- Cleanup will target only exact Phase 41 pidfiles/paths. ✓

Status: not audited / not mainnet-ready / not production-ready; PoAW-X hard-off on mainnet. Devnet soak
is internal/testnet only.
