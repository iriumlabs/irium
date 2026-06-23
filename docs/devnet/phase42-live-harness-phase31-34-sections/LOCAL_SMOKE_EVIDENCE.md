# Phase 42 — Local-Only Loopback Smoke Evidence

Internal, single-host, loopback-only smoke of the **binary** `--phase31-34` path. Devnet (network id 2);
mainnet hard-off. **The installed Irium Core production node (PID 4908,
`AppData\Local\Irium Core\iriumd.exe --http-rpc`) was running throughout and was NOT touched.**

## Setup

- Binary: `target/release/iriumd.exe` (PID 20316) — my devnet node, isolated.
- Storage: `C:\Users\Ibrahim\irium-poawx-windows-test\phase42-devnet\stage-a\nodeA\` (isolated, non-default;
  removed at cleanup).
- RPC `127.0.0.1:41051`, status `127.0.0.1:41048`, **no P2P** (fully isolated; peers=0).
- Gate env: full Phase 28–34 set including Phase 31 caps active, **Phase 33 DMC required**,
  **Phase 34 adaptive required**, Phase 32 ticket store active, sybil bits 0.
- Harness: `poawx-live-proof-harness.exe --devnet --phase31-34 --rpc-url http://127.0.0.1:41051
  --work-dir …\harness-artifacts` (same gate env).

## Result

- 3 blocks mined + accepted live: height 0 → 3, tip
  `6453d62ebced20a2ad59b260f97d32fc20b22295c4124a9d3084565d69be6898`, persisted_height 3, peers 0.
- Because the node ran with **DMC required + adaptive required**, acceptance of all 3 blocks proves the
  harness emitted a valid **DMC1** and **ADM1** in each (a missing/invalid commitment would be rejected);
  the Phase 32 ticket store was active so **TKT1** registrations were collected. Phase 31 caps active
  accepted the canonical reward split.
- **Cold replay:** node stopped by exact PID and restarted on the same storage → reconstructed to
  height 3, identical tip — the Phase 31–34 sections re-validate on replay.
- Note: the binary's human-readable `poawx_sections` summary line still enumerates only the legacy
  sections (cosmetic); the new sections are present, as proven by required-gate acceptance.

## Mainnet/prod safety

- A read-only inventory found the installed **Irium Core** node (PID 4908) running on its own binary,
  storage, port, and (mainnet) network. It was left fully untouched; verified alive before, during, and
  after the smoke. My devnet node is isolated (loopback 41051, isolated storage, devnet magic, no P2P) and
  cannot contact it.

Status: internal devnet smoke executed; not audited / not production-ready / not mainnet-ready;
public-testnet planning-ready only.
