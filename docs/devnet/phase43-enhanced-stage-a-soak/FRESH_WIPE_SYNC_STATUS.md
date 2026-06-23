# Phase 43 — Fresh-Wipe Sync Status

**Deferred to Stage B (cross-host).** Not exercised in Phase 43.

## Why

Fresh-wipe sync requires a SECOND node to sync the chain from a peer over P2P. As established in Phase 41,
the node does **not** dial `127.0.0.1` peers (it treats loopback as self/non-routable; a fresh node logged
`outbound_attempts=0`). So genuine multi-node convergence / fresh-wipe-via-P2P **cannot be demonstrated
loopback-only** and was not forced here (per the phase rules: do not force loopback P2P).

## What Phase 43 did instead

- Single-node enhanced Stage A soak (6 blocks, DMC1/ADM1 required + TKT1 + caps) — see
  `ENHANCED_STAGE_A_EVIDENCE.md`.
- Cold replay (state reconstruction from disk) — see `COLD_REPLAY_EVIDENCE.md`.

## What is still required

Genuine fresh-wipe sync + multi-node convergence + reorg-rejection under load need an **owner-approved
Stage B cross-host run** (Windows + VPS-1 + VPS-2, distinct IPs, source-restricted firewall) — out of
scope for Phase 43 (local-only). See `docs/devnet/phase39-preaudit-multinode-soak/` and
`docs/devnet/phase40-soak-readiness-signoff/`.

Status: cross-host Stage B still pending; not audited / not mainnet-ready; public-testnet planning-ready
only.
