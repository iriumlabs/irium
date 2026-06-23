# Phase 41 — Stage B Cross-Host Go / No-Go

**Current decision: NO-GO / not run in this session.** Stage B (cross-host Windows + VPS-1 + VPS-2) was
not executed. It requires a **reaffirmed owner approval in the session** plus approval to add
source-restricted firewall rules — neither was given in this turn.

## Stage A outcome (prerequisite)

- Core Stage A scenarios **passed** (single-node combined-build boot, 6-block all-gates live chain, cold
  replay). See `STAGE_A_LOCAL_LOOPBACK_EVIDENCE.md`.
- Multi-node convergence (S1) and fresh-node sync (S3) are **not exercisable loopback-only** (the node
  does not dial `127.0.0.1` peers — `outbound_attempts=0`). These specifically need Stage B (distinct
  hosts/IPs). So Stage B is the natural next step **if** the owner approves it.

## What Stage B would require (for owner approval)

- **Current Windows public IP:** `122.162.151.91` (re-check immediately before execution — it changes
  between sessions).
- **VPS-1 IP / VPS-2 IP:** `[owner provides]`.
- **Proposed source-restricted firewall rules (TCP only, no UDP, no 0.0.0.0/0):**
  - VPS-1: allow `122.162.151.91` and `[VPS-2 IP]` → VPS-1 devnet P2P port `[FILL]`.
  - VPS-2: allow `122.162.151.91` and `[VPS-1 IP]` → VPS-2 devnet P2P port `[FILL]` (if needed).
  - Every rule recorded before/after and **removed at cleanup**.
- **Proposed devnet ports:** distinct from any mainnet/pool port on each host (RPC loopback-only each).
- **Storage roots:** `…\phase41-devnet\stage-b\` (Windows), `/home/irium/phase41-devnet/stage-b/`
  (VPS-1/VPS-2).
- **Duration:** short smoke first, then medium soak if it passes.
- **Scenarios:** Win/VPS-1/VPS-2 convergence, 20-block all-gates run, fresh-wipe sync, cold
  restart/replay, adaptive observation (note: harness still cannot emit 31–34 sections — see below),
  cleanup validation.
- **Mainnet safety:** a fresh read-only mainnet inventory on **each VPS** before any devnet process
  (VPS-1 hosts a mainnet node + production pool; VPS-2 a mainnet node — must not be touched).

## Carry-over limitation (independent of Stage A/B)

The current `poawx-live-proof-harness` does not emit Phase 31/32/33/34 block sections, so even Stage B
cannot live-enforce Phases 31–34 — those remain covered by the library suite (822/0) + simulator (17/0).
Full live 31–34 coverage needs a harness extension (a future source-code phase).

## Decision

Stage B **not run**. To proceed, the owner must (1) reaffirm Stage B approval in the session, (2) provide
VPS IPs and approve the exact source-restricted firewall rules, and (3) approve a fresh per-VPS mainnet
safety precheck. Until then, Stage B is **skipped**.
