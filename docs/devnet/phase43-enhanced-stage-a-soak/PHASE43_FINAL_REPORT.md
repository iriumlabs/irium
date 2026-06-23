# Phase 43 — Enhanced Stage A Devnet Soak: Final Report

Internal, single-host, **loopback-only** devnet soak of the combined PoAW-X Phase 28–34 stack using the
Phase 42 enhanced harness (`--phase31-34`). Mainnet/prod untouched. Devnet network id 2; PoAW-X hard-off
on mainnet.

- Branch: `testnet/poawx-phase43-enhanced-stage-a-soak`
- Start HEAD: `693d76da7c6f5717bd26b59803171ebe9bbe739d`
- Build: `iriumd` + `poawx-live-proof-harness` (source == `693d76d`).

## Baseline (before the soak)

Focused phase28–34 + phase42 all green; full lib **829/0**; sim **17/0**; release build OK
(`BASELINE_TEST_EVIDENCE.md`).

## Enhanced Stage A — PASS

- **6 enhanced all-gates blocks** mined + accepted, height 0 → 6, final tip
  `45114d7ea7cc35928d636748c76937af12018f6e342931c972a4f2a396fbb118` (`ENHANCED_STAGE_A_EVIDENCE.md`).
- Gates: **Phase 33 DMC1 required + Phase 34 ADM1 required** + Phase 32 ticket store active + Phase 31
  caps active + the 21x/22x + Phase 28 + Phase 30 stack. Acceptance under the required gates proves each
  block carried valid **DMC1** and **ADM1**; **TKT1** registrations were collected; the canonical
  55/22/13/10 (0% fee) split passed the **reward caps**.
- Adaptive mode = **Normal** (TKT1 emitted ⇒ recent registered tickets ≥ threshold).

## Cold replay — PASS

Restart on the same storage reconstructed to height 6, identical tip, re-validating DMC1/ADM1 under the
required gates (`COLD_REPLAY_EVIDENCE.md`).

## Fresh-wipe sync — DEFERRED to Stage B

Loopback multi-node P2P is not exercisable (node does not dial `127.0.0.1` peers); genuine fresh-wipe /
convergence needs an owner-approved cross-host Stage B (`FRESH_WIPE_SYNC_STATUS.md`).

## Topology / storage / ports / PIDs

- Single Windows host, loopback only. Node RPC `127.0.0.1:41151`, status `41148`, no P2P.
- Storage `…\phase43-devnet\stage-a\nodeA\` (isolated; removed at cleanup).
- PIDs stopped (mine only, exact): 19164, 17484.

## Cleanup — confirmed

No Phase 43 `iriumd` running; only the production node (PID 4908) remains, **alive and untouched**; no
Phase 43 listeners; runtime storage removed; no firewall rules; no credentials stored (`CLEANUP.md`).

## Issues found

None (no consensus defect). The only carried limitations are environmental: loopback can't do multi-node
P2P (Stage B), and full ticket-store *eligibility* enforcement live still needs harness `role_ticket_proofs`
emission + a non-genesis activation design (the harness emits TKT1 + proves H→H+1 active timing).

## Recommended next step

1. **Owner-approved Stage B cross-host soak** (Windows + VPS-1 + VPS-2) for genuine multi-node
   convergence / fresh-wipe sync / reorg rejection — the remaining open item (risk R6/R11).
2. **Auditor handoff** with the current evidence: lib 829/0 + sim 17/0 + this enhanced Stage A live soak
   (combined 28–34 incl. DMC1/ADM1 required + TKT1 + caps) + cold replay.
3. Optional: extend the harness `role_ticket_proofs` for full live ticket-eligibility enforcement.

## Status

production-ready: **no** · mainnet-ready: **no** · audited: **no** · public-testnet-ready: **planning-ready only**
