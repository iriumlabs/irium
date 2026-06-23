# Phase 41 — Final Internal Devnet Soak Report

Internal, operator-only, **loopback** devnet soak of the combined PoAW-X build. Mainnet/prod untouched
(no Windows mainnet process existed). Devnet network id = 2; PoAW-X hard-off on mainnet.

- Branch: `testnet/poawx-phase41-devnet-soak-execution`
- Start HEAD: `7cb543bf19910e8a132a70563a57d82364f4f0b2`
- Build: `target/release/iriumd.exe` + `poawx-live-proof-harness.exe` (source == audited baseline
  `78d5ca3`; Phases 35–40 docs-only).

## Stage results

- **Stage A (local-only loopback): PARTIAL PASS** — core scenarios passed; multi-node deferred.
- **Stage B (cross-host): SKIPPED** — not reaffirmed/approved in session (`STAGE_B_GO_NO_GO.md`).

## Scenarios

| Scenario | Result |
|---|---|
| Baseline convergence (S1, multi-node) | **Deferred to Stage B** — loopback peers not dialed (`outbound_attempts=0`); needs distinct IPs |
| 20-block all-gates run (S2) | **PASS at 6 blocks** (height 0→6, all accepted; 6 used for a bounded run) |
| Fresh-wipe sync (S3, via P2P) | **Deferred to Stage B** (same loopback P2P limitation) |
| Cold restart / replay (S4) | **PASS** (restart on same storage → height 6, identical tip) |
| Historical admissions replay (S5) | Implicitly exercised in S2 (each block's admissions ingested via `/poawx/candidate-admission` then validated); full served-admission-to-fresh-peer path is Stage B |
| Ticket registration replay (S8) | **Not live-driven** (harness emits no `TKT1`) — covered by lib tests |
| Dominance commitment replay (S9) | **Not live-driven** (harness emits no `DMC1`) — covered by lib tests |
| Adaptive transition replay (S10) | **Not live-driven** (harness emits no `ADM1`) — covered by lib tests |
| Controlled reorg (S6) | **Skipped** (not approved; needs multi-node) |
| Cleanup validation (S15) | **PASS** (`STAGE_A_CLEANUP.md`) |

## Topology
Single Windows host, loopback only. Node A (RPC `127.0.0.1:41031`), fresh node B (RPC
`127.0.0.1:41033`). No public ports, no firewall changes, no VPS, no external miners, no real
wallets/keys.

## Evidence highlights
- Block count: 6 (height 0 → 6). Final tip:
  `71bb01b3f13e4dc105c08069660514d0730186bff1c6b898da337c2b9f502fe7`; height-1 irx1 root
  `187797fcca3600e35c45e0b98058d0bf6835d9e24be20d7685488e9e7d482dca`.
- Block sections present (every block): candidate_set, candidate_admission, committed_admission,
  true_vrf(AVR2), role_puzzle_proofs, finality_proof, role_dominance_weights; 0% fee.
- **Finality (Phase 28):** the chain advanced its finalized checkpoint as blocks connected (block H
  finalizes H-1); cold replay reconstructed it from disk.
- **Cold replay:** restart on the same storage reached height 6 with the identical tip.
- **Double-sign/penalty (Phase 30):** gate active; no evidence injected by the harness (no live penalty
  exercised).
- **Reward manifest (31) / ticket store (32) / dominance commitment (33) / adaptive (34):** not
  live-driven — the harness does not emit those sections (see limitation below).

## Fresh-wipe sync / cold replay
- Cold replay: **PASS** (above).
- Fresh-wipe via P2P: **deferred to Stage B** (loopback P2P not exercisable).

## Controlled reorg
- **Skipped** (not approved; requires multi-node).

## Cleanup confirmation
- Both nodes stopped by exact PID (verified release iriumd); no iriumd running; no Phase 41 listeners
  (41028–41033) remain; no firewall rules created. Runtime storage removed by exact path; evidence
  preserved in the markdown docs. (`STAGE_A_CLEANUP.md`)

## Mainnet/prod safety confirmation
- No mainnet/prod process existed on Windows before, during, or after; none stopped/started/signaled.
  VPS-1/VPS-2 not contacted (Stage B skipped). (`MAINNET_SAFETY_INVENTORY.md`)

## Issues found
- **No consensus defect.** Two environment/tooling limitations surfaced (both expected, neither a code
  bug):
  1. Loopback-only multi-node P2P is not exercisable (node does not dial `127.0.0.1` peers) → genuine
     multi-node needs Stage B.
  2. `poawx-live-proof-harness` does not emit Phase 31–34 sections → live enforcement of 31–34 needs a
     harness extension (future source-code phase).

## Recommendation
- **Proceed to the auditor** with: the library suite (822/0), the simulator (17/0), and this Stage A live
  evidence (combined build boots, produces/accepts a 6-block all-gates chain, and cold-replays).
- **For full live coverage**, schedule (a) a future code phase to extend the harness to emit Phase 31–34
  sections, and (b) an owner-approved **Stage B** cross-host run for genuine multi-node convergence /
  fresh-wipe sync / reorg rejection.
- Do **not** treat this soak as a public-testnet or mainnet authorization.

## Status
- production-ready: **no**
- mainnet-ready: **no**
- audited: **no**
- public-testnet-ready: **planning-ready only**
