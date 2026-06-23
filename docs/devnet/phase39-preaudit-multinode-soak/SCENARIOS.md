# Scenarios

Planned soak scenarios for the combined Phase 28–34 stack. Plan only — not executed in Phase 39. Each
maps to pass/fail criteria (`PASS_FAIL_CRITERIA.md`) and evidence (`METRICS_AND_EVIDENCE.md`).

| # | Scenario | What it validates | Key evidence |
|---|---|---|---|
| S1 | Baseline 3-node convergence | A/B/C reach the same height/tip/root | per-node height+tip+irx1 |
| S2 | 20-block all-gates run | sustained production with every gate active | 20 blocks accepted on all nodes |
| S3 | Fresh-wipe sync | brand-new node syncs from scratch (incl. served historical admissions, Phase 26E) | wiped node reaches tip |
| S4 | Cold restart / replay | node on existing storage reconstructs all derived state (Phase 26D) | post-restart state == pre |
| S5 | Historical admissions replay | served admissions re-validated on receiver | receiver rebroadcast / accept |
| S6 | Finalized-checkpoint reorg rejection (Phase 28) | reorg below checkpoint rejected (even higher-work) | reorg-rejection log line |
| S7 | Block-carried double-sign evidence replay (Phase 30) | `DSE1` validated/applied; penalized signer excluded from finality; replays identically | penalty count; finality reject |
| S8 | On-chain ticket registration replay (Phase 32) | `TKT1` registrations build store; rate-limit/expiry deterministic; replay-stable | ticket store count |
| S9 | Dominance commitment replay (Phase 33) | `DMC1` pre/post digests recompute on replay/reorg | dominance digest match |
| S10 | Adaptive mode transition replay (Phase 34) | `ADM1` mode transitions deterministic across nodes/replay | adaptive pre/post per height |
| S11 | Low participation → Caution | adaptive enters Caution on low chain-derived participation | mode == Caution |
| S12 | Dominance concentration → Defense | adaptive enters Defense on high concentration / evidence | mode == Defense |
| S13 | Recovery exit | Defense → Recovery → exits after the deterministic window | mode sequence |
| S14 | Network interruption + reconnection (only if safe) | nodes re-sync after a drop without divergence | post-reconnect convergence |
| S15 | Cleanup validation | all devnet processes stopped by pidfile; storage roots removed; mainnet intact | cleanup table complete |

## Sequencing notes

- Start with **S1/S2 loopback-only on one host** if cross-host P2P is not yet approved.
- S6/S7/S9/S10 are the highest-value consensus-safety scenarios; ensure evidence is captured carefully.
- S11–S13 may require crafting chain-derived conditions (participation/concentration/evidence); document
  how each condition is produced so it is reproducible.
- S14 only if the owner approves controlled network manipulation; otherwise skip.
- S15 is mandatory and must always run last (even on abort).
