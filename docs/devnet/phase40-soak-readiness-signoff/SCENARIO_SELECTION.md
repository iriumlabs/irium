# Scenario Selection

Choose which Phase 39 scenarios (S1–S15) the soak will run. Owner marks each: **required / optional /
skip / defer / unsafe-until-later**. Selection pending. (Full definitions in
`docs/devnet/phase39-preaudit-multinode-soak/SCENARIOS.md`.)

| # | Scenario | Recommended | Owner selection |
|---|---|---|---|
| S1 | Baseline 3-node convergence | **Required** | `[ ]` |
| S2 | 20-block all-gates run | **Required** | `[ ]` |
| S3 | Fresh-wipe sync | **Required** | `[ ]` |
| S4 | Cold restart / replay | **Required** | `[ ]` |
| S5 | Historical admissions replay | **Required** | `[ ]` |
| S6 | Finalized-checkpoint reorg rejection | **Owner-approved separately** | `[ ]` |
| S7 | Block-carried double-sign evidence replay | Optional (recommended) | `[ ]` |
| S8 | On-chain ticket registration replay | **Required** | `[ ]` |
| S9 | Dominance commitment replay | **Required** | `[ ]` |
| S10 | Adaptive mode transition replay | **Required** | `[ ]` |
| S11 | Low participation → Caution | Optional | `[ ]` |
| S12 | Dominance concentration → Defense | Optional | `[ ]` |
| S13 | Recovery exit | Optional | `[ ]` |
| S14 | Network interruption + reconnection | Defer / unsafe-until-later | `[ ]` |
| S15 | Cleanup validation | **Required (always last)** | `[ ]` |

## Recommended minimum set

S1, S2, S3, S4, S5, S8, S9, S10, **S15** — covers convergence, sync (fresh-wipe + cold replay +
historical admissions), the ticket/dominance/adaptive replay paths, and mandatory cleanup.

## Notes

- **S6 (controlled reorg)** requires a separate explicit owner approval (it manipulates chain state);
  default is to include it only if the owner approves, otherwise skip.
- **S7/S11/S12/S13** (double-sign, Caution/Defense/Recovery) require crafting chain-derived conditions;
  include if time/duration allows and document how each condition is produced.
- **S14** (network interruption) only if the owner approves controlled network manipulation; otherwise
  defer.
- **S15 always runs last**, even on abort.
