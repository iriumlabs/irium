# PoAW-X Phase 35 — Consensus Feature Matrix (Phases 27–34)

Every feature is **testnet/devnet only**, **mainnet hard-off** (`network_id == 0` ⇒ gate false), and
**off by default** behind explicit env activation. "Consensus-enforced?" = participates in
`connect_block` acceptance when its gate is active. "Tests reported" = focused `phaseNN_*` count
(see `docs/poaw-x-phase35-phases27-34-commit-map.md` for full-lib totals).

| Feature | Phase | Consensus-enforced? | Block-carried? | Replayable? | Reorg-safe? | Mainnet-off? | Tests reported | Remaining caveats |
|---|---|---|---|---|---|---|---|---|
| Finalized-checkpoint reorg rejection | 28 | Yes | No (derived state) | Yes (cold replay) | Yes (snapshot/restore) | Yes | `phase28_*` 8/0 | Not live-soaked combined with 29–34 |
| Double-sign evidence primitive | 29 | No (primitive only) | No | Yes | Yes | Yes | `phase29_*` 12/0 | Local cache is non-consensus by design |
| Block-carried double-sign evidence | 30 | Yes | Yes (`DSE1`, cap 16) | Yes | Yes (rebuild from chain) | Yes | `phase30_*` 7/0 | Proposer auto-inclusion of local evidence is future work |
| Double-sign penalty exclusion (finality) | 30 | Yes | Via `DSE1` | Yes | Yes | Yes | covered by `phase30_*` | Effective from H+1 (non-retroactive) by design |
| Reward manifest wrapper / caps / fallback | 31 | Yes (additive cap gate) | Yes (manifest) | Yes | Yes | Yes | `phase31_*` 9/0 | Cap gate is a strict superset; economic review still needed |
| On-chain ticket store | 32 | Yes (when enforced) | Yes (`TKT1`) | Yes | Yes (rebuild from chain) | Yes | `phase32_*` 12/0 | Eligibility enforcement is an optional gate |
| Ticket registration rate-limit / expiry | 32 | Yes | Via `TKT1` | Yes | Yes | Yes | covered by `phase32_*` | Pruning thresholds are conservative defaults |
| Dominance-state commitment | 33 | Yes (when active) | Yes (`DMC1`) | Yes | Yes | Yes | `phase33_*` 9/0 | Hard dominance caps deferred as policy (commitment only) |
| Adaptive-mode consensus integration | 34 | Yes (when active) | Yes (`ADM1`) | Yes | Yes (snapshot + rebuild) | Yes | `phase34_*` 17/0 | Effects additive/gated; confirmation-multiplier stays advisory |
| Simulation suite (`poawx-sim`) | 27–34 | No (off-chain) | n/a | Deterministic (fixed seed) | n/a | Yes (refuses mainnet id) | sim 17/0 | Model, not proof |
| Local-only signals exclusion | 34 (consensus) | Enforced by construction | n/a | n/a | n/a | Yes | `phase34_local_signals_not_consensus` | Local signals allowed in sim/operator reporting only |
| Mainnet hard-off gates | all | n/a (always off on net 0) | n/a | n/a | n/a | Yes | each phase's `*_gate`/`*_no_op` tests | Single choke point: `network_id == 0 ⇒ false` |

## Cross-cutting properties

- **Trailing-optional wire format.** `DSE1` / `TKT1` / `DMC1` / `ADM1` are present-only block sections;
  absent ⇒ byte-identical to the prior format. They are folded into the irx1 receipt root, so a present
  section is tamper-evident.
- **Derivation timing.** Block H is validated under state derived from blocks `< H`; H's own
  evidence/registrations/mode commitment apply from H+1 (non-retroactive, replayable).
- **Reorg discipline.** Derived state is either snapshot/restored (finalized checkpoint, adaptive state)
  or rebuilt from the active chain (penalty, ticket store, adaptive state) so abandoned-fork data never
  pollutes the active chain.
- **No changes** to LWMA, PoW target, SHA-256d anchor work, base block reward, or mainnet consensus in
  any of Phases 28–34.

**Caveat:** "consensus-enforced" describes behavior **when the feature's gate is active on
testnet/devnet**. On mainnet all gates are off. None of this is audited or production-ready.
