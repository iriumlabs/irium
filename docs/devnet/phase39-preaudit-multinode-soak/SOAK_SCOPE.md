# Soak Scope

Internal devnet soak of the **combined PoAW-X Phase 28–34 stack**. Devnet only; mainnet hard-off; no
public testnet. Plan only — not executed in Phase 39.

## In scope (exercise together, all gates active)

- **Phase 28** — finalized-checkpoint reorg rejection (reorg below the checkpoint must be rejected).
- **Phase 30** — block-carried double-sign evidence (`DSE1`) + consensus penalty (finality exclusion).
- **Phase 29** — the underlying penalty-state primitive (exercised via Phase 30).
- **Phase 31** — reward manifest wrapper + caps + low-participation fallback.
- **Phase 32** — on-chain ticket store (`TKT1`) + Sybil / rate-limit / expiry.
- **Phase 33** — dominance-state commitment (`DMC1`).
- **Phase 34** — adaptive-mode consensus integration (`ADM1`); Normal/Caution/Defense/Recovery.
- **Phase 26D/26E** — historical-admission serving + fresh-wipe sync, re-exercised with all gates active.
- **Cold replay / fresh wipe** — a brand-new node reconstructs all derived state from the chain.
- **Reorg / replay safety** — all five derived states (checkpoint, penalty, ticket, dominance, adaptive)
  stay consistent across reorg and replay.

## Explicitly out of scope

- **No public testnet**, no public RPC, no public stratum, no external miners.
- **No mainnet/prod** interaction; mainnet processes are inventoried and left untouched.
- No wallet/key access; no real funds; devnet keys only.
- No firewall/sudo changes unless separately and explicitly approved (P2P between hosts is
  approval-gated; default plan is loopback-only first).
- No performance/scale benchmarking beyond rough CPU/mem notes; this is a correctness/safety soak.

## Goal

Demonstrate, on an internal operator-only devnet, that the **combined** stack converges, syncs
(incl. fresh-wipe + cold replay), rejects invalid reorgs, and keeps the double-sign / ticket / dominance
/ adaptive state deterministic and reorg-safe — producing evidence for the auditor and for the
public-testnet planning decision. It does **not** make the system audited, production-ready, or
mainnet-ready.
