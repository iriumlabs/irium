# Audit Scope (Final) — PoAW-X Phases 28–34

**Testnet/devnet only. PoAW-X is hard-off on mainnet (`network_id == 0`). Not audited.**

## In-scope source ranges (linear chain, verified remote refs)

Review each phase as the diff from the previous HEAD:

| Phase | Range | Feature |
|---|---|---|
| 28 | `40db1aa..199ed24` | Finalized-checkpoint reorg rejection |
| 29 | `199ed24..df0cc92` | Double-sign evidence/penalty primitives |
| 30 | `df0cc92..7e5f805` | Block-carried double-sign evidence + consensus penalties |
| 31 | `7e5f805..fae91bb` | Reward manifest wrapper / caps / fallback |
| 32 | `fae91bb..8f2a64d` | On-chain ticket store |
| 33 | `8f2a64d..1a032de` | Dominance-state commitment |
| 34 | `1a032de..78d5ca3` | Adaptive-modes consensus integration |

(`40db1aa` = Phase 27 base; `78d5ca3` = Phase 34 head; `17f8a77` = Phase 35 docs head.)

## In-scope consensus modules

- `src/chain.rs` — `connect_block`, `reorg_to_tip`, `disconnect_tip_block`, the per-phase
  `validate_block_*` validators, and the `rebuild_*_from_chain` reorg rebuilders.
- `src/poawx.rs` — `Phase20ReceiptExt` serialization incl. trailing sections `DSE1`/`TKT1`/`DMC1`/`ADM1`.
- `src/poawx_doublesign.rs`, `src/poawx_penalty.rs` — double-sign evidence + penalty state.
- `src/poawx_reward.rs` — reward manifest wrapper, caps, fallback.
- `src/poawx_ticket.rs` — on-chain ticket store, Sybil/rate-limit/expiry.
- `src/poawx_dominance.rs` — anti-domination state + `DMC1` commitment.
- `src/poawx_adaptive.rs` — adaptive state, signals, transition, `ADM1` commitment.
- `src/activation.rs` — network id + activation gating (mainnet hard-off).
- `src/bin/poawx-sim.rs` — off-chain simulator (model, not consensus).

## In-scope docs

- `docs/poaw-x-phase{28..34}-*.md` (per-phase result + design docs).
- `docs/poaw-x-phase35-*` (closeout, commit map, feature matrix, audit-readiness, risk register,
  public-testnet readiness).
- `docs/audit/phase35-final-handoff/` and this `docs/audit/phase36-independent-audit-kickoff/` package.

## Out of scope

- **Mainnet activation** — not part of this work; PoAW-X is hard-off on mainnet.
- **Public-testnet launch** — planning-ready only; not started.
- **Wallet UX** — no wallet/key code under review.
- **Exchange / liquidity** — not applicable.
- **Production operations** — no live nodes, no ops infrastructure under review.
- **Non-PoAW-X mainnet behavior** — SHA-256d PoW, LWMA-144, anchor work rules, and base block reward are
  unchanged by Phases 28–34 and are not under review here.

## Safety statement

PoAW-X is **testnet/devnet only**. Every Phase 28–34 feature returns false on `network_id == 0`
(mainnet) and is additionally off by default behind explicit env activation heights / required flags.
With no env set, behavior is identical to pre-phase. This package requests an **independent review**; it
makes **no** claim that the code is audited, production-ready, mainnet-ready, or public-testnet
live-ready.
