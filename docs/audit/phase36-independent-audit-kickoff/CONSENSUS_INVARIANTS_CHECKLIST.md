# Consensus Invariants Checklist — PoAW-X Phases 28–34

For the auditor to verify (and mark Pass / Fail / N/A with notes). Testnet/devnet only; not audited.

| # | Invariant | Where to check | Verdict | Notes |
|---|---|---|---|---|
| I1 | **Mainnet hard-off** — every PoAW-X gate is false for `network_id == 0` | `src/activation.rs`; each `*_gate`/`*_active`/`*_required` | ☐ | |
| I2 | **No LWMA change** — LWMA-144 difficulty logic unchanged by 28–34 | diff vs `40db1aa`; `src/chain.rs`/difficulty | ☐ | |
| I3 | **No PoW target change** — SHA-256d target/anchor rules unchanged | `src/pow.rs`, header validation | ☐ | |
| I4 | **No base reward change** — `block_reward` / `constants.rs` unchanged | `src/constants.rs` | ☐ | |
| I5 | **No uncommitted local signal affects consensus** — only chain-derived/committed state influences acceptance | `src/poawx_adaptive.rs` signals; `connect_block` | ☐ | |
| I6 | **No local-only evidence affects consensus** — gossip-cached double-sign evidence is non-consensus; only block-carried `DSE1` is enforced | `src/poawx_doublesign.rs`; `connect_block` | ☐ | |
| I7 | **All block-carried evidence replayable** — `DSE1`/`TKT1`/`DMC1`/`ADM1` reconstruct deterministically on cold replay | `rebuild_to_tip`; per-phase apply/rebuild | ☐ | |
| I8 | **All state reorg-safe** — checkpoint/penalty/ticket/dominance/adaptive snapshot-restore or rebuild-from-active-chain | `reorg_to_tip`; `rebuild_*_from_chain` | ☐ | |
| I9 | **Optional ext sections byte-compatible when `None`** — absent ⇒ identical serialized bytes | `src/poawx.rs` `Phase20ReceiptExt` | ☐ | |
| I10 | **Invalid ext data rejects the block when the gate is active** — bad length/version/dup/unknown-magic/over-cap/tampered-digest | `Phase20ReceiptExt::deserialize`; `validate_block_*` | ☐ | |
| I11 | **phase21d/21e/22a not weakened** — additions are strict supersets | diff of 21d/21e/22a validators (unchanged) | ☐ | |
| I12 | **Reward total never exceeds subsidy + fees** — caps/fallback non-inflationary | `src/poawx_reward.rs`; `validate_and_apply_transactions` | ☐ | |
| I13 | **Finality double-sign penalties deterministic** — suspended-signer exclusion replays identically; no false positives | `is_eligible_for_finality`; `validate_block_finality` | ☐ | |
| I14 | **Ticket registrations deterministic** — validated/deduped/ordered; Sybil + rate-limit + expiry deterministic; no replay across epochs | `src/poawx_ticket.rs`; `validate_block_ticket_registrations` | ☐ | |
| I15 | **Dominance & adaptive state replayable** — `DMC1`/`ADM1` pre/post digests recompute from chain; tampering rejected | `poawx_dominance.rs`/`poawx_adaptive.rs`; `connect_block` | ☐ | |
| I16 | **Non-retroactive timing** — block H validated under state from blocks < H; H's own data effective from H+1 | per-phase apply-after-commit | ☐ | |
| I17 | **Adaptive liveness** — no mode (incl. Defense/Recovery) can deadlock block production; Recovery window is finite/deterministic | `PoawxAdaptiveState::next`; `enforce_adaptive_mode_effects` | ☐ | |
| I18 | **Shared-parameter determinism** — dominance window/lookback feed committed digests; all nodes must use identical values (operator-coordination requirement) | `poawx_dominance.rs`; runbook | ☐ | |

A failure on I1–I4, I11, or I12 would be **Critical** (touches mainnet safety, base consensus, or
inflation). Record all results in `FINDINGS_TRACKER_TEMPLATE.md`.
