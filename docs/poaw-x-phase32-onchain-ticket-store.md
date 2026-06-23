# PoAW-X Phase 32 — On-Chain Ticket Store (Implemented)

Closes deferred Phase 27 item **2E**: Miner Work Tickets are now consensus-replayable via block-carried
registrations + a deterministic on-chain ticket store, with epoch rate-limiting, expiry, and (gated)
eligibility enforcement. **Testnet/devnet only. Mainnet hard-off (`network_id == 0`). NOT audited /
production-ready / mainnet-ready.** Branch `testnet/poawx-phase32-onchain-ticket-store` (from `fae91bb`).

## Where ticket registrations are carried

A registration (`PoawxTicketRegistrationV1`) wraps a `MinerWorkTicket` (self-authenticating via its
Sybil PoW — unsigned by the existing deterministic design; `ticket_id = ticket.digest()`). Carried in a
new **trailing-optional `TKT1` ext section** on `Phase20ReceiptExt` (the proven pattern; `None` ⇒
byte-identical to pre-32 exts; the ext digest is bound into the irx1 root, so registrations are
**committed**). Wire: `TKT1(4) || count(u16 LE) || count × (len(u16 LE) || ticket bytes)`.

## Max / canonicalization / dedup

- **Max per block:** `MAX_TICKET_REGISTRATIONS_PER_BLOCK = 16` (rejected at deserialize + connect_block).
- **Canonical / dedup:** carried in strictly-increasing `ticket_id` order; in-block duplicate id or
  non-canonical order **rejects the block**. Cross-block re-apply of the same id is an idempotent no-op.

## Epoch / rate-limit / expiry rules

- **Rate-limit:** **one active ticket per `(miner_pkh, epoch)`** and **one per `(assignment_public_key,
  epoch)`** — applying a second live registration for either rejects (`MinerEpochRateLimited` /
  `VrfEpochRateLimited`).
- **Epoch window:** bound via the ticket's `issued_height <= height < expiry_height` (old = expired =
  rejected; future = issued-in-future = rejected) — reuses the existing `MinerWorkTicket::validate`.
- **Expiry / pruning:** entries with `expiry_height <= tip` are deterministically pruned on apply.

## Effective timing (non-retroactive)

A registration in block `H` is validated during `H` and **applied after `H` is committed**, usable from
`H+1` (Phase 28/30 pattern). The eligibility check at `H` consults the store from blocks `< H`, so `H`'s
own registrations cannot satisfy `H`'s eligibility.

## Consensus enforcement

- **Registration validation** (`connect_block`, `ticket_store_active`, mainnet-off): each registration
  validated via the existing ticket validator; invalid/over-cap/non-canonical/rate-limited rejects the
  block. Applied to `ChainState.ticket_store` after commit.
- **Eligibility** (additive, `ticket_store_enforced`, off by default, mainnet-off):
  `validate_block_ticket_store_eligibility` requires every rewarded role's `TicketProof` to match an
  **active registered ticket** `(miner_pkh, epoch, assignment_public_key)` with `expiry > height`, else
  `phase32: role ticket not registered on-chain`. A strict **superset** of the existing
  `validate_phase20_ticket_proofs` — only adds rejections. **Role/finality eligibility requires an
  on-chain ticket when the gate is on.**

## Reorg + replay

The store is a pure function of the active chain. Tip extension / cold replay / rebuild apply
incrementally. `reorg_to_tip` **snapshots** the store on entry, **restores** on a failed reorg, and
**rebuilds from the new active chain** on success (`rebuild_ticket_store_from_chain`) — abandoned-fork
registrations never pollute the active chain.

## Local cache (non-consensus)

`NodeTicketRegistrationCache` (bounded, dedup, mainnet-off) helps a builder collect registrations but
**never** touches `ChainState.ticket_store` or block validity (test
`phase32_local_ticket_not_consensus_until_included`).

## Tests

`cargo test --lib phase32 -- --test-threads=1` → **12 passed / 0 failed** (7 store/registration unit +
5 consensus-helper): registration roundtrip/id; store apply + has_active (non-retroactive); rate-limit
(miner/epoch + vrf/epoch); expiry deterministic + prune; store digest order-independent; local cache
no-consensus; gate mainnet-off; block-carried registration validates + ext digest changes (committed) +
wire round-trips; invalid registrations rejected (expired/wrong-net/over-cap/in-block-duplicate);
**missing on-chain ticket rejected for a role + registered ticket accepted** (real
`validate_block_ticket_store_eligibility`); rebuild clears stale; local cache leaves the consensus store
empty.

Regression: full lib suite **796 passed / 0 failed** (was 784; +12). `ticket` 21/0; `sybil` 1/0.
`poawx-sim` bin **15/0** (+1). Release builds (`iriumd`, `poawx-live-proof-harness`, `poawx-sim`)
succeed. Wire-format backward-compat confirmed (phase20 + phase26 green; `None` ⇒ byte-identical).

## Simulation

`poawx-sim` `sybil` scenario now models the on-chain store with the real `PoawxTicketStore` and reports
`ticket_registrations_included`, `rejected_sybil_registrations`, `active_ticket_count`,
`expired_ticket_count`, `sybil_cost_estimate`, `ticket_store_consensus_enforced`. Deterministic;
`ticket_store_modeled` passes.

## Status of 2E

**Consensus-enforced.** Block-carried registrations are validated + applied deterministically,
replayable across replay/reorg, rate-limited per epoch, expiring deterministically, and (gated) gate
role/finality eligibility on an active on-chain ticket — local caches stay non-consensus. Optional
future work: a builder path to auto-include locally-cached registrations (default `None`); a separate
ECDSA registration signature (the Sybil PoW is the deterministic identity cost).

## Safety

No change to `multi_role_amounts`/coinbase validator, `block_reward`, LWMA/PoW/anchors, phase21d/21e/22a,
existing ticket/Sybil validation, or mainnet. Mainnet hard-off throughout. **Production-ready: no.
Mainnet-ready: no. Audited: no.**
