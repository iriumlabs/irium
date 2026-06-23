# PoAW-X Phase 32 — On-Chain Ticket Store: Design

Closes deferred Phase 27 item **2E**: make Miner Work Tickets consensus-replayable via block-carried
registrations + a deterministic on-chain ticket store, with epoch rate-limiting, expiry, and (gated)
eligibility enforcement. **Testnet/devnet only. Mainnet hard-off (`network_id == 0`). NOT audited /
production-ready / mainnet-ready.** Branch `testnet/poawx-phase32-onchain-ticket-store` (from `fae91bb`).

## Current ticket / Sybil primitives (audited)

- `MinerWorkTicket` (`src/poawx_ticket.rs:22`): `version, network_id, miner_pkh, epoch,
  assignment_public_key[33], sybil_work_{nonce,digest}, recent_reward_score, valid/invalid_work_count,
  penalty_status, bond_reference?, issued_height, expiry_height`. Variable-length wire; `digest()` =
  `SHA256(TICKET_DOMAIN || serialize())`. **Unsigned by design** — identity/cost binding comes from the
  Sybil PoW (`compute_sybil_digest` binds `network/miner_pkh/epoch/assignment_key/nonce`;
  `sybil_threshold_bits` leading-zero target).
- `MinerWorkTicket::validate(expected_network, current_height, require_bits)` (`:207`): network/version,
  `issued_height <= current < expiry_height`, valid penalty status, sybil-digest binding + threshold.
- `TicketProof` (`:351`): the compact per-role binding carried in the ext (`miner_pkh, epoch,
  assignment_public_key, expiry_height, ...`), validated when `tickets_enforced(height)` by
  `validate_phase20_ticket_proofs` (`src/chain.rs:3211`).
- Gates: `tickets_activation_height/gate/active/required/enforced` (mainnet hard-off).

**Gap (2E):** tickets are validated as **external per-block proofs**; there is no **on-chain registry**
all nodes agree on. Phase 32 adds block-carried registrations + a replayable store, exactly mirroring
Phase 30's block-carried double-sign evidence.

## Block-carried registration (the `TKT1` ext section)

`PoawxTicketRegistrationV1` wraps a `MinerWorkTicket` (`ticket_id = ticket.digest()`). Carried in a new
**trailing-optional `TKT1` section** on `Phase20ReceiptExt` (the proven pattern; `None` ⇒ byte-identical
to pre-32 exts; the ext digest is bound into the irx1 root, so registrations are **committed**). Wire:
`TKT1(4) || count(u16 LE) || count × (len(u16 LE) || ticket bytes)`.

- **Max per block:** `MAX_TICKET_REGISTRATIONS_PER_BLOCK = 16` (rejected at deserialize + connect_block).
- **Canonical / dedup:** carried in strictly-increasing `ticket_id` order; in-block duplicate id or
  non-canonical order **rejects the block**.

## Registration validation (in `connect_block`, testnet-gated; mainnet hard-off)

When `ticket_store_active(height)`: collect registrations, reject `> MAX` / duplicate / non-canonical,
then for each call `MinerWorkTicket::validate(network_id, height, sybil_threshold_bits())` — **reusing
the existing ticket validator** (network/version, `issued <= height < expiry`, sybil binding +
threshold, penalty status). Any invalid registration **rejects the block**. ("Signature by miner" is
satisfied by the Sybil PoW binding — the existing deterministic, unsigned design; no new crypto.)

## On-chain ticket store (deterministic, replayable)

`ChainState.ticket_store: PoawxTicketStore` — derived from the active chain's block-carried
registrations (cold replay/rebuild reconstruct it; no new persistence). `PoawxTicketStoreEntry`:
`{miner_pkh, epoch, assignment_public_key, expiry_height, registered_height, ticket_id}`, indexed by
`ticket_id` with rate-limit indices on `(miner_pkh, epoch)` and `(assignment_public_key, epoch)`.

- **Rate-limit (one active per epoch):** applying a registration whose `(miner_pkh, epoch)` OR
  `(assignment_public_key, epoch)` already has a live (non-expired) entry is rejected (deterministic).
  Duplicate `ticket_id` is an idempotent no-op across blocks.
- **Expiry / pruning:** entries with `expiry_height <= current tip` are deterministically pruned on
  apply (replayable since derived from the chain).
- **Epoch window:** bound via the ticket's `issued_height <= height < expiry_height` (old = expired =
  rejected; future = issued-in-future = rejected). No separate height→epoch map needed.

## Effective timing (non-retroactive)

A registration in block `H` is validated during `H` and **applied after `H` is committed**, usable from
`H+1`. Mirrors Phase 28/30 (capture-then-apply-after-commit). The eligibility check at `H` consults the
store from blocks `< H`, so `H`'s own registrations cannot satisfy `H`'s eligibility.

## Eligibility enforcement (additive, gated, mainnet-off)

When `ticket_store_enforced(height)`: an additive check `validate_block_ticket_store_eligibility`
requires every rewarded role's `TicketProof` to correspond to an **active registered ticket** in the
store — matching `(miner_pkh, epoch, assignment_public_key)` with `expiry_height > height` — else the
block is rejected (`phase32: role ticket not registered on-chain`). This is a strict **superset** of the
existing `validate_phase20_ticket_proofs` (which still validates the proof itself); it only adds
rejections. Off by default ⇒ zero regression. Penalized tickets are already excluded by the existing
penalty path + Phase 30.

## Reorg + replay

Store is a pure function of the active chain. Tip extension / cold replay / rebuild apply incrementally.
`reorg_to_tip` **snapshots** the store on entry, **restores** on a failed reorg, and **rebuilds from the
new active chain** on success (abandoned-fork registrations never pollute the active chain).

## Local cache (non-consensus)

`NodeTicketRegistrationCache` (bounded, dedup, mainnet-off) helps a builder collect registrations but
**never** touches `ChainState.ticket_store` or block validity. Only block-carried, replayed
registrations affect consensus (tested).

## Tests (`phase32_*`)

Valid registration accepted + store updated + active at H+1; missing on-chain ticket rejected for a role
(gate on); invalid registration (bad sybil / wrong network / malformed / expired / future) rejects;
duplicate ticket id / same miner+epoch / same VRF+epoch rejected; expiry deterministic + expired ticket
unusable; penalty interaction; non-canonical order / over-cap rejected; local-only no consensus effect;
reorg restores/rebuilds; replay reconstructs; mainnet no-op; regression (phase26/28/29/30/31 + full).

## Out of scope / non-goals

- A separate ECDSA registration signature (the Sybil PoW is the deterministic identity cost; adding a
  signature is a future option, not needed for replayable consensus).
- Builder auto-inclusion of locally-cached registrations beyond tests (default `None`).
- No change to `multi_role_amounts`/coinbase validator, `block_reward`, LWMA/PoW/anchors,
  phase21d/21e/22a, existing ticket/Sybil validation, or mainnet.
