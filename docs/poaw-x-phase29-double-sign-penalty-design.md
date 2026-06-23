# PoAW-X Phase 29 — Double-Sign Penalty Wiring: Design

Design for deferred Phase 27 item **5B**: wire detected finality double-signing into deterministic
PoAW-X penalty state. **Testnet/devnet only. Mainnet hard-off (`network_id == 0`). NOT audited /
production-ready / mainnet-ready.** Branch `testnet/poawx-phase29-double-sign-penalties` (from `199ed24`).

## Current finality vote structure (audited)

`FinalityVoteV1` (`src/poawx_finality.rs:78`): `version, network_id, target_height, block_hash,
parent_hash, committee_epoch, member_pkh, member_pubkey, ticket_digest, vote_type, signature[64]`.
- `verify(network_id, target_height, block_hash)` (`:243`): checks version/network/height/block-hash
  binding, `hash160(member_pubkey) == member_pkh`, and a valid secp256k1 signature over the vote digest.
  So a vote is *individually verifiable* against its own `block_hash`.
- `digest()` binds all fields; signing uses `sign_prehash(digest)`.

## Where conflicting votes are detected today

`NodeFinalityVoteCache` (`src/poawx_finality.rs:593`) is keyed by
`(target_height, block_hash, vote_type, member_pkh)`. Because **block_hash is in the key**, two
equivocating votes by the same member (same height/epoch/type, *different* block_hash) land in
**different** keys and coexist — the existing "conflicting vote for member" check (`:666`) only fires
for the *same* key with a different digest (a different anomaly, not classic equivocation). **So
classic double-signing is NOT detected today.** Phase 29 adds a cross-key detector.

## Existing penalty state

`src/poawx_penalty.rs` already provides the deterministic primitives: `PenaltyStatus`
(Clean/Warned/TemporarilyReduced/SuspendedForEpoch/SlashedPlaceholder), `PenaltyRecord`
(`record_invalid_work`, `expire_if_due`, `eligible_for_high_trust_role`), `PenaltyThresholds`, and
mainnet-hard-off gates. Tickets already expose `penalty_status` (`MinerWorkTicket.penalty_status`,
`TicketProof.penalty_status`), and the Phase 21B ticket-proof validator already blocks
suspended/slashed identities from high-trust (SUPPORT/finality) roles when `penalty_state_enforced`.

## Exact double-sign definition (implemented)

A finality participant **double-signs** when two finality votes share the same **finality domain** —
`(network_id, target_height, committee_epoch, vote_type, member_pkh)` and the same `member_pubkey` —
but commit to **different `block_hash`**, and **both signatures verify individually**, and the member
is a **committee member**. Explicitly **NOT** double-signing (no penalty): a duplicate copy of the same
vote (same digest); an invalid signature; wrong network; different height; different epoch; different
vote_type; a different identity; a non-committee member; or a malformed vote.

## How the penalty is made deterministic / replayable

`PoawxDoubleSignPenaltyState` is a pure, order-independent function of the **set** of validated
evidence:
- Evidence is identified by a canonical `evidence_id` = `SHA256(DOMAIN || lo_vote_digest ||
  hi_vote_digest)` with the two vote digests sorted, so `vote_a`/`vote_b` order is irrelevant.
- Applying evidence is **idempotent** by `evidence_id` (a re-applied or re-gossiped piece of evidence
  does not double-count).
- A double-sign immediately sets `SuspendedForEpoch` and `suspended_until_epoch =
  max(existing, epoch + window)` (monotonic max ⇒ application order does not matter).
- `state.digest()` gives a deterministic commitment; replaying the same evidence set in any order
  yields the same digest — the replay test asserts this.

## Penalty effect

A penalized member's `PenaltyStatus` is `SuspendedForEpoch`, so
`eligible_for_high_trust_role()` is **false** for the suspension window — i.e. ineligible for the
finality/SUPPORT committee role (and, where reward/committee selection consults penalty status, for the
finality reward). After the window (`expire_if_due`), it returns to `Warned` (eligible again). This
reuses the existing Phase 21B eligibility path; no new eligibility semantics are invented.

## CONSENSUS-SAFETY scope (the important boundary)

Current blocks do **not** carry double-sign evidence. Per the consensus-safety rule, **local
gossip-detected evidence must not affect block validity / reward / committee in a way nodes could
disagree on.** Therefore Phase 29 deliberately stops at:

1. **Evidence validation** (`PoawxDoubleSignEvidenceV1::validate`) — a pure, deterministic primitive.
2. **Deterministic, replayable penalty state** (`PoawxDoubleSignPenaltyState`) — a pure primitive that a
   *future* block-carried-evidence path could drive identically on every node.
3. **A bounded LOCAL evidence cache** (`NodeDoubleSignEvidenceCache`) for detection/observability — it
   does **not** reject blocks or alter consensus.

It does **NOT** wire the penalty into `connect_block` block acceptance, the reward manifest, or
committee selection, because that would require the evidence to be **consensus-carried** (in blocks) so
every node penalizes identically. That block-carried-evidence design is the **remaining gap** (see
Known Limitations). So **Phase 29 partially closes 5B**: evidence + deterministic penalty-state
primitive + local detection — not full consensus enforcement.

## Files

- New `src/poawx_doublesign.rs` (+ `pub mod` in `src/lib.rs`): evidence struct + canonical id +
  serialize/deserialize + `validate`; `PoawxDoubleSignPenaltyState`; `NodeDoubleSignEvidenceCache`.
- `src/poawx_finality.rs` (test-only helper if needed); reuses `FinalityVoteV1`.
- `src/poawx_penalty.rs` reused unchanged.
- `src/bin/poawx-sim.rs`: model double-sign detection + penalty in the finality-attack scenario.

## Tests (`phase29_*`)

Valid evidence accepted + penalty recorded; duplicate-vote not evidence; invalid signature rejected;
wrong network rejected; non-committee voter rejected; different heights not double-sign; canonical
order id-stable; penalized member ineligible during window + eligible after expiry; penalty state
replays deterministically (order-independent digest); mainnet (`network_id == 0`) applies no penalty;
regression (phase26/28 + full suite).

## Out of scope (intentional)

- Block-carried double-sign evidence and consensus block rejection / reward/committee exclusion based on
  it (the remaining 5B consensus-enforcement gap).
- Economic slashing (`SlashedPlaceholder` stays a placeholder).
- Changing finality threshold/committee validation, signature checks, phase21d/21e/22a, LWMA/PoW/reward,
  or mainnet behavior.
