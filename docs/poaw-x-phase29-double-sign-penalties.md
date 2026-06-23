# PoAW-X Phase 29 — Double-Sign Penalty Wiring (Partial: evidence + penalty state)

Partially closes deferred Phase 27 item **5B**: validated finality double-sign evidence now drives a
deterministic, replayable PoAW-X penalty. **Testnet/devnet only. Mainnet hard-off (`network_id == 0`).
NOT audited / production-ready / mainnet-ready.** Branch `testnet/poawx-phase29-double-sign-penalties`
(from `199ed24`).

## What was implemented

A new module `src/poawx_doublesign.rs` (registered in `src/lib.rs`):

- **`PoawxDoubleSignEvidenceV1`** — two conflicting finality votes, stored in canonical order (by vote
  digest), with `serialize`/`deserialize`, an order-independent `evidence_id`, and `validate`.
- **`PoawxDoubleSignPenaltyState`** — a deterministic, **replayable** penalty state: idempotent per
  `evidence_id` and monotonic suspension window, so the resulting state (and its `digest`) is a pure
  function of the *set* of evidence, independent of application order. Reuses the existing
  `poawx_penalty` primitives.
- **`detect_double_sign`** — a pure helper that finds equivocation pairs among a set of votes
  (observability).
- **`NodeDoubleSignEvidenceCache`** — a bounded, dedup'd, mainnet-hard-off **LOCAL** evidence cache.

## Exact double-sign definition implemented

A finality participant double-signs when two finality votes share the same **finality domain**
`(network_id, target_height, committee_epoch, vote_type, member_pkh)` and the same `member_pubkey`, but
commit to **different `block_hash`**, **both signatures verify individually**, and the signer is a
**committee member**. Explicitly NOT double-signing (no penalty): duplicate of the same vote; invalid
signature; wrong network; different height; different epoch; different vote_type; different identity;
non-committee voter; malformed vote. (Verified by the `phase29_*` tests, including the no-false-penalty
cases.)

## Consensus-enforced or local-only?

**Local / primitive only — NOT consensus-enforced.** This is the deliberate, safe boundary required by
the consensus-safety rule: current blocks do **not** carry double-sign evidence, so making
locally-detected evidence affect block validity / reward / committee would let nodes that saw different
evidence **diverge**. Therefore Phase 29 ships:

- Evidence **validation** (pure, deterministic).
- A deterministic, **replayable** penalty **state** primitive (could be driven identically by a future
  block-carried-evidence path).
- A bounded **local** evidence cache + detector for observability — these never reject blocks or change
  consensus.

It does **not** wire the penalty into `connect_block`, the reward manifest, or committee selection.

## Penalty effect and window

A confirmed double-sign sets the offender's `PenaltyStatus` to **`SuspendedForEpoch`**, with
`suspended_until_epoch = max(existing, committee_epoch + window)` (default window = 1 epoch,
`DEFAULT_SUSPEND_EPOCHS`). While suspended, `eligible_for_high_trust_role()` is **false** and
`weight_multiplier_permille()` is **0** — i.e. ineligible for the finality/SUPPORT committee role (and,
where reward/committee selection consults penalty status, for the finality reward). After the window
(`expire_if_due`), the status returns to `Warned` (eligible again). This reuses the existing Phase 21B
eligibility path; no new eligibility semantics were invented.

## Tests

`cargo test --lib phase29 -- --test-threads=1` → **12 passed / 0 failed**:

- `phase29_accepts_valid_double_sign_evidence` (+ idempotent re-apply)
- `phase29_duplicate_vote_is_not_double_sign`
- `phase29_rejects_invalid_double_sign_signature`
- `phase29_rejects_wrong_network_evidence` (+ mainnet hard-off)
- `phase29_rejects_non_committee_double_sign`
- `phase29_different_heights_not_double_sign`
- `phase29_double_sign_evidence_canonical_order` (order-independent id + wire + round-trip)
- `phase29_penalized_finality_member_ineligible` (ineligible in window, eligible after expiry)
- `phase29_penalty_state_replays_deterministically` (order-independent state digest)
- `phase29_mainnet_applies_no_penalty`
- `phase29_detect_double_sign_from_votes`
- `phase29_local_evidence_cache_bounded_and_dedup`

Regression: full lib suite **768 passed / 0 failed** (was 756; +12). `poawx-sim` bin **12/0** (+1).
Release builds (`iriumd`, `poawx-live-proof-harness`, `poawx-sim`) all succeed.

## Simulation

`poawx-sim` `finality_attack` now models double-signing and reports `double_sign_detected`,
`penalty_applied`, and `penalized_finality_weight_removed` (using the real `PenaltyStatus` weight /
eligibility). Deterministic output preserved; `double_sign_penalty_modeled` test passes.

## Safety boundaries

- No change to finality threshold/committee validation, signature checks, phase21d/21e/22a,
  LWMA/PoW/reward, SHA-256d anchors, or mainnet behavior.
- Mainnet hard-off: `validate`/`apply_evidence`/cache all reject `network_id == 0`.
- No local-only evidence rejects blocks; no consensus divergence risk introduced.

## Remaining gap (still deferred)

**Consensus enforcement** requires a **block-carried double-sign evidence** design so every node
applies the identical penalty deterministically (and the penalty then excludes the signer from finality
reward / committee in `connect_block`). That block-carried-evidence + reward/committee wiring is the
remaining part of 5B and is **not** implemented here. Items 1D, 2E, 3C, 6F from Phase 27 also remain.

**Production-ready: no. Mainnet-ready: no. Audited: no.**
