# PoAW-X Phase 30 — Block-Carried Double-Sign Evidence: Design

Completes the deferred consensus piece of Phase 27 item **5B**: carry validated double-sign evidence in
blocks, apply it to deterministic, replayable penalty state during block connection, and exclude
penalized finality participants from future finality committee/reward in consensus. **Testnet/devnet
only. Mainnet hard-off (`network_id == 0`). NOT audited / production-ready / mainnet-ready.** Branch
`testnet/poawx-phase30-block-carried-doublesign-evidence` (from `df0cc92`).

## Phase 29 recap (the local primitive)

Phase 29 (`src/poawx_doublesign.rs`) delivered `PoawxDoubleSignEvidenceV1` (validated equivocation
evidence with an order-independent `evidence_id`), `PoawxDoubleSignPenaltyState` (deterministic,
replayable, idempotent-by-id, monotonic suspension window), `detect_double_sign`, and a bounded LOCAL
evidence cache. These were **local-only** — not consensus. Phase 30 makes the penalty
**consensus-carried**.

## Where block-carried evidence lives

`Phase20ReceiptExt` (`src/poawx.rs:607`) already uses a proven **trailing-optional section** pattern: 7
phases (precommit/ticket/dominance/candidate/puzzle/finality/committed-admission/true-VRF) each append a
magic-prefixed, present-only section, and `None` ⇒ byte-identical to the prior wire format. Phase 30
adds one more trailing section:

- New field `double_sign_evidence: Option<Vec<PoawxDoubleSignEvidenceV1>>`.
- New section magic **`DSE1`**: `magic(4) || count(u16 LE) || count × evidence.serialize()` (each
  evidence is the fixed `EVIDENCE_WIRE` = 466 bytes). Present-only; absent ⇒ byte-identical to pre-30
  exts (so the 768-test baseline and the live-validated format are preserved).
- The `precommit_root == None` branch that writes a leading `0` flag when any trailing section is
  present gains `|| double_sign_evidence.is_some()`.

This keeps evidence inside the existing receipt-ext bytes that are already committed into the receipts
root and validated in `connect_block` — no new block-level field, no merkle/storage change.

## Serialization, ordering, dedup, cap

- **Deterministic serialization:** evidence is stored in **canonical order** — sorted by `evidence_id`
  — and de-duplicated by `evidence_id` before serialization. The wire reader rejects a section whose
  count exceeds the cap.
- **Max per block:** `MAX_DOUBLE_SIGN_EVIDENCE_PER_BLOCK = 16` (bounded anti-spam). A block carrying
  more is rejected at deserialize and at `connect_block`.
- **Duplicate handling (chosen rule):** within a block, duplicate `evidence_id`s are a **reject** at
  `connect_block` (a well-formed proposer canonicalizes + dedups; a block with in-list duplicates is
  malformed). Across blocks, re-applying the same `evidence_id` is a deterministic **no-op** (idempotent
  penalty state).

## Validation (in `connect_block`, testnet-gated)

When `double_sign_penalty_active(height)` (mainnet hard-off):

1. Collect `double_sign_evidence` from the block's receipt exts; reject if `> MAX`; reject in-list
   duplicate ids; require canonical sorted order.
2. For each evidence, derive the **committee** deterministically from the on-chain block at the
   evidence's `target_height` (the SUPPORT-role solver pkhs in that block's candidate set). Require
   `target_height < connecting_height` (the offense is strictly in the past, on the chain being
   extended); reject if the block/committee is unavailable.
3. `evidence.validate(network_id, &committee)` (the Phase 29 validator: both signatures valid, same
   domain/identity, different block hashes, committee member). **Any invalid evidence rejects the
   block.**

## Penalty application + effective timing (deterministic, non-retroactive)

**Rule (preferred):** evidence in block `H` is validated while connecting `H` and applied to penalty
state **after `H` is committed**, becoming effective for eligibility/reward checks **from `H+1`
onward**. This avoids retroactively invalidating finality/reward choices already made for `H`.

Implementation mirrors Phase 28's finalized-checkpoint pattern (capture-during-validation,
apply-after-commit):

- `ChainState` gains `doublesign_penalty: PoawxDoubleSignPenaltyState` (in-memory; derived from the
  active chain, so cold replay/rebuild reconstruct it — no new persistence).
- In `connect_block`: `validate_block_finality(H)` consults `doublesign_penalty` as it stands from
  blocks `< H` and **rejects** the block if any finality vote's `member_pkh` is currently suspended
  (the **exclusion hook**: a penalized signer cannot be in the finality committee/votes). Then the
  block's own evidence is captured and applied **after commit** — so `H`'s evidence cannot affect `H`'s
  own finality (non-retroactive), only `H+1+`.

## Reorg + replay behavior

The penalty state is a **pure function of the active chain's block-carried evidence** (like the Phase 28
finalized checkpoint). Therefore:

- **Tip extension:** incremental apply (capture-after-commit).
- **Cold replay / rebuild:** `connect_block` re-applies as blocks replay ⇒ reconstructs the state.
- **Reorg:** `reorg_to_tip` **snapshots** the state on entry and **restores** it on a failed reorg; on a
  **successful** reorg it **rebuilds** the state from the new active chain
  (`rebuild_doublesign_penalty_from_chain`), so evidence on an abandoned fork **never** pollutes the
  active chain and the new chain's evidence is fully applied. Rebuild is deterministic
  (chain-order + committee-from-chain).

## Why local gossip-only evidence stays non-consensus

The LOCAL `NodeDoubleSignEvidenceCache` (Phase 29) may help a proposer *collect* evidence, but it never
rejects blocks or alters penalty state. Only evidence **included in a block and replayed by every node**
affects consensus. A test asserts that local-cache evidence alone changes nothing until included in a
block.

## Mainnet safety

All Phase 30 consensus paths are behind `double_sign_penalty_active(height)` /
`finality_committee_enforced(height)`, both hard-off for `network_id == 0`. On mainnet the
`double_sign_evidence` section is never produced/required, the penalty state stays empty, the exclusion
check is a no-op, and the ext stays byte-identical. No change to LWMA/PoW/reward/anchors,
phase21d/21e/22a, finality threshold/committee validation, or signature checks.

## Tests (`phase30_*`)

Block with valid evidence accepted + penalty applied; invalid evidence (bad sig / wrong network /
non-committee / duplicate vote / malformed) rejects the block; canonical order + list determinism;
evidence cap enforced; local-only evidence has no consensus effect until included; penalized signer
excluded from future finality (H+1); non-retroactive (H unaffected); replay reconstructs state; reorg
restores/rebuilds state and abandoned-fork evidence does not pollute; mainnet unaffected; regression
(phase26/28/29 + full suite).

## What remains out of scope

- Builder/harness auto-inclusion of evidence beyond tests (kept optional; default `None`).
- Reward-manifest coinbase exclusion beyond the finality-committee-vote exclusion already enforced
  (the finality reward already stands only with a valid finality proof, and a penalized signer can no
  longer be a valid committee voter — so they cannot anchor the SUPPORT/finality reward).
- Economic slashing (`SlashedPlaceholder` stays a placeholder).
