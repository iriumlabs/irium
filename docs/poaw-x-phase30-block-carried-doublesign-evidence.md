# PoAW-X Phase 30 — Block-Carried Double-Sign Evidence (Consensus Enforcement)

Completes the consensus piece of Phase 27 item **5B**: double-sign penalties are now driven by
**block-carried, deterministically-validated evidence**, applied during block connection/replay, and
**enforced** by excluding penalized finality participants from future finality committee/votes.
**Testnet/devnet only. Mainnet hard-off (`network_id == 0`). NOT audited / production-ready /
mainnet-ready.** Branch `testnet/poawx-phase30-block-carried-doublesign-evidence` (from `df0cc92`).

## Where evidence is carried

A new **trailing-optional `DSE1` section** on `Phase20ReceiptExt` (`src/poawx.rs`) — the same proven
pattern as the 7 prior phases: present-only, and `None` ⇒ byte-identical to pre-30 exts (the 768-test
baseline and the live-validated block format are preserved). The ext digest is bound into the irx1 root
that `connect_block` already validates, so **evidence is committed** — a peer cannot strip or alter it
without changing the block hash. Wire: `DSE1(4) || count(u16 LE) || count × evidence(466 bytes each)`.

- Field: `Phase20ReceiptExt.double_sign_evidence: Option<Vec<PoawxDoubleSignEvidenceV1>>`.
- **Max evidence per block:** `MAX_DOUBLE_SIGN_EVIDENCE_PER_BLOCK = 16` (anti-spam; rejected at
  deserialize and at `connect_block`).
- **Canonicalization / dedup:** evidence is carried in **canonical order** (strictly increasing
  `evidence_id`); an in-block duplicate id or non-canonical order **rejects the block**. Across blocks,
  re-applying the same `evidence_id` is an idempotent no-op.

## Validation (in `connect_block`, testnet-gated; mainnet hard-off)

When `double_sign_penalty_active(height)`: collect the block's evidence, reject if `> MAX` / duplicate
/ non-canonical, then for each piece derive the **committee** deterministically from the on-chain block
at the evidence's `target_height` (its SUPPORT-role solver pkhs) — requiring `target_height <
connecting_height` — and run `PoawxDoubleSignEvidenceV1::validate`. **Any invalid evidence (bad
signature / wrong network / non-committee / not equivocation / unknown offense height) rejects the
block.**

## Penalty timing (deterministic, non-retroactive)

Evidence in block `H` is validated while connecting `H` and **applied after `H` is committed**, becoming
effective **from `H+1`**. Mirrors the Phase 28 capture-then-apply-after-commit pattern, so `H`'s own
finality (validated before the apply) is unaffected by `H`'s evidence. The penalty state
(`ChainState.doublesign_penalty`, a `PoawxDoubleSignPenaltyState`) is **derived from the active chain**
— cold replay/rebuild reconstruct it; no new persistence.

## Enforcement (the consensus hook)

`validate_block_finality` (every block) now **rejects** a block whose finality proof contains a vote by
a currently-suspended identity (per the penalty state from EARLIER blocks): `phase30: penalized signer
in finality committee`. Because a penalized signer can no longer be a valid committee voter, they cannot
anchor the SUPPORT/finality reward either (the finality reward already stands only with a valid finality
proof). This is real, deterministic, replayable consensus enforcement.

## Reorg + replay

- **Tip extension / cold replay / rebuild:** `connect_block` applies evidence incrementally ⇒ state
  reconstructs from the chain.
- **Reorg (`reorg_to_tip`):** the penalty state is **snapshotted** on entry and **restored** on a failed
  reorg; on a **successful** reorg it is **rebuilt from the new active chain**
  (`rebuild_doublesign_penalty_from_chain`) — so evidence carried only on an abandoned fork **never**
  pollutes the active chain, and the new chain's evidence is fully applied.

## Local vs consensus

The Phase 29 `NodeDoubleSignEvidenceCache` (gossip/local) may help a proposer *collect* evidence, but it
**never** touches `ChainState.doublesign_penalty` or block validity. Only block-carried, replayed
evidence affects consensus (test `phase30_local_evidence_not_consensus_until_included`).

## Tests

`cargo test --lib phase30 -- --test-threads=1` → **7 passed / 0 failed**:

- `phase30_block_carried_evidence_validates_and_applies` — committee derived from chain; valid evidence
  validates; ext digest changes with evidence (committed) and round-trips; applying updates state.
- `phase30_invalid_block_carried_evidence_rejected` — bad signature / non-committee / future offense
  height / in-block duplicate / non-canonical order all rejected.
- `phase30_evidence_cap_enforced` — over-cap rejected.
- `phase30_penalized_signer_excluded_from_future_finality` — **real `connect_block`**: with no penalty
  the next block connects (non-retroactive); with the member penalized, the next all-gates block (whose
  finality vote is by that member) is **rejected** (`phase30: penalized signer`).
- `phase30_local_evidence_not_consensus_until_included` — local cache evidence leaves consensus state
  empty; a normal block keeps it empty.
- `phase30_rebuild_penalty_clears_stale_evidence` — rebuild from a chain with no evidence clears
  non-chain penalties (abandoned-fork safety).
- `phase30_mainnet_no_consensus_penalty` — gate off for `network_id == 0`.

Regression: full lib suite **775 passed / 0 failed** (was 768; +7). `poawx-sim` bin **13/0** (+1).
Release builds (`iriumd`, `poawx-live-proof-harness`, `poawx-sim`) all succeed. Wire-format
backward-compat confirmed (phase20 + phase26 suites green; `None` ⇒ byte-identical).

## Simulation

`poawx-sim` `finality_attack` now distinguishes local detection from consensus enforcement and reports
`evidence_included_in_block`, `consensus_penalty_applied`, and `future_finality_eligibility_removed`.
Deterministic; `block_carried_penalty_modeled` test passes.

## Status of 5B

**Consensus-enforced.** Block-carried evidence is validated + applied deterministically, replayable
across replay/reorg, and excludes penalized signers from future finality — local gossip evidence stays
non-consensus. Optional future work: a proposer/builder path to auto-include locally-cached evidence in
candidate blocks (kept out of scope here; tests inject evidence into constructed blocks and pre-populate
penalty state to exercise `connect_block`).

## Safety

No change to LWMA/PoW/reward/SHA-256d anchors, phase21d/21e/22a, finality threshold/committee
validation, or signature checks. Mainnet hard-off throughout. **Production-ready: no. Mainnet-ready: no.
Audited: no.**
