# PoAW-X Phase 33 — Dominance-State Commitment (Implemented)

Closes deferred Phase 27 item **3C**: the PoAW-X anti-domination state digest is now block-carried and
validated, so every node verifies the same dominance-state transition. **Testnet/devnet only. Mainnet
hard-off (`network_id == 0`). NOT audited / production-ready / mainnet-ready.** Branch
`testnet/poawx-phase33-dominance-state-commitment` (from `8f2a64d`).

## Where the commitment is carried

`PoawxDominanceCommitmentV1 { version, network_id, block_height, pre_state_digest[32],
post_state_digest[32] }` (fixed 74-byte wire), carried in a new **trailing-optional `DMC1` ext
section** on `Phase20ReceiptExt` (the proven pattern; `None` ⇒ byte-identical to pre-33 exts; the ext
digest is bound into the irx1 root, so the commitment is **committed**). (`DOM1` is the Phase 21C
dominance-weights section; the new magic is `DMC1`.) The underlying state is the existing reorg-safe
`PersistentDominance`; its order-independent `digest()` is the committed state digest — **no new state,
no new block root.**

## Pre / post digest timing (non-retroactive, replayable)

- **Block H validates against the pre-H state:** `pre_state_digest == self.dominance.digest()` (state
  from blocks `< H`).
- **Block H commits the post-H state:** `post_state_digest ==` the digest **after** applying H's
  role-reward events — computed during validation **without mutating** (clone `self.dominance`, apply
  H's events exactly as `apply_block_dominance` does, including internal pruning, then digest the
  clone).
- The post-H digest is the pre-state for H+1 (the existing `apply_block_dominance` after commit produces
  the identical state deterministically).

Non-retroactive (H's reward application does not affect H's own weight validation) and replayable (both
digests derive from chain-applied events).

## Consensus enforcement

In `connect_block`, gated by `dominance_commitment_active(height)` (requires anti-domination active;
mainnet hard-off): `validate_block_dominance_commitment` checks every `DMC1` commitment's
version/network/height and `pre`/`post` digests against the computed values; **mismatch rejects the
block**. When `dominance_commitment_enforced(height)` (active + required, **off by default**) and no
commitment is present, the block is rejected. **Additive** — it does not change weight validation,
reward amounts, or the canonical coinbase validator.

## Window / pruning

Unchanged — `apply_event` prunes deterministically (window_id/lookback/`PRUNE_MARGIN_WINDOWS`). The
committed digest reflects the pruned post-state and is stable across replay (a deterministic function of
the applied events).

## Reorg + replay

The dominance state is **already** reorg-safe (apply on `connect_block`, revert on
`disconnect_tip_block`) and replay-reconstructable. The commitment rides on it: on reorg, disconnected
blocks revert the state and reconnected blocks re-validate their commitments against the deterministic
state; on cold replay, `connect_block` re-validates. **No new ChainState field and no new reorg
snapshot/restore are needed** — abandoned-fork state is already reverted; the digest is a pure function
of the active chain.

## Local-only state has no consensus effect

There is no local/off-chain dominance cache: the state is derived **only** from connected blocks. The
commitment is the sole consensus input; a fresh state that replays the same blocks reaches the identical
digest (`phase33_dominance_state_replays_from_blocks`).

## Tests

`cargo test --lib phase33 -- --test-threads=1` → **9 passed / 0 failed** (2 commitment unit + 7
consensus): commitment roundtrip + validate (network/version/height/pre/post mismatches; mainnet-off);
gate mainnet-off; valid commitment accepted (pre + post match; ext digest changes/committed; wire
round-trips); bad post + bad pre rejected; reward events evolve the digest; replay reconstructs the
digest; **enforced-requires-commitment** (real `connect_block` rejects a block lacking `DMC1`);
additive-gate no-false-reject (valid chain connects with gate active); mainnet gate off.

Regression: full lib suite **805 passed / 0 failed** (was 796; +9). `dominance` 21/0; `reward` 18/0.
`poawx-sim` bin **16/0** (+1). Release builds (`iriumd`, `poawx-live-proof-harness`, `poawx-sim`)
succeed. Wire-format backward-compat confirmed (phase20 + dominance green; `None` ⇒ byte-identical).

## Simulation

`poawx-sim` `dominant_miner` reports `dominance_state_committed`, `dominance_pre_digest`,
`dominance_post_digest`, `reward_concentration_permille`, `dominant_miner_weight_reduction`, and
`digest_replay_stable` (using the real `PersistentDominance` + `fairness_weight`). Deterministic;
`dominance_commitment_modeled` passes.

## Status of 3C

**Consensus-enforced.** The dominance-state transition is block-carried (pre/post digest), validated in
`connect_block`, deterministic, replayable across replay/reorg, and local-only history has no consensus
effect. **Hard dominance caps are deferred** (Phase 33's goal is state commitment; `fairness_weight`
already reduces concentration without a hard cap — a cap is a broader policy decision documented as
future work).

## Safety

No change to `fairness_weight`, `multi_role_amounts`/coinbase validator, `block_reward`, LWMA/PoW/anchors,
phase21d/21e/22a, existing dominance weight validation, Phase 30/31/32 enforcement, or mainnet. Mainnet
hard-off throughout. **Production-ready: no. Mainnet-ready: no. Audited: no.**
