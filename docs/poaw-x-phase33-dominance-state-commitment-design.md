# PoAW-X Phase 33 — Dominance-State Commitment: Design

Closes deferred Phase 27 item **3C**: commit the PoAW-X anti-domination (recent-reward-concentration)
state digest into block-carried consensus data so every node verifies the same state transition.
**Testnet/devnet only. Mainnet hard-off (`network_id == 0`). NOT audited / production-ready /
mainnet-ready.** Branch `testnet/poawx-phase33-dominance-state-commitment` (from `8f2a64d`).

## Current anti-domination / fairness primitives (audited)

- `PersistentDominance` (`src/poawx_dominance.rs:278`, `#[derive(Clone)]`): the reorg-safe state — a
  `BTreeMap<(miner_pkh, window_id), DominanceBucket>` of recent role-reward totals. `apply_event` /
  `revert_event` are exact inverses; `apply_event` prunes internally (`prune`, window/lookback +
  `PRUNE_MARGIN_WINDOWS`). `digest()` (`:413`) is an **order-independent** SHA256 over the buckets.
  **This IS the `PoawxDominanceState`; `digest()` IS the `PoawxDominanceStateDigest`.**
- `fairness_weight = work_score*1000/(1000+recent_reward_share_permille)` (`:122`).
- Enforced in `connect_block`: `validate_block_dominance_weights` (`src/chain.rs:1825`, before commit)
  validates the per-role weights against the **pre-block** state; `apply_block_dominance` (`:1863`,
  after commit) applies the block's role-reward events; `disconnect_tip_block` calls
  `revert_block_dominance` (`:1086`). So the state is already **reorg-safe + replay-reconstructable**.
- Role-reward events: `dominance_events_from_block` (`:1098`) — `multi_role_amounts(block_reward(h))`
  to `[Primary=worker_pkh, Compute, Verify, Support]`.

**Gap (3C):** `digest()` is computed but **not block-carried/validated** — nodes never cross-check the
dominance-state transition. Phase 33 commits it.

## Block-carried commitment (the `DMC1` ext section)

`PoawxDominanceCommitmentV1 { version, network_id, block_height, pre_state_digest[32],
post_state_digest[32] }` — fixed 74-byte wire. Carried in a new **trailing-optional `DMC1` section** on
`Phase20ReceiptExt` (the proven pattern; `None` ⇒ byte-identical to pre-33 exts; the ext digest is bound
into the irx1 root, so the commitment is **committed**). (`DOM1` is already used by the Phase 21C
dominance-weights section; the new magic is `DMC1`.)

## Pre / post digest timing (non-retroactive, replayable)

Per the preferred rule:
- **Block H validates against the pre-H state:** `pre_state_digest == self.dominance.digest()` (the
  state from blocks `< H`). (The existing weight validation already uses the pre-H state.)
- **Block H commits the post-H state:** `post_state_digest ==` the digest **after** applying H's
  role-reward events. Computed during validation **without mutating** — clone `self.dominance`, apply
  H's events (exactly as `apply_block_dominance` does, incl. internal prune), digest the clone.
- The post-H digest is the pre-state for H+1 (the existing `apply_block_dominance` after commit produces
  the identical state, deterministically).

This is non-retroactive (H's reward application does not change H's own weight validation) and replayable
(both digests derive from chain-applied events).

## Validation (in `connect_block`, testnet-gated; mainnet hard-off)

When `dominance_commitment_active(height)` (requires anti-domination active; mainnet hard-off): for each
receipt ext carrying a `DMC1` commitment, validate version/network/height, then
`pre == self.dominance.digest()` and `post ==` clone-and-apply digest. Mismatch **rejects the block**.
When `dominance_commitment_enforced(height)` (active + required, off by default) and **no** commitment is
present, the block is rejected. A strict **additive** check — it does not change weight validation,
reward amounts, or the canonical coinbase validator.

## Window / pruning

Unchanged: `apply_event` prunes deterministically (window_id from height, lookback,
`PRUNE_MARGIN_WINDOWS`). The committed digest reflects the **pruned** post-state; it is stable across
replay because the buckets and prune are a deterministic function of the applied events.

## Reorg + replay

The dominance state is **already** reorg-safe and replay-reconstructable (apply on `connect_block`,
revert on `disconnect_tip_block`, rebuilt by replay). The commitment rides on it: on reorg, disconnected
blocks revert the state and reconnected blocks re-validate their commitments against the deterministic
state; on cold replay, `connect_block` re-validates. **No new ChainState field and no new reorg
snapshot/restore are needed** — abandoned-fork state is already reverted; the digest is a pure function
of the active chain.

## Tests (`phase33_*`)

Valid commitment accepted (pre + post match); bad post digest rejected; bad pre digest rejected; missing
commitment rejected when enforced; deterministic ordering (digest order-independent — existing) + reward
events update the state; window prune deterministic + digest stable; local-only history has no consensus
effect (the commitment is the only consensus input); reorg leaves no stale state; replay reconstructs;
mainnet no-op; regression (phase26/28/29/30/31/32 + full).

## Caps (Step 4) — deferred

Phase 33's goal is **state commitment**. The existing `fairness_weight` already reduces concentration
(no hard cap). Adding a hard cap is a broader policy decision; per the brief it is **deferred** (not
invented here). Documented as a possible future item.

## Out of scope / non-goals

- No change to `fairness_weight`, `multi_role_amounts`/coinbase validator, `block_reward`,
  LWMA/PoW/anchors, phase21d/21e/22a, existing dominance weight validation, or mainnet.
- No new dominance hard cap (deferred). No builder auto-inclusion beyond tests (default `None`).
