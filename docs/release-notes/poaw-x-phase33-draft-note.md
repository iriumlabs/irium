# PoAW-X Phase 33 — Draft Note (development only — not a release)

> **Draft / development only.** No git tag, no GitHub release, no binaries. **Testnet/devnet only.
> Mainnet hard-off (`network_id == 0`). NOT production-ready / mainnet-ready / audited.** No public
> testnet launch.

Branch: `testnet/poawx-phase33-dominance-state-commitment` (from `8f2a64d`). `origin/main` unchanged
(`19c496dc5f2fa08981a109b10eeb257105c28c43`).

## What changed

- **Dominance-state commitment (closes Phase 27 item 3C).** `PoawxDominanceCommitmentV1` (pre/post state
  digest) is block-carried in a new trailing `DMC1` ext section (committed into the irx1 root) and
  validated in `connect_block`: `pre` must equal the current anti-domination state digest and `post` the
  digest after applying the block's role rewards (clone-and-apply, non-mutating). Non-retroactive (H+1
  timing); the digest is a pure function of the active chain. The state was already reorg-safe +
  replay-reconstructable, so no new state/reorg handling was needed. Gated, mainnet-off, off by default.
- **Simulation:** `poawx-sim` `dominant_miner` reports `dominance_state_committed`,
  `dominance_pre_digest`, `dominance_post_digest`, `reward_concentration_permille`,
  `dominant_miner_weight_reduction`, `digest_replay_stable`.

## Unchanged / safety

- `None` ⇒ byte-identical ext (wire-format backward compatible; phase20/dominance green). No change to
  `fairness_weight`, `multi_role_amounts`/coinbase validator, `block_reward`, LWMA/PoW/SHA-256d anchors,
  phase21d/21e/22a, existing dominance weight validation, or mainnet. Mainnet stays hard-off. Hard
  dominance caps deferred.

## Tests

- `phase33_*`: 9/0. Full lib suite: 805/0 (`dominance` 21/0, `reward` 18/0). `poawx-sim` bin: 16/0.
  Release builds: OK.

_Development only. Not a release. Not audited / production-ready / mainnet-ready._
