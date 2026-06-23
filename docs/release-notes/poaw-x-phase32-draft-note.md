# PoAW-X Phase 32 — Draft Note (development only — not a release)

> **Draft / development only.** No git tag, no GitHub release, no binaries. **Testnet/devnet only.
> Mainnet hard-off (`network_id == 0`). NOT production-ready / mainnet-ready / audited.** No public
> testnet launch.

Branch: `testnet/poawx-phase32-onchain-ticket-store` (from `fae91bb`). `origin/main` unchanged
(`19c496dc5f2fa08981a109b10eeb257105c28c43`).

## What changed

- **On-chain ticket store (closes Phase 27 item 2E).** Block-carried ticket registrations (trailing
  `TKT1` ext section, committed into the irx1 root, cap 16, canonical/deduped) → a deterministic,
  replayable `PoawxTicketStore` in `ChainState` (one active per `(miner,epoch)` and per `(vrf,epoch)`,
  deterministic expiry/pruning), validated + applied in `connect_block` (effective from H+1),
  reconstructed by replay and rebuilt from the active chain on reorg. An **additive** (gated,
  off-by-default, mainnet-off) eligibility hook requires a rewarded role's ticket proof to match an
  active on-chain ticket (`phase32: role ticket not registered on-chain`). Local registration cache is
  non-consensus.
- **Simulation:** `poawx-sim` `sybil` scenario reports `ticket_registrations_included`,
  `rejected_sybil_registrations`, `active_ticket_count`, `expired_ticket_count`, `sybil_cost_estimate`,
  `ticket_store_consensus_enforced`.

## Unchanged / safety

- `None` ⇒ byte-identical ext (wire-format backward compatible; phase20/26 green). No change to
  `multi_role_amounts`/coinbase validator, `block_reward`, LWMA/PoW/SHA-256d anchors, phase21d/21e/22a,
  existing ticket/Sybil validation, or mainnet. Mainnet stays hard-off.

## Tests

- `phase32_*`: 12/0. Full lib suite: 796/0 (`ticket` 21/0, `sybil` 1/0). `poawx-sim` bin: 15/0. Release
  builds: OK.

_Development only. Not a release. Not audited / production-ready / mainnet-ready._
