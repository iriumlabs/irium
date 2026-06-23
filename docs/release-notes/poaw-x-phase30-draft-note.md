# PoAW-X Phase 30 — Draft Note (development only — not a release)

> **Draft / development only.** No git tag, no GitHub release, no binaries. **Testnet/devnet only.
> Mainnet hard-off (`network_id == 0`). NOT production-ready / mainnet-ready / audited.** No public
> testnet launch.

Branch: `testnet/poawx-phase30-block-carried-doublesign-evidence` (from `df0cc92`). `origin/main`
unchanged (`19c496dc5f2fa08981a109b10eeb257105c28c43`).

## What changed

- **Block-carried double-sign evidence → consensus enforcement (completes Phase 27 item 5B).**
  Double-sign evidence is now carried in a trailing-optional `DSE1` section on `Phase20ReceiptExt`
  (committed into the irx1 root; cap 16; canonical/deduped), validated and applied in `connect_block`
  (effective from H+1, non-retroactive), reconstructed by replay and rebuilt from the active chain on
  reorg, and **enforced** by excluding penalized signers from future finality committee/votes
  (`phase30: penalized signer in finality committee`). Local gossip evidence remains non-consensus.
- **Simulation:** `poawx-sim` `finality_attack` reports `evidence_included_in_block`,
  `consensus_penalty_applied`, and `future_finality_eligibility_removed`.

## Unchanged / safety

- `None` ⇒ byte-identical ext (wire-format backward compatible; phase20/26 suites green).
- No change to LWMA/PoW/reward/SHA-256d anchors, phase21d/21e/22a, finality threshold/committee
  validation, or signature checks. Mainnet stays hard-off.

## Tests

- `phase30_*`: 7/0 (incl. a real `connect_block` exclusion test). Full lib suite: 775/0. `poawx-sim`
  bin: 13/0. Release builds: OK.

_Development only. Not a release. Not audited / production-ready / mainnet-ready._
