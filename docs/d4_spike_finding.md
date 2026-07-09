# D4 spike finding: the pool cannot self-produce a proposer VRF proof (architectural blocker)

Status: SPIKE COMPLETE. The plan (docs/m3_stage_d_proposer_production_plan.md)
called for spiking D4 FIRST because it was the largest unknown. It is now
resolved, and the answer is a genuine architectural blocker that changes the rest
of the plan. This document records the exact requirement, the blocker, the scope
that IS achievable now, and the decision the blocker forces.

## What a pool-submitted block must carry (traced in the node)

For the node to accept the pool's custodial/delegated proposer, each PoAW-X
receipt in a `submit_block_extended` block must carry, inside its `phase20_ext`:

1. `proposer_assignment: Some(ProposerAssignmentV1 { round: u32, proof:
   AssignmentProofV2 })` (node `src/poawx.rs:632`, magic `PRP1`).
   `AssignmentProofV2` (node `src/poawx_candidate.rs:633`, 273-byte wire) is a
   real **RFC-9381 ECVRF proof over secp256k1**. For a proposer proof:
   `role_id = ROLE_PROPOSER (0)`, `ticket_digest = [0;32]`, `seed =
   expected_epoch_seed(height, prev_hash, previous)`, `assignment_public_key =`
   the custodial proposer VRF key, `solver_pkh = hash160(assignment_public_key)`,
   and a VALID `vrf_proof` / `vrf_output` produced by proving with the proposer
   SECRET. `round` is chosen by running local VRF sortition
   (`priority(vrf_output) < threshold(eligible_count, round)`).
2. A v2 `delegation` whose `proposer_pubkey == assignment_public_key`,
   `pool_pubkey ==` the pool signer, `miner_pkh() == worker_pkh` (miner payout).

The node validates this in `validate_block_proposer` (`src/chain.rs:1350`), which
runs `pa.proof.validate(net, height)?` - a full ECVRF verify - plus role, seed,
ticket, solver-pkh, delegation-binding, eligibility, sortition and round-timing
checks. The registration must additionally be frozen in the registry (announced
with a valid recent sybil anchor, activated off the FIFO queue, aged >=
`FREEZE_DEPTH = 16` blocks, within expiry). Reference implementation the pool
must reproduce: `build_delegated_poawx_block_with_proposer`
(`src/poawx_mining_harness.rs:580`), where the proof is built by
`AssignmentProofV2::prove_self_solver(proposer_secret, ...)`.

## The blocker

A VRF proof is not a wire format that can be "mirrored" - it must be **computed**
with the proposer secret using the ECVRF prover. The pool intentionally does not
have that prover:

- `AssignmentProofV2Mirror` (pool `src/delegation.rs:1327`) is explicitly ser/de
  only: "mirrors the 273-byte wire byte-for-byte ... (no `vrf_fun` dependency
  here)". It cannot generate a valid proof.
- `irium-node-rs` is a **`[dev-dependencies]`** of the pool only
  (`pool/irium-stratum/Cargo.toml:34`); every `irium_node_rs::` use in `src/` is
  under `#[cfg(test)]`. Production code cannot call the node's prover.

So the pool's production path **cannot produce a valid custodial proposer
`AssignmentProofV2`** today. This is the true reason the custodial-proposer live
production was deferred - and the spike has now made it precise.

## What IS achievable now (proposer-VRF enforcement OFF)

`validate_block_proposer` and `validate_block_proposer_registrations` are called
by `connect_block` **only when `proposer_vrf_enforced(height)`** (`chain.rs:941`),
which is mainnet-hard-off and env-gated on non-mainnet. With it OFF:

- The pool CAN produce a **delegated block that pays the miner directly** (the
  Stage-D user-facing goal): the delegation-triangle check
  (`validate_poawx_block_receipts`, gated by `poawx_delegation_active`, not
  proposer-VRF) still verifies `d.verify_signature()`, `d.miner_pkh() ==
  worker_pkh`, `worker_pubkey == pool_pubkey`. This needs **no ECVRF prover**.
- The PRG1 registration section (D2), the custodial secret load (D1), the
  registration emission (D3), and the delegation binding (D5) are all
  implementable and testable without the prover.

So the achievable slice is: **D1 + D2 + D3 + D5 with proposer-VRF enforcement
OFF** => the node accepts a pool-produced delegated block paying the miner
directly on-chain. **D4 (the per-block proposer VRF proof, required only when
proposer-VRF is enforced) is the sole blocked item.**

## The decision the blocker forces (for the FULL custodial-proposer mode)

To make the pool act as a sybil-registered proposer under proposer-VRF
enforcement, one of these must be chosen (a real architecture decision, not
wiring):

- **A. Add an ECVRF prover to the pool's production dependencies.** Add `vrf_fun`
  (or the minimal secp256k1 ECVRF used by the node) as a real dependency and give
  `AssignmentProofV2Mirror` a `prove` path byte-compatible with the node. Highest
  fidelity risk (must match the node's ECVRF byte-for-byte) and enlarges the live
  pool's crypto surface. Would need its own parity + adversarial review before any
  ASIC-facing use.
- **B. Promote a minimal proving crate.** Factor the node's proposer-proof
  builder into a small, audited crate depended on by both node and pool (avoids
  hand-mirroring ECVRF, but is a workspace/dependency change).
- **C. Miner-produced proposer proof.** Keep the prover in `irium-miner` (which
  already has it) and have the miner produce the proposer `AssignmentProofV2` for
  the pool's custodial key - but the miner does not hold the custodial secret, so
  this needs a custody/protocol change (e.g. the pool signs, or a different
  proposer-custody model). Largest protocol change.
- **D. Run the custodial-proposer pool with proposer-VRF enforcement OFF.** Ship
  the direct-payout delegated mode (D1/D2/D3/D5) without proposer-VRF, and treat
  proposer-VRF-enforced custodial proposing as a separate later milestone. Lowest
  risk; delivers the user-facing "pay the miner directly" goal now; does not give
  the pool a sybil-registered VRF proposer identity.

Recommendation: **do not add crypto to the live pool binary unilaterally.** Land
D1/D2/D3/D5 gated off (option D's building blocks), and take the A/B/C decision
explicitly before building an ECVRF prover into a real ASIC-facing pool. Every one
of A/B/C is gated behind the same `stage_d_production_active` inert gate and the
unresolved real-ASIC notify test (Milestone 4) regardless.

## This pass

- D2 landed: `Phase20ReceiptExtMirror.proposer_registrations` + PRG1 serialize in
  the exact node position + full-ext parity test
  (`d2_proposer_registration_section_full_ext_parity_with_node`): the pool builds a
  full ext carrying PRG1 and the node deserializes+round-trips it byte-for-byte.
- D1/D3/D5 code and the direct-payout end-to-end (proposer-VRF off) are ready to
  build on top; deferred pending the A/B/C/D decision above so the work is not
  redone against the chosen proposer-custody architecture.
- D4 (ECVRF proposer proof) blocked on that decision. Nothing here is merged,
  deployed, activated, or on the live pool/mainnet.
