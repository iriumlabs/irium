# M6: honest readiness report — pre-activation infrastructure pass

Scope of this pass: complete every piece of infrastructure + validation work that
can be done WITHOUT mainnet exposure or real ASIC hardware, so a responsible
activation decision can later be made. No activation height was set or discussed.
Nothing was deployed to the live pool or mainnet. All work is on branch
`testing-codes-before-merging` (local; not pushed unless separately approved).

## What is PROVEN

1. Merge (M1). `feature/delegation-signup` (PR #79) merged into
   `testing-codes-before-merging` at 282d910. Full node suite green: lib 861/0,
   integration 259/0, plus bin/doc targets 0 failed. Pool suite 115/0. No
   regressions.

2. Settable delegation height gate (M2, e9d76f7). `poawx_delegation_active` is now
   a real, settable mainnet height gate via
   `MAINNET_POAWX_DELEGATION_ACTIVATION_HEIGHT: Option<u64> = None` +
   `poawx_effective_delegation_activation`. Behavior is byte-identical today
   (mainnet off at every height; testnet/devnet env-gated as before). Deliberately
   NOT routed through `poawx_effective_activation` (which returns 50_000 — mainnet
   is already past it, so that would activate delegation immediately). 3 new unit
   tests; full suite green. KNOWN FOLLOW-UP: a second, independent unconditional
   mainnet reject in `validate_poawx_block_receipts` ("unconditional and stays")
   must also be converted to this gate as part of any real delegation-activation
   commit before the gate alone is determinative on mainnet.

3. Receipt-producer upgrade (M3, e075849 + 64682de), all INERT behind the
   `stage_d_production_active` gate (hard mainnet-off, default-off, single explicit
   opt-in):
   - Option A: producer prefers `build_collected_bundle_ext` (distinct
     per-participant COMPUTE/VERIFY/SUPPORT payouts) when gated on + a complete
     bundle exists; byte-identical fallback to today's path otherwise.
   - Stage D custodial-proposer registration: pool-side byte-parity mirror
     (`ProposerRegistrationV1Mirror`/`SectionMirror`) + custodial key gen +
     registration builder, PROVEN byte-identical to the node — the real node
     deserializes the pool-built registration, re-serializes it byte-for-byte, and
     fully validates it (sybil digest + self-signature); reverse direction too.
   - Full pool suite 115/0 with the gate OFF: the existing coinbase / fallback path
     is completely unaffected.

4. Merged binary live proof (M5). The merged `iriumd` + `irium-miner` mine real
   all-gates PoAW-X blocks that the node ACCEPTS live on an isolated devnet
   (heights 1-3 accepted via `submit_block_extended`, coinbase pays the miner, full
   gate set active: proposer VRF, multi-role, fairness, tickets). The merge is
   live-safe for block production. Never touched :38500 (rig) or :38300 (mainnet).

## The ONE genuinely unverified risk (M4)

Real ASIC `mining.notify` compatibility of the reshaped multi-role / Stage-D
coinbase (the cb1/cb2 payload). This exact reshaping collapsed real-ASIC candidate
production THREE separate times while cpuminer/simulated rigs stayed green.

- What CAN be verified here (and is): the cb1/cb2 split reassembles to the exact
  coinbase the node validates (deterministic Rust); node-side acceptance of the
  multi-role coinbase (covered by live-E2E tests). These were all green the three
  times production still broke.
- What CANNOT be verified here: real ASIC firmware behavior. No real ASIC hardware
  is reachable from this isolated environment, and the faithful simulated
  alternative (cpuminer) is precisely what produced the false-greens.

Mitigation in this pass: the entire reshaped-coinbase path is behind
`stage_d_production_active` — hard mainnet-off, default-off. It is INERT. Today's
single-payout coinbase remains the live default in all cases.

## Recommended path before any activation can be responsibly discussed

1. Close the real-ASIC gap (Option 3 from the M4 decision). Point a real or
   faithfully-emulated ASIC (e.g. a bitaxe or stock cgminer on real firmware) at an
   isolated pool instance running the reshaped coinbase, and confirm it assembles
   `coinbase = cb1 + extranonce + cb2`, computes the merkle root, and produces
   ACCEPTED shares. This is the sole precondition to ever flipping
   `stage_d_production_active` on for a real ASIC-facing pool. A green isolated rig
   is NOT sufficient evidence.

2. Build the deferred live Stage-D production wiring
   (docs/m3_stage_d_proposer_production_plan.md): D4 (the block-level proposer proof
   through submit_block_extended) should be spiked FIRST on the isolated rig, then
   D1-D3/D5, then a full isolated-rig proof of distinct on-chain payouts.

3. Only after 1 + 2 both pass on the isolated rig, convert the second
   `validate_poawx_block_receipts` mainnet lock (M2 follow-up), choose a mainnet
   activation height with a coordinated upgrade window, and stage a controlled
   canary before broad rollout.

## Honest timeline assessment

Not weeks-scale yet, and no calendar estimate should be given until item 1 (real
ASIC validation) has a concrete plan and hardware. The critical path is NOT code
volume — it is obtaining real-ASIC validation for a change that has already broken
production three times. Until that hardware/test exists, an activation height
cannot be responsibly chosen. Everything that could be safely built and verified
without it is done and gated off; nothing is deployed.
