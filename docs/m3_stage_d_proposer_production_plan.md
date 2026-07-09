# M3 deferred: live pool custodial-proposer block production (Stage D)

Status: DEFERRED / not implemented. This document is the precise scope for a
future, separately-scoped session so it can be picked up without re-deriving.

Everything below stays behind `delegation::stage_d_production_active(height)`
(hard mainnet-off, default-off, single explicit opt-in), and MUST NOT be enabled
for any real ASIC-facing pool until the real-ASIC `mining.notify` validation test
passes and is separately approved (see the M6 readiness report / Milestone 4).

## What already exists after M3 (this pass)

All inert / gated off:

1. `stage_d_production_active(height)` gate (delegation.rs) — hard mainnet-off,
   default-off, `IRIUM_POAWX_STAGE_D_PRODUCTION=1` opt-in on non-mainnet only.
2. Option A ext selection (stratum.rs `build_session_poawx_receipts`): when the
   gate is on and a complete bundle exists, prefer `build_collected_bundle_ext`;
   otherwise byte-identical fallback to `build_collected_phase20_ext` -> synthetic.
3. Byte-parity proposer-registration mirror (delegation.rs), proven against the
   node in `m3_proposer_registration_*` tests:
   - `ProposerRegistrationV1Mirror` (169-byte wire) + `serialize`/`deserialize`/
     `pkh`/`signing_digest`/`build_signed`.
   - `ProposerRegistrationSectionMirror` (PRG1) + `serialize`.
   - `load_or_generate_proposer_secret` (custodial key, non-mainnet gen only).
   - `build_pool_proposer_registration_section(...)` builder.

## What is DEFERRED (the live wiring)

### D1. Producer holds the custodial proposer secret
- Extend `PoawxProducer` (delegation.rs ~4391) with an optional
  `proposer_secret: Option<[u8; 32]>` loaded via `load_or_generate_proposer_secret`
  in `load_producer()` ONLY when `stage_d_production_active`-equivalent config is
  set and network is non-mainnet (`allow_generate = network_id != 0`).
- On load, set `IRIUM_POAWX_POOL_PROPOSER_PUBKEY_HEX` from the derived pubkey so
  the advertised pool-identity proposer pubkey (Step A) equals the held secret's
  pubkey. Today the pubkey is advertised from env with no secret behind it.

### D2. Add `proposer_registrations` to the pool Phase20 ext mirror
- The pool `Phase20ReceiptExtMirror` (delegation.rs) currently has NO
  `proposer_registrations` field; every pool block sets it to `None`.
- Add `pub proposer_registrations: Option<ProposerRegistrationSectionMirror>` and
  serialize the PRG1 section in the EXACT node position. Per the node encoder
  (src/poawx.rs `Phase20ReceiptExt::serialize`), PRG1 is emitted AFTER
  `role_assignment_v2` (AVR2) and BEFORE the RVK1 revocation section. Verify the
  exact trailing-section order against the node encoder at wiring time and add a
  full-ext round-trip parity test (build pool ext with a section -> node
  deserialize -> assert announces/activations equal).
- Respect caps: announces <= `PROPOSER_ANNOUNCE_CAP` (8), activations <=
  `PROPOSER_REG_CAP` (8).

### D3. Emit the registration until it is frozen, then stop
- Anchor: fetch a recent on-chain block height+hash from the node
  (`/rpc/getblocktemplate` prev / a status endpoint) for `anchor_height`/
  `anchor_hash`. The node enforces an anchor-recency window in
  `connect_block` (see `poawx_proposer::registration_anchor_window_math` and the
  registration validation path) — confirm the exact allowed lag.
- Required sybil bits: read the node's required bits (mainnet hard-off = 0;
  non-mainnet via `IRIUM_POAWX_TICKET_SYBIL_BITS`). Use the same value the node
  validates against (`poawx_ticket::sybil_threshold_bits` mirror).
- Attach `build_pool_proposer_registration_section(...)` to the produced block's
  ext `announces` until the registry reports the proposer registered AND frozen
  (freeze depth 16, env `IRIUM_POAWX_PROPOSER_FREEZE_DEPTH`). Then clear it so
  steady-state blocks carry no registration section.
- Query registration/freeze status via the node `/poawx/proposer-status?pkh=...`
  endpoint added in PR #79 Step F.

### D4. Block-level proposer proof (the deepest unknown — resolve first)
- A pool block is assembled by the node from `submit_block_extended` (coinbase +
  receipts + nonce). Determine EXACTLY what proposer proof a submitted block must
  carry for `validate_block_true_vrf` / `validate_block_proposer` to accept the
  pool's custodial proposer as the block proposer. Trace, in src/chain.rs:
  `validate_block_true_vrf`, `validate_block_proposer`, and how the proposer
  identity is derived for a submit_block_extended block (AssignmentProofV2
  proposer vs a separate proposer signature over the header/candidate).
- The existing Stage-D proofs built this in the harness
  (`build_delegated_poawx_block_with_proposer` takes `proposer_ctx` +
  `registration_section`); the pool must reproduce the equivalent PROOF bytes as a
  mirror and attach them through `submit_block_extended`. This is the largest
  remaining unknown and should be spiked FIRST on the isolated rig before the rest.

### D5. Delegated-receipt binding
- Ensure `build_mode1_pending_receipt` (already used by
  `build_session_poawx_receipts`) uses a stored delegation whose
  `proposer_pubkey` equals the custodial proposer pubkey, and whose payout
  (`worker_pkh`) is the MINER's own address. The multi-role coinbase already pays
  PRIMARY to `first.worker_pkh`; with a correct delegation that is the miner's
  address, so PRIMARY-direct-to-miner falls out with no coinbase change beyond
  the already-gated multi-role path.

## Test plan (isolated rig, no ASIC)

1. Full-ext PRG1 round-trip parity (pool ext with section <-> node deserialize).
2. Isolated devnet: pool with gate ON + custodial proposer generated + registered;
   a delegated miner mines; the node ACCEPTS the block; the miner is paid its own
   address on-chain; distinct COMPUTE/VERIFY/SUPPORT participants each paid.
3. Confirm gate OFF remains byte-identical to today (single-payout default).

## The one thing that CANNOT be validated here

Real ASIC `mining.notify` compatibility of the reshaped multi-role coinbase
(cb1/cb2). This is Milestone 4 and is the sole blocker before the gate may EVER be
flipped on for a real ASIC-facing pool or mainnet. A green isolated rig is not
sufficient evidence (it was green all three times production broke). Requires a
real or faithfully-emulated ASIC assembling `coinbase = cb1 + extranonce + cb2`,
computing the merkle root, and producing accepted shares against the reshaped
coinbase, explicitly passing and separately approved.
