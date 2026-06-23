# PoAW-X Phase 27 — Known Limitations & Remaining Work

What Phase 27 did **not** implement, and why, with a recommended order for the deferred items. **These
are deferred consensus changes, each requiring design sign-off** before implementation — they were not
invented here to avoid risking the 748-test / live-validated baseline or weakening any gate.
**Testnet/devnet only. NOT audited / production-ready / mainnet-ready.**

## Why deferred (the stop conditions)

The Phase 27 plan says to **stop and report** if a step would change reorg logic, weaken
phase21d/21e/22a, bypass validation, require a security-sensitive shortcut, or hit a consensus
ambiguity that cannot be resolved deterministically without a decision. Each remaining gap below hits
at least one of these. Implementing them blind would be exactly the fix-one-break-another failure mode
the project's change rules forbid on consensus-critical code.

## Deferred items (recommended order)

### A. Finality: finalized-checkpoint state + reorg-below-finalized rejection (System 5) — **DONE in Phase 28**
- **Status:** ✅ Implemented in Phase 28 (branch `testnet/poawx-phase28-finalized-reorg-rejection`).
  `connect_block` now derives a monotonic finalized checkpoint after `validate_block_finality`, and
  `reorg_to_tip` rejects any reorg whose fork point is below it (even a higher-work fork). Reconstructed
  on cold replay/rebuild; no new wire format. See
  `docs/poaw-x-phase28-finalized-reorg-rejection.md` and its design doc. 8 `phase28_*` tests; full lib
  suite 756/0. Testnet/devnet only; mainnet hard-off.

### B. Finality: double-sign → penalty wiring (System 5) — **DONE (Phase 29 primitive + Phase 30 consensus)**
- **Phase 29:** validated double-sign evidence (`PoawxDoubleSignEvidenceV1`) + deterministic replayable
  penalty state + bounded local cache (local-only primitive).
- **Phase 30 (consensus enforcement):** evidence is now **block-carried** (trailing `DSE1` ext section,
  committed into the irx1 root, cap 16, canonical/deduped), **validated + applied in `connect_block`**
  (effective from H+1, non-retroactive), reconstructed by replay and rebuilt from the active chain on
  reorg, and **enforced** by excluding penalized signers from future finality
  (`phase30: penalized signer in finality committee`). Local gossip evidence stays non-consensus. See
  `docs/poaw-x-phase30-block-carried-doublesign-evidence.md`. 7 `phase30_*` tests; full lib suite 775/0.
- **Optional future work:** proposer/builder auto-inclusion of locally-cached evidence into candidate
  blocks (out of scope; tests inject evidence + pre-populate penalty state to exercise consensus).

### C. Anti-domination: state-digest commitment + validation (System 3) — **DONE in Phase 33**
- **Status:** ✅ Implemented in Phase 33 (`src/poawx_dominance.rs` + `src/poawx.rs` + `src/chain.rs`):
  `PoawxDominanceCommitmentV1` (pre/post state digest) is block-carried in a trailing `DMC1` ext section
  (committed into the irx1 root) and validated in `connect_block` — `pre` against the current state and
  `post` against the state after applying the block's role rewards (clone-and-apply, non-mutating),
  non-retroactive (H+1 timing). The dominance state is already reorg-safe + replay-reconstructable, so
  no new state/reorg handling was needed. See `docs/poaw-x-phase33-dominance-state-commitment.md`. 9
  `phase33_*` tests; full lib suite 805/0.
- **Caps deferred:** a hard dominance cap (vs. `fairness_weight` reduction) is a broader policy decision,
  documented as future work — Phase 33's goal was the state commitment.

### D. Reward manifest: versioned wrapper + caps + low-participation fallback (System 1) — **DONE in Phase 31**
- **Status:** ✅ Formalized in Phase 31 (`src/poawx_reward.rs`): a versioned `PoawxRewardManifestV1`
  wrapper + `PoawxRoleRewardCap` (rounding-aware: non-primary roles hard-capped at their bps floor,
  PRIMARY is the residual) + `PoawxRewardFallbackMode` (deterministic, non-inflationary: absent roles
  not minted) + a penalized-recipient link (Phase 30) + an **additive** (gated, off-by-default,
  mainnet-hard-off) consensus cap gate in `validate_phase20_production_block` that is a strict superset
  of the existing exact-match. **No new wire/root**, no change to `multi_role_amounts`/the coinbase
  validator/`block_reward`. See `docs/poaw-x-phase31-reward-manifest-wrapper.md`. 9 `phase31_*` tests;
  full lib suite 784/0. (Caps/total/non-inflation were already enforced by exact-match; Phase 31
  formalizes + names + tests them and adds the fallback spec.)

### E. Miner tickets: on-chain store + epoch rate-limiting (System 2) — **DONE in Phase 32**
- **Status:** ✅ Implemented in Phase 32 (`src/poawx_ticket.rs` + `src/chain.rs`): block-carried ticket
  registrations (trailing `TKT1` ext section, committed into the irx1 root, cap 16, canonical/deduped),
  a deterministic replayable `PoawxTicketStore` in `ChainState` (one active per `(miner,epoch)` and per
  `(vrf,epoch)`, deterministic expiry/pruning), validated + applied in `connect_block` (effective from
  H+1), reconstructed by replay and rebuilt from the active chain on reorg, with an additive (gated,
  off-by-default, mainnet-off) eligibility hook that requires a rewarded role's ticket proof to match an
  active on-chain ticket. Local registration cache stays non-consensus. See
  `docs/poaw-x-phase32-onchain-ticket-store.md`. 12 `phase32_*` tests; full lib suite 796/0. (Ticket
  signatures remain a deliberate non-goal — the Sybil PoW is the deterministic identity cost.)

### F. Adaptive modes: consensus/node integration (System 6)
- **Gap:** `assess()` + policies exist and are tested, but nothing consumes them — confirmation
  multipliers, `require_finality`, and stricter verification are not applied in block acceptance.
  `PoawxModeValidationError` is absent.
- **Decisions needed:** which effects are consensus-binding vs node-local advisory; deterministic
  signal sourcing; transition validation.
- **Risk:** Medium-High (changes block-acceptance behavior).

## Cross-cutting limitations (carried from prior phases)

- **Independent audit not done** — no external review; the Phase 26I self-review is not an audit.
- **No live multi-machine run this phase** — Phase 27 is code+tests+sim only; no devnet nodes were run.
- **phase21e propagation-sensitivity** — unchanged, pre-existing design consideration.
- **Simulator is a model, not a proof** — `poawx-sim` reuses the real primitives but abstracts network
  timing, mempool, and true VRF; its passing scenarios are evidence, not guarantees.
- **Admission window / deep-scale sync** — still a public-testnet objective.

## Recommended next steps

1. Take the deferred items **one at a time**, each as its own scoped change with a design note (current
   behavior → why → what changes → what else could break → tests), per the project change rules.
2. Start with **A** (finalized-checkpoint reorg rejection) — it is the most security-significant gap.
3. Re-run the simulator after each consensus change to watch fairness/finality/concentration metrics
   for regressions.
4. Keep mainnet hard-off and the public-testnet gate closed throughout; obtain the independent audit
   (Phase 26H–26N program) before any launch.

**None of the deferred items are implemented. Phase 27 is not a completion of the full blueprint.**
