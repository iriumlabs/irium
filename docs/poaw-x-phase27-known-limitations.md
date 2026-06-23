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

### C. Anti-domination: state-digest commitment + validation (System 3)
- **Gap:** `PersistentDominance::digest()` is computed but not committed in the receipt/manifest nor
  validated; there is no explicit cap (weights only *reduce* score).
- **Decisions needed:** wire-format addition (the receipt/coinbase is live-validated — risky); whether
  an explicit cap is wanted at all (reduction-only already satisfies "without banning honest miners").
- **Risk:** Medium (wire change + new rejection semantics).

### D. Reward manifest: versioned wrapper + total≤subsidy+fees gate + low-participation fallback (System 1)
- **Gap:** the 55/22/13/10 split is enforced via constants + coinbase shape, not a single versioned
  `PoawxRewardManifestV1` object; no explicit ceiling gate beyond sum-equals-`total_reward`; no explicit
  low-participation fallback rule (the simulator models a deterministic fold-into-proposer fallback,
  which the node does not encode).
- **Decisions needed:** whether a redundant manifest struct is worth a wire-format change to an
  already-enforced, live-validated path; exact fallback rules.
- **Risk:** Medium-High (wire change to a working, live-validated path).

### E. Miner tickets: on-chain store + epoch rate-limiting (System 2)
- **Gap:** tickets are validated as external proofs; there is no on-chain `MinerTicketStore`/registry
  or per-epoch issuance rate-limit. (Ticket signatures are a deliberate non-goal — digests are
  deterministic and recomputable.)
- **Decisions needed:** persistent, reorg-safe store; epoch quota rule; registration endpoint vs
  proof-only model.
- **Risk:** Medium (new persistent consensus state).

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
