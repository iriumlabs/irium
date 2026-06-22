# PoAW-X Phase 27 — Full-Blueprint Gap Audit

Pre-implementation audit of the current repo against the Phase 27 full-blueprint requirements, on a
fresh branch `testnet/poawx-phase27-full-blueprint-implementation` (from `2cb5823`). **Testnet/devnet
only. NOT audited / production-ready / mainnet-ready.** Mainnet PoAW-X hard-off (`network_id == 0`).

Baseline verified: `cargo test --lib -- --test-threads=1` → **748 passed / 0 failed**; release build of
`iriumd` + `poawx-live-proof-harness` OK. `origin/main` unchanged
(`19c496dc5f2fa08981a109b10eeb257105c28c43`).

## Headline finding

This is **not greenfield**. Five of the seven blueprint systems are already implemented and
consensus-enforced from earlier phases (20–22). The genuinely-missing system is the **simulation
suite**; the **adaptive-modes** data layer exists but is not wired into consensus; the remaining gaps
are **additive consensus refinements** (finalized-checkpoint state, dominance-state commitment,
explicit manifest wrapper, double-sign→penalty wiring) that each carry real consensus-design decisions.

| # | System | Current status | Net-new work |
|---|--------|----------------|--------------|
| 1 | Reward manifest / 55-22-13-10 | **Enforced** (split + coinbase validation in `connect_block`) | Versioned manifest wrapper; explicit total≤subsidy+fees gate; low-participation fallback |
| 2 | Miner tickets / Sybil | **Enforced** (`validate_phase20_ticket_proofs`) | On-chain store/persistence; epoch rate-limit; (signature is a deliberate non-goal) |
| 3 | Anti-domination | **Enforced** (`phase21c` weight validation, reorg-safe) | State-digest commitment + validation; explicit caps (vs reduction-only) |
| 4 | Puzzle system | **Complete** (5 modes, `phase21f` enforced) | None |
| 5 | Extended finality + penalties | **~70% enforced** (`phase21h` proof + threshold) | Finalized-checkpoint state; reorg-below-final rejection; double-sign→penalty wiring |
| 6 | Adaptive modes | **Data layer complete**, not wired | Consensus integration; `PoawxModeValidationError` |
| 7 | Simulation suite | **Missing entirely** | Full `poawx-sim` binary + scenarios + metrics + reports |

## Detailed gap table

Columns: requirement · current status · missing code · required consensus changes · required tests ·
risk · planned files.

### 1. Reward manifest / 55-22-13-10 enforcement

- **Current:** `MULTI_ROLE_{PRIMARY,COMPUTE,VERIFY,SUPPORT}_BPS = 5500/2200/1300/1000`
  (`src/poawx.rs:81-85`); deterministic `multi_role_amounts()` (`:143`, remainder→primary, u128 math);
  `apply_fee()` (`:197`); coinbase validated by `validate_poawx_coinbase_payout()` /
  `validate_multi_role_coinbase_outputs()` (`src/chain.rs:2691/2618`) and
  `validate_phase20_production_block()` (`:2855`), called in `connect_block` (`:3373`). Mainnet hard-off
  via `multi_role_reward_active()` (`:2522`). Tests in `poawx.rs`/`chain.rs`/`iriumd.rs`.
- **Missing:** a standalone *versioned* `PoawxRewardManifestV1` struct (split is enforced via constants
  + coinbase shape, not a single manifest object); an explicit `total ≤ subsidy + fees` ceiling gate
  (today the sum-equals-`total_reward` check assumes a correctly-derived total); explicit
  low-participation fallback rules; recent-reward-state commitment in the manifest.
- **Consensus changes:** adding a manifest struct to the receipt/coinbase = **wire-format change** (must
  not break the live-validated block format or the 748 tests).
- **Tests needed:** total-cap reject; low-participation fallback determinism; manifest-root reject.
- **Risk:** **Medium-High** (wire change to an already-enforced, live-validated path).
- **Planned files:** `src/poawx.rs` (manifest struct), `src/chain.rs` (cap gate). **Deferred — needs
  design sign-off** (the split itself already meets the core requirement).

### 2. Miner tickets / Sybil resistance

- **Current:** `MinerWorkTicket` (`src/poawx_ticket.rs:22`) with miner_pkh, epoch, assignment key,
  sybil work (nonce+digest, leading-zero threshold), reward score, work counts, penalty status,
  optional bond, expiry; `TicketProof` (`:351`) role-bound; `validate()` checks network/version/expiry/
  penalty/sybil. Consensus-enforced when `tickets_enforced(height)` via
  `validate_phase20_ticket_proofs()` (`src/chain.rs:2922`, call `:2913`). Mainnet hard-off. 7+ tests.
- **Missing:** on-chain `MinerTicketStore` / persistence + registration endpoint; a *separate*
  registration PoW (today the sybil work IS the deterministic cost); per-epoch rate-limiting. Tickets
  are unsigned by deliberate design (deterministic, recomputable digests) — treat signature as a
  documented non-goal, not a gap.
- **Consensus changes:** a persistent ticket store in `ChainState` + reorg-safe apply/revert; epoch
  quota enforcement = new consensus state.
- **Tests needed:** store roundtrip/reload; epoch quota reject; rate-limit determinism.
- **Risk:** **Medium** (new persistent consensus state; reorg-safety required).
- **Planned files:** `src/poawx_ticket.rs`, `src/chain.rs`, `src/storage.rs`. **Deferred — needs design
  sign-off.**

### 3. Anti-domination engine

- **Current:** `PersistentDominance` (`src/poawx_dominance.rs:277`); deterministic
  `fairness_weight = work_score*1000/(1000+recent_share_permille)` (`:122`); window/lookback; reorg-safe
  `apply_event`/`revert_event`; `digest()` (`:413`). Enforced in `connect_block` via
  `validate_block_dominance_weights()` (`src/chain.rs:1463`, call `:856`); apply/revert at `:1501`.
  Hardware-agnostic. 14 tests incl. reorg.
- **Missing:** the dominance state `digest()` is **computed but not committed** in the receipt/manifest
  nor validated; weights *reduce* effective score but there is no explicit *cap*/veto rule.
- **Consensus changes:** committing + validating the state digest = wire-format change; caps = new
  rejection rule.
- **Tests needed:** commitment-mismatch reject; cap behavior; low-participation no-halt.
- **Risk:** **Medium** (wire change + new rejection semantics).
- **Planned files:** `src/poawx_dominance.rs`, `src/poawx.rs`, `src/chain.rs`. **Deferred — needs design
  sign-off** (reduction-only already satisfies "without banning honest strong miners").

### 4. Puzzle system

- **Current:** `PuzzleMode` 5 modes (Sha256dAnchor, RandomMemory, ParallelCompute, VerificationWork,
  FinalityWorkPlaceholder) (`src/poawx_puzzle.rs:41`); deterministic `assign_puzzle_mode()` (`:138`);
  bounded `verify_solution()` (`:429`); challenge binds network/height/role/miner/ticket/block/seed;
  difficulty from `IRIUM_POAWX_PUZZLE_BITS` (no LWMA touch). Enforced via `phase21f`
  (`validate_block_puzzle_proofs`, `src/chain.rs:1089`, call `:864`). 9 module tests + 1 chain test.
- **Missing:** nothing material. All 5 modes present, bound, replay-proof, mainnet hard-off.
- **Risk:** **None** for this phase. **No change planned.**

### 5. Extended finality committee + penalties

- **Current:** `FinalityVoteV1` (`src/poawx_finality.rs:78`, ECDSA, binds network/height/block_hash/
  parent/epoch/member/ticket/type); `FinalityProofV1` (`:279`) with configurable threshold
  (`finality_threshold()` `:488`, default 1/1; tests use 2/3); `NodeFinalityVoteCache` (`:593`) with
  conflict detection (`:667`). Enforced via `phase21h` (`validate_block_finality`, `src/chain.rs:1046`,
  call `:867`). `PenaltyStatus`/`PenaltyRecord` (`src/poawx_penalty.rs`) + ticket eligibility wiring.
- **Missing:** persistent `PoawxFinalityCheckpoint`/`PoawxFinalityState`; **reorg-below-finalized
  rejection** (today `reorg_to_tip`/`find_reorg_path` do not consult a finalized height); double-sign
  detected at gossip but **not** recorded into `PenaltyRecord::record_invalid_work`; no explicit
  `PoawxFinalityCommitteeV1` epoch struct (committee inferred from SUPPORT candidates per block).
- **Consensus changes:** finalized-checkpoint state + reorg gate = **reorg-logic + persistent state
  change** (safety-sensitive); penalty wiring = persistent penalty state feeding eligibility.
- **Tests needed:** finalized immutability; reorg-below-final reject; double-sign→penalty escalation.
- **Risk:** **High** (touches reorg path + adds consensus state; genuine design decisions: finalization
  rule, recovery semantics).
- **Planned files:** `src/poawx_finality.rs`, `src/poawx_penalty.rs`, `src/chain.rs`. **Deferred — needs
  design sign-off** (Step-12 stop condition: reorg/consensus ambiguity).

### 6. Adaptive security/mining modes

- **Current:** `AdaptiveMode {Normal,Caution,Defense,Recovery}` (`src/poawx_adaptive.rs:14`);
  `NetworkSignals` (`:23`); `AdaptivePolicy` (`:34`); deterministic `assess()` state machine with
  hysteresis (`:115`); triggers (low miners/roles, invalid work, reorg signal, concentration) and
  effects (confirmation multiplier, stricter verification, require_finality, role_fallback); no-halt
  guarantee; mainnet hard-off; 6 tests.
- **Missing:** `PoawxModeValidationError`; **consensus/node integration** — the module is data-only and
  is not consumed by `connect_block` or the node (no enforcement of confirmation multipliers /
  require_finality).
- **Consensus changes:** enforcing modes changes block-acceptance behavior (confirmations, finality
  requirement) — a behavior change requiring design.
- **Tests needed:** integration tests; invalid-transition reject.
- **Risk:** **Medium-High** (changes acceptance behavior). **Deferred — needs design sign-off.**

### 7. Simulation suite

- **Current:** **none.** `poawx_mining_harness.rs` and `poawx-live-proof-harness` are single-block
  proof tools, not a scenario simulator. No `poawx-sim` binary, no scenarios, no metrics/reports.
- **Missing:** the entire suite — deterministic-seed scenario runner (normal, low-participation,
  dominant miner, dominant pool, Sybil, reorg, randomness manipulation, reward distribution over
  epochs, finality attack, fresh-wipe behavior), configurable miners/attacker-share/epochs, fairness /
  concentration / finality-safety / sybil-cost metrics, JSON + markdown reports.
- **Consensus changes:** **NONE** — a standalone off-chain analysis binary that reuses the existing
  deterministic primitives (`fairness_weight`, `multi_role_amounts`, sybil leading-zero, puzzle
  assignment). It does **not** touch `connect_block` or any gate.
- **Tests needed:** deterministic output for fixed seed; each scenario completes; metrics produced;
  report generated.
- **Risk:** **Low** (no consensus surface). **IMPLEMENT THIS PHASE.**

## Phase 27 execution decision (honesty-driven)

Per the Phase 27 stop conditions ("stop and report if any consensus ambiguity cannot be resolved
deterministically / any step would change reorg or weaken gates / any security-sensitive shortcut is
needed") and the project's standing rule (plan + approval before consensus changes), this phase will:

1. **Commit this gap audit** (done first, as required).
2. **Implement the simulation suite** (System 7) — the one fully-missing, **non-consensus, zero-gate-
   risk** deliverable — with deterministic seeds, scenarios, metrics, JSON+markdown, and tests.
3. **Document** the precise remaining consensus gaps (Systems 1–3, 5, 6) as **remaining work requiring
   design sign-off**, rather than inventing wire-format/reorg/penalty consensus rules unilaterally
   (which would risk the 748-test/live-validated baseline and could weaken or alter consensus).

This is deliberately **not** a claim that Phase 27 is "complete." Systems 1–6 are reported by true
state: 4 complete, 1/2/3/5 enforced-with-gaps, 6 data-only. Each deferred item is a separate, scoped,
approval-gated change — recommended one system at a time with its own design + tests, exactly to avoid
the fix-one-break-another failure mode on consensus-critical code.

See `docs/poaw-x-phase27-known-limitations.md` for the per-system remaining work and recommended order.
