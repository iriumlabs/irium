# Phase 42 — Live Harness Phase 31–34 Sections (Design)

Testnet/devnet only; mainnet hard-off; not audited; not production-ready.

## Why Phase 41's live soak did not exercise TKT1/DMC1/ADM1

The `poawx-live-proof-harness` (via `build_devnet_all_gates_block`) emitted "all-gates" blocks per the
Phase 24K/24L definition — candidate set, candidate admission, committed admission, true-VRF,
role puzzle proofs, finality proof, role dominance weights, 0%-fee coinbase. It set
`ticket_registrations`, `dominance_commitment`, and `adaptive_mode_commitment` to `None`. So a node with
the Phase 32/33/34 gates enforced would reject those blocks, and Phase 41 Stage A could only run the
Phase 28 + 21x/22x (+ Phase 30-active) gate set.

## How the harness constructs each new section

The builder gains an opt-in `AllGatesSections { dominance_commitment, adaptive_commitment,
ticket_registrations }`. `build_devnet_all_gates_block` (legacy, no sections) delegates to
`build_devnet_all_gates_block_with(opts, …)`; with `default()` the output is byte-identical to before.

- **DMC1 (Phase 33).** `pre = dom_at(H).digest()` (dominance after blocks < H), `post = dom_at(H+1).digest()`
  (after this block's role rewards) — exactly what the node's `validate_block_dominance_commitment`
  recomputes (`pre` = current digest, `post` = after H). `dom_at` is the builder's existing deterministic
  dominance replay over the fixed role identities.
- **ADM1 (Phase 34).** The builder replays the adaptive state over blocks < H (transitioning only when
  the adaptive gate is active at that height) to get `pre`, then `post = pre.next(signals_H)`, using the
  **public** `PoawxAdaptiveState::next` (the same code the node runs). The signals mirror the node's
  `adaptive_chain_signals`: concentration + participation from the dominance-after-h state; recent ticket
  registrations = per-block count × recent-window blocks; recent double-sign evidence = 0 (the harness
  carries none); finality available = true (every harness block carries a finality proof). **No
  local-only signal** is read — the consensus mode is chain-derived only.
- **TKT1 (Phase 32).** Deterministic devnet registrations (no real wallet/key) for the three non-primary
  role solvers, each for the NEXT block's epoch (`H+1`), sybil work satisfying the configured bits,
  canonical strictly-increasing `ticket_id`. A registration in block H is ACTIVE from H+1.
- **Phase 31 reward caps/fallback.** No wire section exists; the canonical 55/22/13/10 split already
  satisfies the cap/fallback validator, so the harness output passes Phase 31 with the caps gate active
  (confirmed by test).

The live binary gains `--emit-dmc1 / --emit-adm1 / --emit-tkt1 / --phase31-34` flags that select the
options; default (no flag) = the legacy all-gates block.

## Effective timing rules

- **Ticket registrations:** a registration in block H (epoch H+1) is usable for an H+1 role (the store
  marks it `registered_height = H`, active when queried at height > H). Genesis-height eligibility is
  inherently impossible (no earlier block to register), so full ticket-eligibility ENFORCEMENT from
  height 1 is not achievable; the harness exercises registration validity + the H→H+1 active timing.
- **Dominance:** `pre`/`post` digests bind the state around H (pre = blocks < H, post = incl. H).
- **Adaptive:** block H is validated under the pre-mode (blocks < H); H commits the post-mode which is
  active for H+1 (non-retroactive).

## Out of scope

- Cross-host live nodes (Stage B) — separate owner approval.
- Real wallets/keys; public testnet; mainnet.
- Live ticket-eligibility ENFORCEMENT from genesis (inherent H→H+1 limitation; documented).

## Safety boundaries

Devnet only (`network_id` 2); mainnet hard-off; isolated non-default storage; loopback RPC; no P2P in the
smoke; exact-PID/exact-path cleanup; the installed Irium Core production node is never touched.
