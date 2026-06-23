# Phase 42 — Validation

Testnet/devnet only; mainnet untouched; not audited.

## In-process integration tests (`phase42_*`, 7/0)

Run with `cargo test phase42 --lib -- --test-threads=1`:

- `phase42_harness_preserves_legacy_all_gates_path` — default options emit no new sections; legacy
  all-gates chain connects; ext round-trips.
- `phase42_harness_emits_tkt1_dmc1_adm1_sections` — with all opts + gates active, the connected block
  carries TKT1 + DMC1 + ADM1 and the ext round-trips.
- `phase42_harness_ticket_h_plus_one_timing` — a registration emitted in block H (epoch H+1) is ACTIVE
  at H+1 (block 1's epoch-2 ticket active at height 2; an unregistered epoch is not active).
- `phase42_harness_dominance_commitment_valid` — the harness DMC1 validates against the node's recompute
  (`validate_block_dominance_commitment`).
- `phase42_harness_adaptive_commitment_valid` — the harness ADM1 validates against the node's recompute
  (`validate_block_adaptive_commitment`).
- `phase42_harness_full_phase31_34_stack_connects` — a 6-block chain with Phase 31 caps active + Phase 33
  DMC **required** + Phase 34 adaptive **required** + Phase 32 ticket store active connects end to end,
  every block carrying TKT1 + DMC1 + ADM1.
- `phase42_harness_no_mainnet_activation` — the builder refuses `network_id == 0` regardless of options.

## Regression

- Focused: phase42 7/0, phase34 17/0, phase33 9/0, phase32 12/0, phase31 10/0, phase30 7/0, phase29 12/0,
  phase28 8/0.
- Full library suite: **829/0** (was 822; +7).
- `poawx-sim`: **17/0**.
- Release build: `iriumd` + `poawx-live-proof-harness` + `poawx-sim` OK; harness `--help` shows the new
  `--emit-*` / `--phase31-34` flags.

## Local-only loopback smoke (binary path)

See `LOCAL_SMOKE_EVIDENCE.md`. The actual binary with `--phase31-34` mined 3 blocks accepted by a node
with **DMC required + adaptive required** (so the sections had to be present and valid), then cold-replayed
to the same tip. The installed Irium Core production node was running and was left untouched.

## Conclusion

The harness can now live-drive Phase 33 (DMC1) and Phase 34 (ADM1) under their **required** gates, emit
Phase 32 (TKT1) registrations with correct H→H+1 timing, and satisfy Phase 31 caps — substantially
closing the Phase 41 gap. Full ticket-store *eligibility* enforcement and cross-host (Stage B) live
soak remain future work (see `README.md` limitations). Not audited / not production-ready /
not mainnet-ready.
