# Phase 42 — Live Harness Phase 31–34 Section Support

Extends the PoAW-X live proof harness so internal devnet/live validation can emit and exercise the newer
Phase 31–34 block sections, enabling a fuller Phase 28–34 live soak. **Testnet/devnet only; mainnet
untouched; not audited; not production-ready; not mainnet-ready; public-testnet planning-ready only.**

## What changed (source)

- `src/poawx_mining_harness.rs`: new `AllGatesSections` opt-in struct +
  `build_devnet_all_gates_block_with(opts, …)`; the legacy `build_devnet_all_gates_block` delegates with
  `default()` (byte-identical legacy path). Emits **DMC1** (Phase 33), **ADM1** (Phase 34), and **TKT1**
  (Phase 32) when enabled; Phase 31 caps need no section (canonical split passes).
- `src/bin/poawx-live-proof-harness.rs`: `--emit-dmc1 / --emit-adm1 / --emit-tkt1 / --phase31-34` flags.
- `src/chain.rs`: `phase42_*` tests only (no consensus change).

## Emitted sections

| Section | Phase | Emitted? | How |
|---|---|---|---|
| TKT1 ticket registrations | 32 | **yes** (`--emit-tkt1`) | deterministic devnet registrations, epoch H+1, canonical order, sybil-valid |
| DMC1 dominance commitment | 33 | **yes** (`--emit-dmc1`) | pre = dom after <H, post = dom after H (matches node) |
| ADM1 adaptive commitment | 34 | **yes** (`--emit-adm1`) | replay adaptive state via public `next()`; chain-derived signals only |
| Reward caps/fallback | 31 | n/a (no section) | canonical 55/22/13/10 split satisfies the caps validator |

## Validation

See `VALIDATION.md`. In-process integration tests (`phase42_*`, 7/0) build chains with the Phase 31/33/34
gates active+required and connect every block; full lib suite **829/0**; sim **17/0**. A local-only
loopback smoke (`LOCAL_SMOKE_EVIDENCE.md`) mined 3 blocks via the binary `--phase31-34` accepted by a node
with DMC + adaptive **required** (proving the sections were present and valid), then cold-replayed.

## Limitations (honest)

- **Ticket-eligibility enforcement from genesis is impossible** (H→H+1 timing: a block's role tickets must
  be registered in an earlier block; block 1 has none). The harness emits TKT1 + proves the H→H+1 active
  timing; full ticket-store *eligibility* enforcement live still needs a non-genesis activation design
  and harness `role_ticket_proofs` emission (future work).
- The binary's human-readable `poawx_sections` summary line still lists the legacy sections only
  (cosmetic); the new sections are present (proven by required-gate acceptance).

## Status

production-ready: no · mainnet-ready: no · audited: no · public-testnet-ready: planning-ready only.
This harness extension enables a stronger future soak; it does not itself authorize any launch.

> **Used in Phase 43:** the enhanced harness drove a 6-block single-host Stage A soak with `--phase31-34`
> under DMC + adaptive **required** + TKT1 + caps, plus cold replay —
> `docs/devnet/phase43-enhanced-stage-a-soak/PHASE43_FINAL_REPORT.md`.
