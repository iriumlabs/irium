# PoAW-X Phase 27 — Simulation Results

Canonical output of the `poawx-sim` suite. **Off-chain model only; analysis, not proof. NOT audited /
production-ready / mainnet-ready.** Reproduce exactly with the command below (deterministic for the
given seed).

```
cargo build --release --bin poawx-sim
./target/release/poawx-sim --seed 1 --miners 12 --attacker-share 200 --epochs 4 \
    --blocks-per-epoch 16 --sybil-bits 16 --out-dir ./poawx-sim-out
```

## Canonical run (seed 1, default config)

Config: seed=1, network_id=2 (devnet), miners=12, attacker_share=200‰, epochs=4, blocks_per_epoch=16,
sybil_bits=16. Summary: **10 scenarios, 10 passed, 0 failed.**

| Scenario | Passed | Key metrics |
|----------|--------|-------------|
| normal | ✅ | top1 reward share 284‰, Gini×1000 = 313 |
| low_participation | ✅ | 2 miners, no halt, final adaptive mode = Caution; top1 528‰ |
| dominant_miner | ✅ | raw work 700‰ → realized reward **475‰** (fairness reduces concentration) |
| dominant_pool | ✅ | coordinated group raw 592‰ → reward 392‰ |
| sybil | ✅ | ~130,323 hashes/identity at 16 bits → ~4.17M hashes for 32 identities |
| reorg | ✅ | attacker (200‰) reward share 273‰; below majority |
| randomness_manipulation | ✅ | puzzle-mode distribution bounded under seed bias (no mode capture) |
| reward_distribution | ✅ | ≥2 miners earn; Gini×1000 = 379 |
| finality_attack | ✅ | 2/3 threshold ⇒ attacker ≤666‰ cannot forge finality |
| fresh_wipe | ✅ | informational — Phase 26E live-validated served-admission re-validation |

## What the numbers show

- **Anti-domination works (real `fairness_weight`):** a miner controlling 700‰ of raw work realizes
  only 475‰ of reward over the run, and a coordinated group at 592‰ realizes 392‰ — concentration is
  reduced, but the strong miner is never banned (still earns). This is the **real** node formula,
  reused by the simulator.
- **No halt at low participation:** with 2 miners the chain keeps producing and the **real** adaptive
  `assess()` reports `Caution` (not a halt) — matching the no-halt design goal.
- **Sybil has a real, tunable cost:** at 16 leading-zero bits, each identity costs ~130k SHA-256
  attempts (measured by grinding with the **real** `leading_zero_bits`). At the default
  `IRIUM_POAWX_TICKET_SYBIL_BITS=0` the cost is disabled; raising it imposes the cost.
- **Finality threshold bounds attacks:** with a 2/3 committee threshold, an attacker needs >666‰ of
  committee weight to forge finality and >333‰ to stall — quantified by the `finality_attack` scenario.
- **Determinism:** re-running with the same seed yields byte-identical JSON (verified by test and by a
  CLI diff).

## Caveats (do not over-read)

- The simulator **abstracts** network timing, mempool, true VRF internals, and the actual block wire
  format. It models economics/selection using the real deterministic primitives, but a passing
  scenario is **evidence, not a security proof**.
- The `reorg` and `finality_attack` scenarios are **threshold/share models**; they explicitly note that
  **deep reorg below a finalized checkpoint is a deferred consensus gap** (see
  `docs/poaw-x-phase27-known-limitations.md`, item A) — the node does not yet reject it.
- Metrics vary with `--seed`, `--miners`, `--attacker-share`, etc. The table above is one canonical
  point, not a worst case. Operators should sweep parameters.

## Suggested sweeps

```
# Heavier attacker
./target/release/poawx-sim --seed 1 --attacker-share 450 --scenario reorg,finality_attack --out-dir ./sweep-attacker
# Stronger sybil cost
./target/release/poawx-sim --seed 1 --sybil-bits 20 --scenario sybil --out-dir ./sweep-sybil
# Longer horizon
./target/release/poawx-sim --seed 1 --epochs 12 --blocks-per-epoch 32 --scenario reward_distribution --out-dir ./sweep-long
```

Generated reports (`poawx-sim-report.json`, `poawx-sim-report.md`) are git-ignored
(`poawx-sim-out/`), so they are not committed artifacts.
