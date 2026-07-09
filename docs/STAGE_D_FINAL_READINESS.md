# Stage D / multi-role pool production - final readiness summary

Scope: everything built and proven across this effort, exactly what is ready, and
the one thing that still requires a real Bitaxe hardware test before mainnet
activation could ever be responsibly considered.

Status posture (unchanged throughout): everything is behind the
`stage_d_production_active` gate (hard mainnet-off, default-off), isolated-rig /
devnet only. NOTHING is merged to main, deployed to the live pool, pushed to
origin, or activated. No mainnet activation height has been set or discussed.

Branches (local on the VPS):
- `testing-codes-before-merging` @ `a1a6675` - C4 harness + docs (base for the below).
- `stage-d/live-proposer-wiring` @ `7e74720` (base testing `04c97cb`) - D1-D5 + carrier fix.

---

## 1. What is READY (built, tested, and proven)

### A. Fail-safe multi-role coinbase notify (prior work, `04c97cb`)
The reshaped multi-role notify path was fallible and dropped ASIC sessions on any
coinbase-build error (the reproduced cause of the 3 live breaks). Now infallible:
on any build error it falls back to the self-pay coinbase and keeps the session.
Success path byte-identical; zero live-mainnet change.

### B. C4 sustained-load heap validation - DONE, definitive
The one non-code ASIC-notify risk (heap fragmentation over sustained load) was
validated with a faithful host harness: the real ESP-IDF v5.5.3 multi_heap + TLSF
allocator (-m32) + the real ESP-Miner stratum RX/parse pattern + real cJSON +
genuine captured multi-role frames.
- Accelerated: 30,000,000 jobs at a thin 40 KB margin -> 0 alloc failures, 0
  esp_restart; free stayed one contiguous block start to finish. Zero fragmentation.
- Real-cadence: full 6-hour TCP soak (16,042 jobs) -> identical, 0 failures.
- Verdict: the sustained-fragmentation hypothesis is refuted. The only residual was
  per-notify transient peak footprint (worst on the carrier-laden frame).
- QEMU-ESP32 was honestly ruled out (no WiFi emulation, no ASIC/I2C stack,
  idealized PSRAM) rather than presented as a definitive emulation.

### C. Carrier-stripping mitigation - DONE (closes the C4 residual)
The multi-role coinbase fed the raw template header-relay carriers even to
small-buffer ASIC firmware (the self-pay path already stripped them). Fixed:
`session_template_coinbase_extras` strips carriers per-session for small-buffer
firmware on the multi-role path too. Result: ASIC multi-role notify 4699B/9113B ->
669B; true peak heap footprint ~19KB/~37KB -> ~2.5KB (well below the ~18KB target),
serviceable down to an 8 KB internal heap. Regression-tested. Non-small-buffer
firmware and the STRATUM_CARRIERS=off kill-switch are unchanged.

### D. Stage-D infrastructure (gated, inert)
- Settable mainnet delegation gate (`MAINNET_POAWX_DELEGATION_ACTIVATION_HEIGHT =
  None`); behavior byte-identical today.
- Byte-parity proposer-registration mirror (PRG1) proven against the node.
- Option A ext selection wired (prefers the collected bundle when the gate is on).

### E. D1-D5 delegated direct-payout (proposer-VRF off) - DONE and PROVEN
- D1: the pool holds a custodial proposer secret and advertises its pubkey.
- D2: PRG1 proposer-registration section in the pool ext mirror, full-ext parity
  vs the node (node deserializes + round-trips the pool ext byte-for-byte).
- D3: gated proposer-registration emission (off by default; forward-prep).
- D5: the delegated mode-1 receipt pays the miner directly (worker_pkh = miner);
  proven byte-parity with the node.
- End-to-end (in-process): the node's real connect_block ACCEPTS a delegated
  all-gates block with proposer-VRF off, paying the miner directly on-chain.
- End-to-end (LIVE isolated devnet): the real pool binary produced delegated blocks
  over stratum that the real node ACCEPTED via submit_block_extended
  (source=pool_stratum_native_rewardable, 3 blocks, tip advanced), paying the miner
  directly - with a v2 delegation and no proposer_assignment (proposer-VRF off).
  Isolated storage/ports; mainnet and rig untouched.

### Test status (zero regressions across all of the above)
- Pool suite: 119/0. Node lib: 862/0. Production builds clean.

---

## 2. What is DEFERRED (explicitly, by decision - not blockers to the above)

- D4 - full proposer-VRF custodial mode: the pool would have to produce a real
  RFC-9381 ECVRF proposer proof, but a VRF proof cannot be mirrored (it must be
  computed with the secret) and the pool production path has no ECVRF prover. This
  needs an architecture decision (add an ECVRF prover to the pool / a shared proving
  crate / change proposer custody) and is deferred (Option 1 chosen: ship the
  direct-payout path with proposer-VRF off). Same ECVRF-prover limit also blocks the
  pool from self-producing contributor true-VRF proofs, so the live demo runs the
  gate set that does not require a pool-side prover.
- Distinct per-role live participants: the live devnet used the devnet-only single-
  miner synthetic role source, so all role payouts resolve to the one miner. Distinct
  COMPUTE/VERIFY/SUPPORT participants need the live role-collection path (separate
  work); the in-process node test already proves distinct-participant acceptance.

---

## 3. The ONE thing that still requires REAL BITAXE HARDWARE

Before the `stage_d_production_active` gate could EVER be flipped on for a real
ASIC-facing pool or mainnet, a real (or faithfully device-emulated) Bitaxe-class
ASIC must:
1. connect to a pool serving the reshaped multi-role coinbase (carrier-stripped),
2. assemble coinbase = cb1 + extranonce + cb2, compute the merkle root, and
3. produce accepted shares against that coinbase, sustained, with well-formed
   phase20 exts throughout (so it exercises the multi-role path, not the self-pay
   fallback), and stay heap-stable.

Why the host validation is not sufficient on its own: it faithfully reproduces the
allocator algorithm and the alloc/free pattern (fragmentation is an allocator
property, and both soaks refute it), but it is not silicon - it omits concurrent
WiFi/ASIC/task internal-heap pressure and cache/timing. The rig-green result was
false-green three times; only real hardware closes that gap.

What has changed since those three breaks (why a hardware test is now much more
likely to pass):
- the notify path no longer drops the session on any build error (fail-safe);
- sustained heap fragmentation is refuted by 30M-job + 6h soaks;
- the ASIC-facing multi-role notify is now carrier-stripped (669B, ~2.5KB peak),
  removing the size/footprint variable that correlated with the breaks.

Only after that hardware test explicitly passes and is separately approved could a
mainnet activation height even be discussed. Until then the gate stays off.
