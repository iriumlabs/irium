# Fail-safe multi-role coinbase — design / scope (planning only, no code yet)

Goal: the multi-role / Stage-D coinbase path must NEVER drop a session on a build
error. On ANY failure (malformed phase20_ext, missing extranonce marker, or any
other build error) it must fall back to the self-pay coinbase and keep serving the
session exactly as if the multi-role attempt had never been tried.

## 1. Exactly what changes

Introduce a single infallible wrapper used everywhere the multi-role coinbase is
emitted into a session, e.g.:

    // pseudocode — NOT implemented
    fn multi_role_notify_split_or_selfpay(snap, session, job) -> (Vec<u8>, Vec<u8>) {
        match native_rewardable_notify_split(snap) {
            Ok((cb1, cb2)) => (cb1, cb2),
            Err(e) => {
                warn!("[poawx] multi-role coinbase build failed ({e}); \
                       falling back to self-pay for worker={} job={} — session kept",
                       session.worker, job.job_id);
                // exact self-pay path used by the non-native branch today:
                coinbase_prefix_suffix(job.height, job.coinbase_value, &pkh,
                                       session.coinbase_bip34,
                                       session_coinbase_extras(job, session))
            }
        }
    }

Key properties:
- Infallible: returns (cb1, cb2) unconditionally — no `?`, no error propagation, so
  it can never reach the session-drop path.
- On error it returns the SAME bytes the self-pay branch already produces, so the
  session continues with a normal, ASIC-compatible self-pay coinbase (miner is not
  multi-role-attributed for that job, but stays connected and keeps mining).
- Logs a warning with enough context to diagnose which sessions/jobs degraded.
- Success case is byte-identical to today (only the error case changes: drop ->
  self-pay fallback).

## 2. Call sites where the fallback must be applied

Production (non-test) fallible multi-role sites on the current branch:

- PRIMARY (the confirmed candidate-collapse drop): `send_notify` at stratum.rs:4577,
  `let (cb1, cb2) = native_rewardable_notify_split(snap)?;` inside the
  NativeRewardableReserved branch. Its Err propagates to `break Err(e)` (session
  loop, ~2312) / `?` (~2547, ~2615) -> the ASIC connection is DROPPED. This is the
  ONE site that must switch to the infallible wrapper. This alone removes the
  reproduced drop mechanism.

- SECONDARY (robustness, not candidate-collapse): the submit-side reconstruct calls
  `reconstruct_canonical_coinbase(snapshot, &extranonce2)?` at stratum.rs:2783
  (decode_native_rewardable_submit) and :3645 (auxpow parent). An error here rejects
  a share, it does not drop a pre-share session, so it is not the collapse trigger;
  but for completeness these should REJECT the share gracefully (return a share
  error) rather than bubble an error that could tear down the connection. Recommended
  to include, lower priority than PRIMARY.

- NOT a concern now: `build_native_rewardable_job` (build_native_rewardable_coinbase)
  is only reached from tests on the current branch, not production.

- FUTURE: the deferred Stage-D live production wiring (D1-D5,
  docs/m3_stage_d_proposer_production_plan.md) must be built ON TOP of this same
  infallible wrapper from day one — never call the fallible split with `?` in a
  session path.

## 3. How it is tested

Extend the existing reproduction test
`repro_multirole_notify_split_is_fallible_and_drops_session_selfpay_is_not`:

- Keep the current assertion that the RAW `native_rewardable_notify_split` is
  fallible (documents the underlying hazard).
- ADD: call the new infallible wrapper with the SAME malformed-ext snapshot and
  assert it returns Ok/(cb1, cb2) equal to the self-pay `coinbase_prefix_suffix`
  output for that job — i.e. under the exact condition that previously dropped the
  session, the wrapper now yields a self-pay coinbase and the session survives.
- ADD a session-level assertion: drive the send_notify path (or a thin test seam
  over it) with the malformed-ext snapshot and assert it returns Ok (notify sent),
  NOT Err (which is what caused `break Err(e)` / drop). This proves the connection
  is kept.
- Keep the self-pay-infallible contrast assertion.

## 4. Gating — and an honest discrepancy to flag

The requested framing is "gate the fix behind stage_d_production_active so it does
not change any currently-live behavior, since the multi-role path is off by default."
Two honest clarifications:

- The reproduced drop site (send_notify:4577) is the PRE-EXISTING NativeRewardable
  multi-role notify path. It is reachable for NativeRewardableReserved sessions
  (poawx testnet/devnet, or if native_rewardable_enabled) and is gated by adapter
  selection + node_phase20_production_active — it is mainnet-OFF, but it is NOT
  specifically behind `stage_d_production_active`. So "the multi-role path is off by
  default behind stage_d_production_active" is not exactly where this drop lives.
- The fail-safe change is strictly-safer and error-case-only: it changes NO
  success-case behavior anywhere, and NO live-mainnet behavior (mainnet ASIC
  sessions are served self-pay via LegacyRewardable, so send_notify:4577 is not hit
  for them). Therefore applying the wrapper UNCONDITIONALLY at the drop site is the
  correct, minimal, safe fix — it cannot change anything currently live.

Recommendation: apply the infallible wrapper directly at send_notify:4577
(unconditional, because it is strictly safer and touches no live/success behavior),
and require the deferred Stage-D production (behind stage_d_production_active) to use
the same wrapper. If you instead want the fallback strictly conditioned on
stage_d_production_active, that is possible but would leave the pre-existing
NativeRewardable path fallible when the gate is off — i.e. it would NOT fix the exact
path we reproduced. My recommendation is the unconditional wrapper at the drop site.

Either way: mainnet-live behavior is unchanged (ASICs are self-pay there), and the
whole reshaped-coinbase capability stays inert by default.

## 5. Honest assessment: does this + notify-size clearance raise Bitaxe confidence?

Meaningfully YES for the KNOWN failure — but it does NOT reduce the importance of C4.

- The two identified catastrophic mechanisms are: (a) oversize-notify parser
  overflow — REFUTED by the harness (fits every real firmware buffer, even at ~9 KB
  worst case); and (b) fatal drop-on-build-error — REMOVED by this fail-safe. With
  both addressed, a Bitaxe test is much less likely to reproduce the 3x candidate
  collapse, and the pool degrades gracefully (self-pay) instead of dropping if
  anything is off. Confidence against a REPEAT of the known failure: substantially
  higher.

- C4 (sustained-load ESP32 heap) is a DIFFERENT, independent failure class: slow
  heap exhaustion / fragmentation from Bitaxe's per-line realloc churn over hours,
  unrelated to a single oversized notify or a single build error. Neither fix touches
  heap-over-time behavior. So C4 remains EQUALLY necessary — only a real device (or a
  faithful long QEMU-ESP32 run) exercising the multi-role path sustainedly can answer
  it.

- Important interaction: the fail-safe fallback can MASK the multi-role path during a
  Bitaxe test — if errors keep it falling back to self-pay, you would be load-testing
  self-pay, not multi-role. So to actually answer C4 the test must run the multi-role
  path CLEANLY (well-formed exts throughout) for the whole run; the fail-safe is a
  safety net, not a substitute for exercising the real path under sustained load.

Net: fail-safe + size-clearance remove the known "cliff" and make hardware testing
safe to run; C4 (the "slow burn") is undiminished and still gates any activation.
