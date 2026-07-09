# Routing / binary-divergence investigation — findings

Investigation only. No production code, gate, or coinbase changed; no live-pool
contact. Follows the refuted size-overflow theory (docs/asic_notify_harness_results.md).

## Question 1: Is the ASIC->multi-role routing change purely data, or structural?

STRUCTURAL. Concrete differences (not just coinbase content):

1. FALLIBLE job/notify path that DROPS the session (CONFIRMED + reproduced).
   The multi-role coinbase path is fallible: `native_rewardable_notify_split` ->
   `build_native_rewardable_coinbase` returns `Result` and errors on
   `"malformed phase20_ext"` (role_reward_pkhs_from_ext_hex returns None) or
   `"native extranonce marker missing"`. In the failed deploy d839b83 this ran
   inside `build_canonical_job_snapshot(&j, &session, &config)?` (via
   `apply_poawx_multi_role_coinbase`); on the current branch it runs inside
   `send_notify` as `native_rewardable_notify_split(snap)?`. At EVERY session call
   site the error propagates via `?` / `break Err(e)` -> the ASIC CONNECTION IS
   DROPPED at job/notify time, before any share is submitted.
   The self-pay path (`coinbase_prefix_suffix`) is INFALLIBLE and can never drop a
   session this way.
   -> This matches the exact live symptom: miners disconnecting (conn 19->5),
      candidate production collapsing to 0 over 2-3 minutes, and REJECTS staying 0
      (sessions are dropped BEFORE submitting, so nothing reaches the reject path).
   -> Reproduced in the unit test
      `repro_multirole_notify_split_is_fallible_and_drops_session_selfpay_is_not`
      (pool suite, passes): a receipt with a present-but-unparseable phase20_ext
      makes the multi-role split Err while the self-pay path stays infallible.

2. Different submit-decode function per adapter (structural): NativeRewardable ->
   handle_submit_native_rewardable + reconstruct_canonical_coinbase; Legacy ->
   handle_submit_legacy_rewardable + reconstruct_coinbase. Only matters AFTER a
   share is found, so it is not the candidate-collapse trigger.

3. Notify WIRE structure is identical across adapters (same JSON params, same
   prev-hash handling, version hard-coded 00000001); only the coinbase content and
   branches source differ. The content was already proven not to overflow the real
   firmware parsers (harness results). So the notify itself is not the break.

4. The CanonicalJobSnapshot is built PER SESSION with `session.extranonce1`, so
   there is no session/snapshot extranonce mismatch. The marker-based split is
   consistent with the session's own extranonce.

Confidence: the fallible-drop MECHANISM is CONFIRMED and reproducible. Whether a
malformed/edge-case ext (or a marker-split failure) actually fired during the three
live deploys is PLAUSIBLE but not proven here — the test shows the path CAN fire,
not that it DID in production. Notably the rig never triggers it, because the rig's
synthetic phase20_ext is always well-formed and its extranonce/coinbase are
controlled — a direct explanation of why "rig-green != live-safe".

## Question 2: The ~1.5 MB binary divergence (10 MB failed vs 8.5 MB caa085a4)

Could not be functionally diffed offline. caa085a4's source lives only in the live
deployment clone (/opt/irium-pool), not in this repo's git history
(`git cat-file -t caa085a4` fails here), and reading /opt would be live-pool
contact, which was excluded. The failed-deploy commits (d839b83 etc.) build on the
full accumulated node/pool codebase (all PoAW-X phases + HTLC/swap stack), which is
~1.5 MB more code than the caa085a4-era pool. That is a large opaque behavioral
surface and a genuine separate deploy risk, but it could not be characterized
without the caa085a4 source. Because Question 1 already yields a concrete structural
mechanism that explains the symptom WITHOUT invoking the binary divergence, the
divergence is a secondary, offline-uncharacterizable suspect rather than a
demonstrated cause.

## Reproduction status

- Unit level: CONFIRMED (test passes) — the fallible multi-role path drops sessions;
  the self-pay path does not.
- Full end-to-end (a real ASIC dropped by a live malformed ext under load): NOT
  reproduced; needs live conditions. The cpuminer/rig path is green as always and
  cannot reproduce ASIC-specific live behavior.

## Conclusion (did NOT come up empty)

The investigation found a CONFIRMED, reproducible structural difference: the
multi-role coinbase path is fallible and its error DROPS the ASIC session, whereas
the self-pay path is infallible. This plausibly explains the live symptom and is
invisible to the rig. It is distinct from, and complementary to, the sustained-load
heap theory (C4) — both are real, offline-invisible mechanisms.

Two things follow for any FUTURE activation of the reshaped-coinbase path (my M3
work, still gated off):
  (a) Code prerequisite: the multi-role / Stage-D production path MUST fail SAFE —
      on ANY coinbase-build error it must fall back to the self-pay coinbase (or the
      prior job) and NEVER drop the session. Today it drops. (This is a code fix for
      a future pass; not made here — investigation only.)
  (b) The sustained-load heap question (C4) still needs a real device.
Both are prerequisites before the gate could ever be flipped; neither is resolved by
the gate simply being off (it is).
