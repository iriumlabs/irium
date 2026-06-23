# Phase 43 — Cold Replay / Restart Evidence

The enhanced Stage A node was stopped by exact PID (cold) and restarted on the **same** isolated Phase 43
storage, with the same full Phase 28–34 gate env (DMC + adaptive **required**).

## Result — PASS

- Restarted node reconstructed to `height = 6`, identical tip
  `45114d7ea7cc35928d636748c76937af12018f6e342931c972a4f2a396fbb118`, `persisted_height = 6`.
- Because the node restarted with **DOMINANCE_COMMITMENT_REQUIRED + ADAPTIVE_COMMITMENT_REQUIRED**, the
  cold replay re-validated each block's **DMC1** and **ADM1** during `connect_block` reconstruction —
  proving the Phase 33/34 commitments remain valid on replay (and the dominance/adaptive state is
  deterministically rebuilt from the chain). Phase 28 finalized checkpoint and Phase 32 ticket store are
  likewise reconstructed.
- No default storage used (only `…\phase43-devnet\stage-a\nodeA\`).

Note: the `/status` view does not expose the per-block irx1 root or the trailing ext sections; the
required-gate acceptance on replay is the evidence that the committed sections re-validate. The full
in-process replay/round-trip is additionally covered by the `phase42_*` and `phase33/34` library tests.

Status: not audited / not production-ready / not mainnet-ready.
