# Metrics & Evidence

What to measure and capture during the (future) soak. Plan only — nothing captured in Phase 39. All
metrics are read via loopback RPC / logs; none are consensus inputs.

## Per-block / per-node metrics

- **Height** per node (A/B/C[/D]).
- **Tip hash** per node.
- **irx1 / receipt root** per block.
- **PoAW-X extension presence** per block: which of `DSE1` / `TKT1` / `DMC1` / `ADM1` are carried.
- **Finalized checkpoint** height + hash (Phase 28).
- **Ticket store count** (active registered tickets) (Phase 32).
- **Penalty state count** (penalized/suspended signers) (Phase 30).
- **Dominance digest** (Phase 33).
- **Adaptive mode** pre/post + trigger + recovery-window-remaining (Phase 34).

## Sync / safety metrics

- **Sync time** (fresh-wipe and cold-replay): wall-clock to reach tip.
- **Reorg-rejection log line** (Phase 28) when a below-checkpoint reorg is attempted.
- **Fresh-wipe sync success** (S3): wiped node reaches tip + matches peers.
- **Cold replay success** (S4): post-restart derived state equals pre-restart.
- **CPU / memory** rough stats per node (only if easy to capture; not a benchmark).

## Evidence to collect (per scenario)

- Loopback RPC status outputs (height/tip/root/finalized) for each node — saved to the node's log dir.
- Relevant node log excerpts (acceptance, reorg rejection, served-admission, sync warnings).
- Command outputs / terminal captures for each runbook step actually executed.
- For consensus features: the per-node metric snapshots showing they **match** across nodes and across
  replay (this is the core evidence).
- Cleanup confirmation (process stopped by pidfile; storage path removed; mainnet still running).

## Storage of evidence

- Save all artifacts under each node's **log dir** inside its Phase 39 storage root, then **copy/archive
  out before cleanup** to an explicit archive path (record it in `EVIDENCE_LOG_TEMPLATE.md`).
- Do not capture or store any private key, seed, or credential. Redact if a log would contain one.

## Reminder

These are operator/telemetry metrics for evidence only. They do **not** influence consensus; the
adaptive mode and all committed state derive solely from chain-derived data.
