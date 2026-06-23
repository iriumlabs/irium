# Duration & Resource Plan

Choose the soak duration and note resource expectations. **No run in Phase 40.** Selection pending.

## Duration options

| Option | Length | Best for | Owner selection |
|---|---|---|---|
| Short smoke | 30–60 min | quick "does it converge + sync" check (S1–S5, S15) | `[ ]` |
| Medium soak | 3–6 hours | minimum recommended set incl. ticket/dominance/adaptive replay | `[ ]` |
| Long soak | 12–24 hours | sustained stability + more scenarios (S7/S11–S13) | `[ ]` |
| Extended soak | 48+ hours | endurance / drift observation | `[ ]` |

Recommended first run: **short smoke** (Option A topology) → then **medium soak** once the smoke passes.

## Resource notes

- **CPU:** devnet mining is low-difficulty (puzzle bits small); modest CPU per node. Avoid co-locating
  many nodes on a constrained host.
- **Disk:** small chains; the main consumer is logs — keep them under each node's log dir within the
  isolated storage root; rotate/cap if running long/extended.
- **Logs:** size grows with duration; archive + prune per `EVIDENCE_RETENTION_PLAN.md`.
- **Network:** loopback-only (Option A) ⇒ negligible. Cross-host (Option B/C2) ⇒ light P2P traffic on
  the single source-restricted port.
- **VPS impact:** ensure the devnet nodes do not contend with the production pool/mainnet node on VPS-1/2
  (CPU, disk, ports). Inventory first (`MAINNET_SAFETY_PRECHECK.md`).
- **Mainnet isolation:** mainnet runs untouched throughout; devnet is fully separate
  processes/storage/ports.

## Gate

Duration is approved in `EXECUTION_READINESS_SIGNOFF.md` (item 6). Longer durations increase log/resource
footprint — confirm retention + host headroom before choosing long/extended.
