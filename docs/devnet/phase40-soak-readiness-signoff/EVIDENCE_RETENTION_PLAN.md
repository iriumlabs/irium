# Evidence Retention Plan

What to keep from the (future) soak, and what to never keep. Nothing captured in Phase 40. Approval
pending.

## What to keep

- Per-node status snapshots (height, tip hash, irx1 root, finalized checkpoint) per scenario.
- Relevant log excerpts: block acceptance, reorg-rejection lines, served-admission / fresh-wipe sync,
  cold-replay reconstruction, adaptive/dominance/ticket/penalty state.
- Command outputs for each runbook step actually executed.
- The filled `EVIDENCE_LOG_TEMPLATE.md` entries and the `POST_SOAK_REPORT_TEMPLATE.md`.

## Where to store

- During the run: under each node's **log dir** inside its isolated Phase 40 storage root.
- After the run: **archive out before cleanup** to an explicit archive path (record it in the evidence
  log). Cleanup deletes storage roots only after archiving.

## Naming convention

`phase40-<scenario>-<host>-<YYYYMMDD-HHMM>.<ext>` (e.g.,
`phase40-S3-nodeC-20260101-1430.log`). Keep names free of any secret.

## What NOT to save (ever)

- **Credentials / passwords** (SSH, sudo, RPC auth).
- **Private keys / seed phrases**.
- **Real wallet data**.
- Any value that could compromise mainnet/prod.
- If a log would contain any of the above, **redact before archiving**.

## Retention & approval

| Item | Value |
|---|---|
| Retention duration | `[FILL — owner decides]` |
| Archive location | `[FILL — explicit path; not default/prod]` |
| Redaction confirmed before archive | ☐ pending |
| Owner approves retention plan | ☐ pending |

These are operator/telemetry artifacts only; none is a consensus input and none implies the system is
audited or production-ready.
