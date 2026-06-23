# Owner Approval Checklist (before any soak execution)

The soak is **not** executed until the owner approves every item below in writing. Phase 39 only prepares
the plan; execution is a separate phase.

| # | Approval needed | Approved? | Notes |
|---|---|---|---|
| 1 | **Hosts** to use (Windows only, or + VPS-1 / VPS-2) | ☐ | start loopback-only if unsure |
| 2 | **Ports** (devnet P2P/RPC/status per node; no mainnet/pool collision) | ☐ | |
| 3 | **Firewall changes** (only if cross-host P2P; source-restricted, single-port, TCP) | ☐ | owner performs sudo; default = none |
| 4 | **Storage roots** (explicit Phase 39 paths; no default/`/tmp`/`.irium`) | ☐ | |
| 5 | **Duration** of the soak | ☐ | |
| 6 | **Exact cleanup plan** (pidfile stop + path delete + log archive) | ☐ | |
| 7 | Whether to run the **controlled reorg** scenario (S6) | ☐ | |
| 8 | Whether to use **VPS-1 / VPS-2** (vs. local-only) | ☐ | |
| 9 | Whether to **collect/preserve logs** and where to archive them | ☐ | redact any secrets |

## Gate

- Execution may begin only when items 1–9 are approved **and** `PRECHECK_CHECKLIST.md` is fully complete.
- Approvals are logged (reuse `docs/audit/phase37-auditor-selection-engagement/OWNER_DECISION_LOG.md` or
  a dedicated soak decision log).
- A passing soak feeds the audit + public-testnet **planning** decision; it does not, by itself,
  authorize a public testnet or mainnet (`docs/poaw-x-phase35-public-testnet-readiness.md`,
  `docs/audit/phase38-remediation-workflow/NO_MAINNET_NO_PUBLIC_TESTNET_GATES.md`).
