# Execution Go / No-Go

The final gate before a soak execution phase begins. Current state: **No-Go** (execution not approved;
soak not executed). Nothing is executed in Phase 40.

## GO — only if ALL hold

- [ ] Owner has signed the execution checklist (`EXECUTION_READINESS_SIGNOFF.md` items 1–13) and
  `FINAL_OWNER_APPROVAL_TEMPLATE.md`.
- [ ] Branch / commit verified (audited baseline `78d5ca3` or the agreed soak build).
- [ ] Storage roots approved (`STORAGE_ROOTS_SIGNOFF.md`); isolation guard confirmed.
- [ ] Ports approved and confirmed non-colliding with mainnet/pool.
- [ ] Firewall approved **if** cross-host P2P is used (source-restricted, single TCP port) — else N/A
  (loopback-only).
- [ ] Mainnet safety pre-check clean (`MAINNET_SAFETY_PRECHECK.md`, all items).
- [ ] Abort criteria understood (Phase 39 `ABORT_AND_ROLLBACK.md`).

## NO-GO — if ANY is true

- Ambiguous ports or storage paths.
- Windows public IP changed and the source-restricted firewall rule not updated.
- Any uncertainty about a mainnet/prod PID or a possible port overlap.
- Any risk of a default storage path (`/tmp`, `~/.irium`, `%USERPROFILE%\.irium`, binary default).
- No owner approval (or any checklist box still pending).
- Any need to put credentials/secrets into logs or chat.
- Any public-exposure risk (public RPC/stratum, `0.0.0.0/0`, UDP, external miners).

## Decision record (filled at execution time)

```
Date:          [YYYY-MM-DD]
Decision:      [GO | NO-GO]
Topology:      [A | B | C-stage1 | C-stage2]
Rationale:     [...]
Outstanding:   [any conditions]
```

A **Go** authorizes only the internal devnet soak execution phase — not a public testnet or mainnet.
