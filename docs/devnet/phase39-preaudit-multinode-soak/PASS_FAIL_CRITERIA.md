# Pass / Fail Criteria

For the (future) soak execution. Plan only — not evaluated in Phase 39. A soak "passes" only if **all**
pass criteria hold and **no** fail criterion occurs.

## Pass criteria

1. All nodes **converge** to the same height, tip hash, and irx1 root after each scenario.
2. All planned **block extensions** (`DSE1`/`TKT1`/`DMC1`/`ADM1`) that should be present are present and
   **validated**; absent-when-expected is investigated.
3. **No mainnet/prod process** was touched (verified before, during, after).
4. **No default storage** used (only the explicit Phase 39 roots; isolation guard never bypassed).
5. **Fresh-wipe sync succeeds** (S3): a brand-new node reaches tip and matches peers.
6. **Cold replay succeeds** (S4): a restarted node reconstructs all derived state and reaches tip.
7. **Invalid reorg rejected** (S6): a reorg below the finalized checkpoint is rejected (even higher-work).
8. **No local-only signals affect consensus**: adaptive mode + all committed state depend only on
   chain-derived data; identical chains → identical state across nodes/replay.
9. **No broad firewall rules remain**: any temporary source-restricted rule is removed at cleanup.
10. **All test processes stopped and cleaned**: devnet nodes stopped by exact pidfile; Phase 39 storage
    roots removed; logs archived first.

## Fail criteria (any one ⇒ fail; abort + report)

- Any node **diverges** (different height/tip/root for the same chain).
- A **mainnet/prod process** was stopped, restarted, signaled, or otherwise disturbed.
- **Default storage** (`/tmp`, `~/.irium`, `%USERPROFILE%\.irium`, or the binary default) was used.
- **Unexpected public port exposure** (public RPC/stratum, broad/any-source firewall rule, UDP).
- **Irreversible-cleanup risk** (e.g., a delete targeting a parent/default path).
- A block **accepted with an invalid extension** (malformed/tampered `DSE1`/`TKT1`/`DMC1`/`ADM1` accepted
  when its gate is active).
- **Inconsistent** adaptive / dominance / ticket / penalty / checkpoint state across nodes or across
  replay/reorg.

## Outcome handling

- **Pass** → record evidence; feed into the audit and the public-testnet **planning** decision (still
  owner-gated; not a launch).
- **Fail** → abort (`ABORT_AND_ROLLBACK.md`), preserve logs, file findings (use the Phase 38 finding
  templates if a real defect is found), and do not advance any gate.
