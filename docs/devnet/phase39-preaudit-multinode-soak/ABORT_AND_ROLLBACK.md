# Abort & Rollback

How to safely stop the (future) soak. Plan only — nothing executed in Phase 39.

## When to abort

- Any node diverges (height/tip/root mismatch for the same chain).
- Any sign a mainnet/prod process was disturbed.
- Unexpected public-port exposure (public RPC/stratum, broad/any-source firewall rule, UDP).
- Any irreversible-cleanup risk (a delete targeting a parent or default path).
- A block accepted with an invalid extension, or inconsistent derived state.
- Operator uncertainty about safety — abort first, investigate after.

## Abort steps (in order)

1. **Stop devnet nodes by exact pidfile** only (`…/nodeX/node.pid`). Never kill by process name; never
   touch mainnet/pool/wallet PIDs.
2. **Preserve logs first** — copy each node's log dir to an explicit archive path **before** deleting any
   storage.
3. **Remove temporary firewall rules only if created** — delete only the exact source-restricted devnet
   P2P allow rule(s) added for this soak; leave all other rules unchanged. (Owner performs sudo/firewall
   actions; passwords typed into a real terminal, never stored.)
4. **Verify mainnet still running** — confirm the inventoried mainnet PIDs (and production pool/stratum)
   are still alive and untouched on every host.
5. **Report partial results** — record what ran, what was observed, and the abort reason in
   `EVIDENCE_LOG_TEMPLATE.md` / `POST_SOAK_REPORT_TEMPLATE.md`.

## Rollback notes

- There is **no change to merge or revert**: the soak runs separate devnet processes/storage; rollback =
  stop + clean those, nothing else.
- Do **not** delete the Phase 39 storage roots until logs are archived.
- If a real defect is found, file it via the Phase 38 finding templates
  (`docs/audit/phase38-remediation-workflow/FINDING_RECORD_TEMPLATE.md`); do not patch consensus blind.

## Safety invariant

Aborting must never (a) touch mainnet/prod, (b) leave a broad/public firewall rule in place, or
(c) delete anything outside the explicit Phase 39 paths.
