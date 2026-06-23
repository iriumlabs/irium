# Remediation Branch Template

Copy this block into the top of each future remediation branch (e.g., as
`REMEDIATION.md` on the branch, or into the finding record). **No remediation branch exists yet.**

```
# Remediation — [F-NNN][, F-MMM if grouped]

Branch name:    testnet/poawx-audit-remediation-[F-NNN]-[short-title]
Finding IDs:    [F-NNN] [+ grouped IDs, owner-approved]
Base commit:    [audited baseline, default 78d5ca3, or approved remediation base]

Fix summary:    [what changed and why it resolves the finding]
Files changed:  [src/...]
Fix commit(s):  [hash(es)]

Tests:
  - Focused:    [cargo test --lib phaseNN -- --test-threads=1  => X/0]
  - Full lib:   [cargo test --lib -- --test-threads=1          => Y/0]
  - Simulator:  [cargo test --bin poawx-sim -- --test-threads=1 => Z/0]
  - Release:    [cargo build --release ... => OK]
  - Added regression test: [name]

Risks / residual: [notes; or "none"]

Retest evidence:  [auditor verdict + commit retested; or "pending"]
Status:           [In remediation | Fixed (pending retest) | Closed (retested) | Accepted risk]
```

## Rules (recap)

- Branch off the audited baseline (or approved remediation base); never `main`.
- One finding per branch unless grouped (owner-approved).
- No force push to a reviewed branch; no merge/PR/tag/release as part of remediation.
- Fix must be additive / non-weakening (no change to PoW/LWMA/base-reward/mainnet; gates not relaxed).
- See `REMEDIATION_BRANCH_POLICY.md`, `REMEDIATION_TEST_MATRIX.md`, `RETEST_PROTOCOL.md`.
