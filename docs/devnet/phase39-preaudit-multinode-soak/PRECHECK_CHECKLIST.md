# Pre-Check Checklist (before any soak execution)

Complete every item before starting nodes. Nothing is executed in Phase 39; this is the gate for a
future execution phase.

| # | Check | Done? |
|---|---|---|
| 1 | Branch + commit verified (audited baseline `78d5ca3` or the agreed soak build) | ☐ |
| 2 | `origin/main` unchanged at `19c496dc5f2fa08981a109b10eeb257105c28c43` | ☐ |
| 3 | Mainnet processes inventoried per host (exact PIDs) and confirmed they will be left untouched | ☐ |
| 4 | Production pool/stratum/wallet processes inventoried and left untouched | ☐ |
| 5 | Current Windows public IP re-checked (it changes between sessions) | ☐ |
| 6 | UFW / firewall rules reviewed; **no change** without explicit approval | ☐ |
| 7 | Explicit isolated storage roots created (`STORAGE_AND_PORT_PLAN.md`); no default/`/tmp`/`.irium` | ☐ |
| 8 | Binaries built (`iriumd`, `poawx-live-proof-harness`, `poawx-sim`) from the agreed commit | ☐ |
| 9 | No default-storage env set; storage-isolation guard verified to reject default paths | ☐ |
| 10 | No real wallet/key files present in the devnet roots; devnet keys only | ☐ |
| 11 | Expected gate env documented (activation heights + required flags for Phases 28–34) and identical across nodes | ☐ |
| 12 | Dominance window/lookback pinned identically across nodes (consensus parameter) | ☐ |
| 13 | Ports verified not to collide with mainnet/pool on each host | ☐ |
| 14 | Abort criteria + cleanup plan understood by the operator (`ABORT_AND_ROLLBACK.md`) | ☐ |
| 15 | `OWNER_APPROVAL_CHECKLIST.md` fully approved | ☐ |

## Notes

- Items 11–12 are critical: divergent gate config or dominance window/lookback across nodes can split
  consensus (these feed committed digests). Pin a single profile.
- Do not proceed if any box is unchecked. Execution is a separate, owner-approved phase.
