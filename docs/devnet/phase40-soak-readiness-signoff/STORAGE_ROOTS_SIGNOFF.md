# Storage Roots Sign-Off

Approve the explicit, isolated storage roots for the soak. **No directories created in Phase 40.**
Approval pending.

## Proposed storage roots

| Host | Storage root |
|---|---|
| Windows | `C:\Users\Ibrahim\irium-poawx-windows-test\phase40-devnet\` |
| VPS-1 | `/home/irium/phase40-devnet/` |
| VPS-2 | `/home/irium/phase40-devnet/` |

Each node uses its own subdirectory under these roots (e.g., `phase40-devnet\nodeA\`, `…/nodeB/`,
`…/nodeC/`), with pidfiles and log dirs inside its own subdirectory.

## Forbidden paths (must be rejected by the node's storage-isolation guard)

- `/tmp` (any temp dir)
- `~/.irium` (Unix home default)
- `%USERPROFILE%\.irium` (Windows home default)
- Any existing **mainnet/prod** data directory
- Any production **pool/stratum/wallet** directory
- The repository working tree's source dirs

## Owner approval

| Item | Approved? |
|---|---|
| Windows storage root approved | ☐ pending |
| VPS-1 storage root approved | ☐ pending |
| VPS-2 storage root approved | ☐ pending |
| Confirmed none overlap mainnet/prod/default paths | ☐ pending |
| Cleanup will delete only these exact roots (logs archived first) | ☐ pending |

## Notes

- Storage roots are created **at execution time**, not in Phase 40.
- Cleanup deletes only these exact roots; never a parent or default path (Phase 39
  `STORAGE_AND_PORT_PLAN.md` cleanup table).
