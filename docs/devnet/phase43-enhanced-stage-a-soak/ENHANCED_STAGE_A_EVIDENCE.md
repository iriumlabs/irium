# Phase 43 — Enhanced Stage A (Local-Only Loopback) Evidence

Internal devnet soak, **Windows host only, loopback only, no P2P**, using the Phase 42 enhanced harness
with `--phase31-34`. Devnet network id 2. The installed Irium Core production node (PID 4908) was running
and **left untouched**.

## Configuration

- Binary: `target/release/iriumd.exe` (combined Phase-42 build; source == `693d76d`).
- Node A storage: `C:\Users\Ibrahim\irium-poawx-windows-test\phase43-devnet\stage-a\nodeA\` (isolated).
- Node A RPC `127.0.0.1:41151`, status `127.0.0.1:41148`, **no P2P** (`peer_count=0`).
- Harness: `poawx-live-proof-harness.exe --devnet --phase31-34 --rpc-url http://127.0.0.1:41151
  --work-dir …\harness-artifacts` (one block per invocation).
- Gate env (node + harness, identical): full Phase 28–34 set —
  **Phase 33 dominance commitment REQUIRED**, **Phase 34 adaptive commitment REQUIRED**, Phase 32 ticket
  store ACTIVE, Phase 31 reward caps ACTIVE, plus the 21x/22x + Phase 28 finality + Phase 30 stack,
  puzzle bits 4, sybil bits 0. `IRIUM_SKIP_BTC_BOOTSTRAP=1`.
- Genesis (devnet): `0000000028f25d65557e9d8d9e991f516c00d68f5aeae10b750645b398bd10a3`.

## Result — 6 enhanced all-gates blocks accepted (height 0 → 6)

| H | block hash | accepted |
|---|---|---|
| 1 | `5a5877aee45a2bbf5870a5e0794d03d3897d6a9849be8574a52fe3d980cf44a8` | yes |
| 2 | `4b05c774fa9471bc78598bde086b92b3ed1c7eab42b3650ee8b2de9705598a9f` | yes |
| 3 | `3c9869ce7522a3bf9a59c0f7145767465cdb1cf6ffe4fcb48bd4ec7e9a67f664` | yes |
| 4 | `2a0d293f75ffc171bb286109664336020e43d1c840e1258cc4b5f82f831f8c19` | yes |
| 5 | `79fbd0ef656f1ab2ec36ba7498c9b2b338ad3c3104ac30fa10bd05130d350301` | yes |
| 6 | `45114d7ea7cc35928d636748c76937af12018f6e342931c972a4f2a396fbb118` | yes |

Final node status: `height=6`, `persisted_height=6`, tip `45114d7e…`, `peer_count=0`.

## Sections exercised live (proven by required gates)

- **DMC1 (Phase 33): present + valid on every block** — the node ran with
  `DOMINANCE_COMMITMENT_REQUIRED=1`, so a block missing/with-invalid DMC1 is rejected; all 6 connected.
- **ADM1 (Phase 34): present + valid on every block** — the node ran with
  `ADAPTIVE_COMMITMENT_REQUIRED=1`; all 6 connected. With TKT1 emitted (3/block) the adaptive mode is
  **Normal** (recent registered tickets ≥ threshold), and the committed pre/post modes matched the node's
  recompute.
- **TKT1 (Phase 32): present** — ticket store ACTIVE; the harness emitted 3 registrations/block (epoch
  H+1), collected + applied by the node.
- **Reward caps (Phase 31): satisfied** — caps gate ACTIVE; the canonical 55/22/13/10 split (0% official
  fee) passed on every block.
- Legacy all-gates sections (candidate set, candidate admission, committed admission, true-VRF, role
  puzzle proofs, finality proof, role dominance weights) present as before; Phase 28 finalized checkpoint
  advanced as blocks connected.

This is the fuller live counterpart of the Phase 42 3-block smoke: the **combined Phase 28–34 stack**
(incl. DMC1/ADM1 required + TKT1 + caps) was live-driven for 6 blocks on a single loopback node.

Status: internal devnet soak executed; not audited / not production-ready / not mainnet-ready;
public-testnet planning-ready only.
