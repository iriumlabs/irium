# Phase 41 — Stage A (Local-Only Loopback) Evidence

Internal devnet soak, **Windows host only, loopback addresses only, P2P self-contained**. Mainnet was
not running on Windows and was not touched. Devnet network id = 2.

## Configuration

- Binary: `target/release/iriumd.exe` (combined Phase-34 build; source == audited baseline `78d5ca3`).
- Node A storage root: `C:\Users\Ibrahim\irium-poawx-windows-test\phase41-devnet\stage-a\nodeA\`
- Node A RPC/HTTP: `127.0.0.1:41031` · status: `127.0.0.1:41028` (loopback only).
- Harness: `target/release/poawx-live-proof-harness.exe --devnet --rpc-url http://127.0.0.1:41031
  --work-dir …\stage-a\harness-artifacts` (one block per invocation).
- Gate env (identical on node + harness): the proven harness-compatible "all-gates" set —
  `IRIUM_NETWORK=devnet`, `IRIUM_POAWX_MODE=active`, puzzle bits 4, multi-role reward, fairness matrix,
  anti-domination (required), candidate set (required), assignment proof (required), candidate admission
  (required), puzzle work (required), finality committee (required, threshold 1/1), committed admission
  (required), true-VRF (required), double-sign penalty (active). `IRIUM_SKIP_BTC_BOOTSTRAP=1`.
- Genesis (devnet): `0000000028f25d65557e9d8d9e991f516c00d68f5aeae10b750645b398bd10a3`.

## Scenarios & results

### S2 — all-gates block production (6 blocks) — **PASS**
Single node, height 0 → 6, every block accepted live (`accepted:true`). Per-block hashes:

| H | block hash |
|---|---|
| 1 | `532aa3fe7f9819e78f64d2efe7d96a58467de4d685fe45285f4640b7f8be9eac` (irx1 `187797fcca3600e35c45e0b98058d0bf6835d9e24be20d7685488e9e7d482dca`) |
| 2 | `07cc56a48683722802cd18c5471f94c63dafa441c395956f37ecbbd7cba5f4c3` |
| 3 | `796a3aa92708a4734d3ae88829b7e8db10ceb9b0ab311ed8eb49adb265b8594a` |
| 4 | `64b503b096f031fe8194b2d7ba298b2b93b779227b34138cc61b28e33b85617f` |
| 5 | `66cf8148f9ed0162e6300f16044c5eede1af5c6db1dea264a4b5b4d18145f096` |
| 6 | `71bb01b3f13e4dc105c08069660514d0730186bff1c6b898da337c2b9f502fe7` |

Each block carried PoAW-X sections: **candidate_set, candidate_admission, committed_admission,
true_vrf(AVR2), role_puzzle_proofs, finality_proof, role_dominance_weights** — exercising the 21x/22x +
Phase 28 finality stack live. Final node status: `height=6`, `persisted_height=6`, tip
`71bb01b3…`, `peer_count=0` (isolated). 0% fee coinbase.

### S4 — cold restart / replay — **PASS**
Node A stopped by exact PID (cold), restarted on the **same storage**. It reconstructed to
`height=6`, `persisted_height=6`, identical tip `71bb01b3f13e4dc105c08069660514d0730186bff1c6b898da337c2b9f502fe7`
(all derived state, incl. the Phase 28 finalized checkpoint, rebuilt from disk via `connect_block`
replay).

### S1 / S3 — multi-node convergence & fresh-node sync — **NOT EXERCISABLE LOOPBACK-ONLY (deferred to Stage B)**
A fresh node B (own isolated storage, RPC `127.0.0.1:41033`, P2P `127.0.0.1:41032`) was started with
`IRIUM_ADDNODE=127.0.0.1:41030` to dial node A (P2P `127.0.0.1:41030`). After ~180s, node B stayed at
height 0 with `peer_count=0`; its peer-manager logged `outbound_attempts=0` (it never dialed). On
**loopback**, the node treats `127.0.0.1` peers as self/non-routable and does not dial them, so two-node
P2P convergence cannot be demonstrated loopback-only. This is a topology limitation, **not a consensus
defect** — node A's 6-block chain is valid and node B is a valid empty node that simply did not connect.
Genuine multi-node convergence / fresh-wipe-via-P2P needs **distinct hosts/IPs = Stage B**, which
requires separate owner approval + source-restricted firewall rules (`STAGE_B_GO_NO_GO.md`).

## Scope limitation — Phases 31–34 not live-driven (harness)
`poawx-live-proof-harness` builds "all-gates" blocks per the Phase 24K/24L definition (candidate set /
admission / puzzle / finality / committed admission / true-VRF / role dominance weights / 0%-fee
coinbase). It does **not** emit the Phase 31 reward-manifest, Phase 32 ticket-registration (`TKT1`),
Phase 33 dominance-commitment (`DMC1`), or Phase 34 adaptive-commitment (`ADM1`) sections. Therefore
Stage A did not enable enforcement of Phases 31–34 (doing so would reject harness blocks). Phases 31–34
remain validated by the **library test suite (822/0)** and the **simulator (17/0)**; live enforcement of
31–34 requires extending the harness to emit those sections — a future **source-code** phase (out of
scope for Phase 41).

## PIDs used (all exact, all our release iriumd; no mainnet PID touched)
- 1664 — node A initial run (blocks 1–6).
- 6856 — node A cold-replay restart.
- 15528 — node A P2P-enabled restart.
- 1884 — fresh node B (did not connect).

Status: internal devnet soak partially executed (Stage A core scenarios pass; multi-node deferred to
Stage B; 31–34 live enforcement blocked by harness). Not audited / not production-ready / not
mainnet-ready; PoAW-X hard-off on mainnet.
