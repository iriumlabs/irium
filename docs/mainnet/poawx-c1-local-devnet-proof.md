# PoAW-X C1 — Local Devnet Proof (enhanced full stack incl. RMF1)

Internal, single-host, **loopback-only** devnet proof of the full C1 stack via the enhanced harness
(`--phase31-34`, which now includes RMF1). Mainnet/prod untouched. Devnet network id 2; PoAW-X hard-off
on mainnet. **No real activation height set.** Not audited / not production-ready / not mainnet-ready.

## Mainnet safety

The installed **Irium Core production node** (PID 4908, `AppData\Local\Irium Core\iriumd.exe --http-rpc`)
was running throughout and was **left fully untouched** (verified alive before/after). My devnet node is
isolated (loopback RPC, isolated storage, devnet magic, no P2P) and cannot contact it.

## Configuration

- Binary: `target/release/iriumd.exe` (C1 build).
- Storage: `C:\Users\Ibrahim\irium-poawx-windows-test\c1-devnet\stage-a\nodeA\` (isolated; removed at cleanup).
- RPC `127.0.0.1:41251`, status `127.0.0.1:41248`, no P2P.
- Node gates: full Phase 28–34 + **RMF1 required** (`IRIUM_POAWX_REWARD_MANIFEST_REQUIRED=1` + caps
  active) + **DMC1 required** + **ADM1 required** + ticket store active + sybil 0.
- Harness: `poawx-live-proof-harness --devnet --phase31-34` (emits RMF1 + TKT1 + DMC1 + ADM1 +
  role ticket proofs).
- Genesis (devnet): `0000000028f25d65557e9d8d9e991f516c00d68f5aeae10b750645b398bd10a3`.

## Result — 6 full-stack blocks accepted (height 0 → 6)

| H | block hash |
|---|---|
| 1 | `1ac080da96d09a11403b320eed82642775bcff6af7abe4e58b418d5a9e32ce94` |
| 2 | `742b2cde3ad03f7bb2283948e997909bdb0accb7138fce873f9a571bce9aab32` |
| 3 | `0d0fe01fcfe13c3dec42253f145331cafbfe045c48514a11881b88bb436d4f8d` |
| 4 | `5a95419621c815fbd1df5d04fc0738550c0789aa0dfa36d133d776c617b527a9` |
| 5 | `3395a65a87981f6ff70878888b9ed51a754ed235e76a039178db4b9e9adf946e` |
| 6 | `30a89204bac6abb99b8279b8acbb3067fb9c86751b9d908a476d84c1cf39b49a` |

Final: `height=6`, `persisted_height=6`, tip `30a89204…`, `peer_count=0`.

## Sections exercised live (proven by required gates)

- **RMF1 (reward manifest): present + valid on every block** — node ran with
  `IRIUM_POAWX_REWARD_MANIFEST_REQUIRED=1`; a block missing/with-non-canonical RMF1 is rejected; all 6
  connected.
- **DMC1 + ADM1: present + valid** — both **required**; all 6 connected.
- **TKT1 + role ticket proofs: present** — ticket store active; registrations collected, role ticket
  proofs emitted (active from H+1).
- **Reward caps (Phase 31): satisfied** — canonical 55/22/13/10 (0% fee).

## Cold replay — PASS

Restart on the same storage reconstructed to `height=6`, identical tip
`30a89204bac6abb99b8279b8acbb3067fb9c86751b9d908a476d84c1cf39b49a`, re-validating RMF1/DMC1/ADM1 under the
required gates.

## Fresh-wipe / multi-node — DEFERRED to Stage B

Loopback multi-node P2P is not exercisable (node does not dial `127.0.0.1` peers); genuine fresh-wipe /
convergence needs an owner-approved cross-host Stage B.

## Notes / limitations

- Full **ticket-store eligibility ENFORCEMENT** from genesis is inherently impossible (H→H+1 timing); the
  phased activation schedule (`poawx_activation_schedule.rs`) models warm-up→enforcement, but the live
  node here keeps ticket-store eligibility non-required (registrations + role proofs are still emitted and
  the H→H+1 active timing is proven by the `mainnet_poawx_role_ticket_proofs_eligible_after_registration`
  test). Wiring the phased schedule into `connect_block`'s ticket-enforcement gate is future work.
- The binary's human-readable `poawx_sections` summary line lists only the legacy sections (cosmetic);
  the new sections are present (proven by required-gate acceptance).

## Cleanup — confirmed

Devnet node stopped by exact PID (26336 mining, 8780 cold-replay); only the production node (4908) remains
(alive, untouched); no Phase-C1 listeners; runtime storage removed by exact path; no firewall rules; no
credentials stored.

## Status

production-ready: no · mainnet-ready: no · audited: no · public-testnet-ready: planning-ready only ·
live mainnet activation: no.
