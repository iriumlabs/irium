# PoAW-X Completion C1 — Pending Blueprint Gap Audit (vs Phase 42)

Engineering audit of the PoAW-X blueprint requirements against the completed Phase 42 code
(`693d76d`), to scope the C1 mainnet-activation engineering. **No real mainnet activation height is set;
mainnet remains PoW-only and PoAW-X hard-off (`network_id == 0`) by default.** Not audited; not deployed.

Branch note: C1 is based on the **Phase 42 stack** (`693d76d`) — the only branch carrying the complete
PoAW-X implementation. `origin/main` (`19c496d`) predates all PoAW-X work and is untouched.

| # | Blueprint requirement | Current status (Phase 42) | File / module | C / P / M | C1 action | Test required |
|---|---|---|---|---|---|---|
| 1 | 55/22/13/10 reward distribution | canonical split enforced; manifest type exists | `poawx::multi_role_amounts`, `poawx_reward.rs` | **Complete** | confirm under activation | reward-split tests (exist) |
| 2 | Block-carried reward manifest | only a PURE wrapper (`PoawxRewardManifestV1`, digest only) — **no wire section** | `poawx_reward.rs` | **Partial** | add **RMF1** trailing section + connect_block validation + harness emit | RMF1 accept/reject suite |
| 3 | Proposer eligibility proof | candidate set + admission + true-VRF assignment | `poawx_candidate.rs`, `poawx_admission.rs` | **Complete** | — (referenced by RMF1) | existing 21d/21e/22d |
| 4 | Best-worker proof | worker receipt PoW + role reward | `poawx.rs`, harness | **Complete** | reference in RMF1 | existing |
| 5 | Other valid worker receipts | role claims (compute/verify/support) | `poawx.rs` `Phase20ReceiptExt` | **Complete** | — | existing |
| 6 | Finality committee signatures | FIN1 finality proof, threshold, validated | `poawx_finality.rs` | **Complete** | — | phase28/existing |
| 7 | Recent reward / dominance commitment | DMC1 block-carried (pre/post digests) | `poawx_dominance.rs`, DMC1 | **Complete** | — | phase33/phase42 |
| 8 | Miner tickets / Sybil proof | MinerWorkTicket + sybil; TKT1 registrations | `poawx_ticket.rs`, TKT1 | **Complete** | — | phase32/phase42 |
| 9 | Role ticket proof emission (live) | harness emits TKT1 but **not** `role_ticket_proofs` for eligibility | `poawx_mining_harness.rs` | **Partial** | emit `role_ticket_proofs` after warmup | warmup→enforce live test |
| 10 | Ticket H→H+1 activation timing | proven at unit level; no phased schedule | `poawx_ticket.rs`, chain | **Partial** | add phased activation (warmup window) | activation-boundary tests |
| 11 | Hidden assignment / VRF | AVR2 true-VRF assignment proofs | `poawx_candidate.rs` (AssignmentProofV2) | **Complete** | — | 22d/existing |
| 12 | Randomized puzzles | PZL1 per-role puzzle solutions | `poawx_puzzle.rs` | **Complete** | — | 21f/existing |
| 13 | Finality checkpoint / reorg protection | monotonic checkpoint + reorg-below-finalized reject | `chain.rs` (Phase 28) | **Complete** | — | phase28 |
| 14 | Double-sign penalties | DSE1 evidence + penalty state + finality exclusion | `poawx_doublesign.rs` (Phase 30) | **Complete** | — | phase30 |
| 15 | Invalid-vote penalties | covered via double-sign/penalty status | `poawx_penalty.rs` | **Complete (scope)** | — | phase29/30 |
| 16 | Adaptive modes | ADM1 block-carried; chain-derived | `poawx_adaptive.rs` (Phase 34) | **Complete** | — | phase34/phase42 |
| 17 | Mainnet activation gating | per-feature env gates; mainnet hard-off; **no unified schedule** | `activation.rs`, per-module gates | **Partial** | add unified **phased activation schedule** (disabled default) | schedule + default-disabled tests |
| 18 | Pre-activation compatibility | gates hard-off on net 0; not asserted as a mainnet suite | `activation.rs` | **Partial** | add `mainnet_pre_*` tests | pre-activation suite |
| 19 | Post-activation enforcement | per-phase enforcement exists; no boundary suite | `chain.rs` | **Partial** | add `mainnet_*` boundary tests | post-activation suite |
| 20 | Live harness coverage (31–34) | DMC1/ADM1/TKT1 emitted (Phase 42) | `poawx_mining_harness.rs` | **Partial** | + RMF1 + role_ticket_proofs | enhanced devnet proof |
| 21 | Cross-host soak readiness | Stage A done; Stage B pending | `docs/devnet/phase39-43` | **Partial (ops)** | out of C1 scope (owner-approved Stage B) | — |

## C1 work items (this phase)

- **RMF1** block-carried reward manifest (item 2) — new wire section + validation + harness + tests.
- **Live `role_ticket_proofs`** emission (item 9) — harness warmup → eligibility.
- **Phased activation schedule** (items 10/17) — `poawx_activation_schedule` module: mainnet activation
  `None` by default; warmup window; `ticket_enforcement_height = A + W + 1`; pure gates + tests.
- **Mainnet pre-/post-activation test suites** (items 18/19).
- **Enhanced local devnet proof** including RMF1 + role_ticket_proofs (item 20).
- **Mainnet activation engineering runbooks** (operational).

## Explicitly NOT in C1

- No real activation height; mainnet disabled-by-default placeholder (`None`).
- No deployment, no live mainnet, no cross-host Stage B (owner-approved separately), no public testnet.

Status: PoAW-X implementation engineering active; live mainnet activation: no; production deployment: no.
Not audited / not production-ready / not mainnet-ready.
