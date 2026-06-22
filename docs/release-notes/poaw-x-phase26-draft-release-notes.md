# PoAW-X Phase 26 Draft Release Notes

> ## ⚠️ Draft only — not a release
> - **DRAFT** documentation. This is **not** a release.
> - **No git tag** has been created. **No GitHub release**. **No binaries/artifacts**.
> - **No mainnet activation.** PoAW-X is hard-off for `network_id == 0`.
> - **NOT production-ready. NOT mainnet-ready. NOT audited.**
> - No public testnet has launched. Nothing here authorizes a launch.
>
> **Phase 27 note (development only — not a release):** subsequent Phase 27 work on branch
> `testnet/poawx-phase27-full-blueprint-implementation` added an off-chain **simulation suite**
> (`poawx-sim`) and a full **gap audit**; it changed no consensus gate. Several blueprint refinements
> remain deferred (see `docs/poaw-x-phase27-known-limitations.md`). Phase 27 is **development only**,
> is **not** part of any release, and is **not** a completion of the full blueprint.

## Audience

- **Independent auditors** evaluating the Phase 26 changes.
- **Internal reviewers** tracking what shipped to the test branch.
- **Future public-testnet operators** (for orientation only; launch is separately gated).

## Branch and commit baseline

- Repo: `https://github.com/iriumlabs/irium.git` (public)
- Branch: `testnet/poawx-phase20-blueprint-completion-local`
- Branch HEAD at this draft: `93fd8f3` (docs); last **source** change: **`0208368`**.
- `origin/main` unchanged at `19c496dc5f2fa08981a109b10eeb257105c28c43`.
- Full source range: **`30bce64..0208368`** (8 source files, +1006/−47; rest = tests + docs).

## Summary of Phase 26

PoAW-X (a multi-role proof-of-aligned-work consensus overlay, devnet/testnet only) moved from
single-block-only to a satisfiable, cold-resync-capable multi-block chain, followed by a full
audit-readiness program.

- **Seed contradiction found (26A):** for a block at height H, the candidate-set gate (phase21d)
  required `candidate_set.seed == hash(H-1)` while the committed-admission gate (phase22a) required the
  set to be seeded by `hash(H-2)` — impossible for H≥2, capping all-gates chains at one block over
  genesis.
- **Epoch-seed alignment implemented (26B):** added the pure helper
  `admission_epoch_seed(parent_prev_hash, block_prev_hash)` (grandparent hash; genesis at the
  activation boundary) and changed **only the expected seed value** in phase21d and the phase21e
  admitted-set lookup key. No gate weakened; phase22a unchanged.
- **Multiblock all-gates chain proven (26B):** a 6-block chain connects through `connect_block` with
  per-height seed invariants; negative tests reject stale seeds and tampered/replayed commitments.
- **Live three-system soak passed (26C):** real Irium-native-PoW all-gates blocks mined, accepted, and
  propagated across Windows + VPS-1 + VPS-2 to the same height/tip.
- **Restart cold-resync fixed (26D):** validated candidate admissions are persisted to an isolated
  data-root file and **re-validated on reload**, so a restarted node rebuilds the chain from disk.
- **Fresh-wipe sync fixed (26E):** when serving block bodies, a node also sends the matching
  admissions (bounded), each **re-validated by the receiver**; a fully-wiped fresh node synced from
  scratch.
- **Audit / readiness packages created (26F–26M):** independent-audit package, public-testnet
  readiness, kickoff, internal self-review, external handoff, remediation workflow, engagement tracker,
  and the program summary/index/commit-map/decision-tracker.

## Validation evidence

- **Repo-local 6-block test:** `phase26b_multiblock_epoch_seed_soak` (plus stale-seed and
  tampered/replayed-commitment negatives) pass.
- **Full serialized lib tests:** `cargo test --lib -- --test-threads=1` → **748 passed / 0 failed**
  (serialized; PoAW-X tests mutate process-global env + the global admission cache). Release build of
  `iriumd` + `poawx-live-proof-harness` succeeds.
- **Live Windows + VPS-1 + VPS-2 6-block soak (26C):** all three nodes reached the same height/tip;
  loopback RPC, source-restricted P2P.
- **Restart cold-replay validation (26D):** a node reloaded persisted candidate admissions and rebuilt
  the active chain to tip from disk, then followed a newly-mined block.
- **Fresh-wipe sync validation (26E):** a fully-wiped node received served historical admissions with
  blocks and synced the chain from scratch, matching peers' tip.

> Live results are summarized from the per-phase docs; logs are summarized, no secrets. These are
> small, controlled devnet runs — not scale or adversarial testing.

## Unchanged areas (verified)

- **phase22a (`validate_block_committed_admission`) unchanged** — byte-identical across
  `30bce64..0208368` (proven in the 26I self-review).
- **phase21e equality unchanged** — `cs.serialize() != admitted.serialize()` still gates connection;
  only the seed the lookup is keyed on changed.
- **No PoW / LWMA / difficulty / target / reward / `constants.rs` change** in the range.
- **Mainnet hard-off** — every PoAW-X gate returns inactive for `network_id == 0`.

## Known limitations

- **Independent audit not completed** — no external audit has occurred; the 26I self-review is **not**
  an audit.
- **Public testnet not launched** — the 26G readiness package is docs-only and launches nothing.
- **Admission window / deep-scale sync** — window default is 64; behavior on deep chains and at scale
  needs broader exposure (a public-testnet objective).
- **phase21e propagation-sensitivity** — phase21e proves "best among candidates admitted to THIS node
  in the window," a documented, pre-existing design consideration unchanged by Phase 26.

## Next steps

1. **Choose an independent auditor** (`docs/audit/phase26l-engagement-tracker/AUDITOR_SELECTION_CRITERIA.md`).
2. **Send the audit package** (after owner inputs + send approval; `docs/audit/phase26j-external-handoff/`).
3. **Handle findings** via the remediation workflow (`docs/audit/phase26k-remediation-workflow/`).
4. **Public testnet only after the audit path** — gated on a scoped sign-off with no open
   Critical/High findings.
5. **Governance / mainnet remains blocked** — out of scope for Phase 26.

See `docs/poaw-x-phase26-final-program-summary.md`, `docs/poaw-x-phase26-index.md`,
`docs/poaw-x-phase26-commit-map.md`, and `docs/poaw-x-phase26-next-decision-tracker.md`.

---

_This draft does not constitute a release, a tag, or any claim of being audited, production-ready, or
mainnet-ready._
