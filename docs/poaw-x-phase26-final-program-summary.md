# PoAW-X Phase 26 — Final Program Summary

A single orientation document for a new reviewer, operator, or auditor. **NOT audited. NOT
production-ready. NOT mainnet-ready.** Mainnet PoAW-X is hard-off (`network_id == 0`); a public testnet
has not launched and remains gated.

> **Continued in Phases 27–35.** After Phase 26, the Phase 27 blueprint gap audit's six deferred
> consensus items were implemented (Phases 28–34) and consolidated in the Phase 35 closeout. New
> reviewers/auditors should now start from `docs/poaw-x-phase35-final-closeout.md` and
> `docs/audit/phase35-final-handoff/README.md`. Status is unchanged: not audited / not production-ready /
> not mainnet-ready / public-testnet planning-ready only.

## Executive summary

Phase 26 took PoAW-X (a multi-role proof-of-aligned-work consensus overlay) from "single-block-only"
to a **satisfiable, cold-resync-capable multi-block chain on devnet**, then wrapped the work in a
complete **audit-readiness program**. The core technical result: a previously-blocking consensus
contradiction between the candidate-set gate (phase21d/21e) and the committed-admission gate (phase22a)
was resolved by **epoch-seed alignment** — without weakening any gate, without changing
PoW/LWMA/difficulty/target/reward, and with phase22a left byte-for-byte unchanged. Restart cold-resync
and fresh-wipe sync were then fixed by **persisting** and **serving** already-validated candidate
admissions, each re-validated on the receiving side. All of this is devnet/testnet only; mainnet stays
hard-off.

The remaining work is **not** more code — it is an **independent audit** and the decisions that follow
it. Phases 26F–26L produced the audit package, internal self-review, external handoff, remediation
workflow, and engagement tracker so that engagement can start immediately once an auditor is chosen.

## Branch and commit baseline

- Repo: `https://github.com/iriumlabs/irium.git` (public)
- Branch: `testnet/poawx-phase20-blueprint-completion-local`
- Branch HEAD at this summary: `208d5ff` (docs); last **source** change: **`0208368`**.
- `origin/main` unchanged at `19c496dc5f2fa08981a109b10eeb257105c28c43`.
- Full source audit range: **`30bce64..0208368`** (8 source files, +1006/−47; rest = tests + docs).

## Timeline (26A → 26M)

| Phase | What | Type | Key commit |
|-------|------|------|-----------|
| 26A | Seed-reconciliation design (recommends epoch-seed = grandparent) | docs | `30bce64` |
| 26B | Option C epoch-seed alignment implemented + tests | code | `081a1bd` |
| 26C | Live three-system 6-block multiblock soak (26B validated live) | docs | `bfe16fd` |
| 26D | Restart cold-resync fix: persist + reload candidate admissions | code | `de13a83` (+ `abb2fd3` live) |
| 26E | Fresh-wipe sync fix: serve historical admissions during sync | code | `9de939f` (+ `0208368` live) |
| 26F | Independent-audit package (scope, appendix, checklist) | docs | `c15c436` |
| 26G | Public-testnet readiness package (readiness, checklist, risk, runbook) | docs | `972bb9c` |
| 26H | Independent-audit kickoff package | docs | `1217c85` |
| 26I | Internal self-review (748/0; phase22a byte-unchanged proof) | docs | `22dfde8` |
| 26J | External auditor handoff package | docs | `0e196ba` |
| 26K | Audit response / remediation workflow | docs | `6c7681a` |
| 26L | Audit engagement tracker | docs | `208d5ff` |
| 26M | This final program summary + index + commit map + decision tracker | docs | _this commit_ |

See `docs/poaw-x-phase26-commit-map.md` for the full table and source ranges, and
`docs/poaw-x-phase26-index.md` for all document links. Draft release notes (draft only — no tag/
release): `docs/release-notes/poaw-x-phase26-draft-release-notes.md` and
`docs/release-notes/poaw-x-phase26-draft-changelog.md`.

## Major technical achievements

- **Multiblock seed contradiction found (26A):** for a block at height H, phase21d expected
  `candidate_set.seed == hash(H-1)` while phase22a (via the parent's committed admission) required the
  set to be seeded by `hash(H-2)` — impossible for H≥2, which is why all-gates chains could only ever
  extend genesis by one block.
- **Option C epoch-seed alignment implemented (26B):** added the pure helper
  `admission_epoch_seed(parent_prev_hash, block_prev_hash)` (grandparent hash; genesis at the
  activation boundary) and changed **only the expected seed value** in phase21d and the phase21e
  admitted-set lookup key. The phase21e equality check and phase22a are unchanged.
- **6-block repo-local test passed (26B):** `phase26b_multiblock_epoch_seed_soak` connects a 6-block
  chain through `connect_block` with per-height seed invariants; negative tests reject stale seeds and
  tampered/replayed commitments.
- **6-block live three-system soak passed (26C):** real Irium-native-PoW all-gates blocks mined,
  accepted, and propagated across Windows + VPS-1 + VPS-2 to the same height/tip (loopback RPC,
  source-restricted P2P).
- **Restart cold-resync fixed (26D):** validated candidate admissions are persisted to an isolated
  data-root file and **re-validated on reload** at startup, so a restarted node rebuilds the chain from
  disk; live-validated (node reloaded persisted admissions and reached tip).
- **Fresh-wipe sync fixed (26E):** when serving block bodies, a node also sends the matching
  admissions (bounded `16 × served_block_count`), each **re-validated by the receiver**; a fully-wiped
  fresh node synced a 6-block chain from scratch; live-validated.
- **Audit / readiness packages created (26F–26L):** independent-audit package, public-testnet
  readiness, kickoff, internal self-review, external handoff, remediation workflow, and engagement
  tracker.

## Exact claim status

- Production-ready: **no**
- Mainnet-ready: **no**
- Audited: **no** (no independent audit has occurred; the Phase 26I self-review is **not** an audit)

## Mainnet safety statement

PoAW-X is **hard-off for `network_id == 0`** — every PoAW-X gate returns inactive on mainnet, verified
by inspection in 26I and unchanged across `30bce64..0208368`. No PoW/LWMA/difficulty/target/reward or
`constants.rs` change is in the range. The devnet/test block builders are **not** validators; the node
independently validates every block. `origin/main` was never modified throughout Phase 26.

## Remaining blockers

1. **Independent auditor engagement** — an auditor must be chosen and the package sent (owner inputs
   required; see the decision tracker).
2. **External audit findings + remediation** — no external findings exist yet; the remediation workflow
   (26K) is prepared but unused.
3. **Public-testnet launch decision** — gated on the audit outcome; the readiness package (26G) is
   docs-only and launches nothing.
4. **Governance / mainnet activation** — out of scope for Phase 26 and remains blocked.

## Next recommended decision

**Either** provide auditor details (name, company, contact), complete the send checklist, grant
explicit send approval, and send the package — **or** explicitly pause until a reviewer is chosen.
Both are valid; the project will not contact anyone or invent a recipient without owner input. Track
this in `docs/poaw-x-phase26-next-decision-tracker.md` and
`docs/audit/phase26l-engagement-tracker/`.
