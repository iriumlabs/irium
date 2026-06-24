# PoAW-X Mainnet Activation Runbook (DRAFT — no activation scheduled)

**No real activation height is set; nothing here is scheduled or deployed. Mainnet remains PoW-only and
PoAW-X hard-off until an explicitly owner/governance-approved activation.** Not audited; not
production-ready; not mainnet-ready.

This runbook describes the *engineering procedure* for a future PoAW-X mainnet activation. It is a plan,
not an execution.

## Pre-conditions (all required before scheduling)

- Independent audit of Phases 28–34 + C1 complete; findings remediated + retested.
- Cross-host devnet (Stage B) soak passed with the full stack under enforcement.
- Activation height `A` and warm-up window `W` chosen by owner/governance; `A` must be **far in the
  future** (well beyond current tip) to allow upgrades and announcement.
- Miner/pool/wallet upgrade builds published and adopted (see the upgrade guides in this folder).
- Public announcement issued with the activation height + timeline.
- Rollback/recovery plan reviewed (`poawx-mainnet-rollback-and-recovery.md`).

## Procedure (future)

1. **Set the activation constants** (not done in C1): set `MAINNET_POAWX_ACTIVATION_HEIGHT = Some(A)` and
   the warm-up window; build a tagged release (release/tag is a later, separate step — never in C1).
2. **Publish** the upgraded `iriumd` (+ pool/wallet) and the activation announcement.
3. **Pre-activation (`height < A`)**: nodes run normal PoW; verify no PoAW-X sections are required and
   `validate` accepts legacy blocks. Monitor upgrade adoption.
4. **Activation (`height = A`)**: PoAW-X support begins. Warm-up starts. Miners begin emitting PoAW-X
   sections + TKT1 registrations. Monitor acceptance/reject reasons.
5. **Warm-up (`A ..= A+W`)**: confirm the on-chain ticket store fills; eligibility not yet required.
6. **Enforcement (`height >= A+W+1`)**: full enforcement (RMF1 + TKT1 eligibility + DMC1 + ADM1 +
   finality/double-sign). Monitor convergence, reorg-rejection, finalized checkpoint, adaptive mode.
7. **Post-activation monitoring**: watch for divergence, stuck sync, unexpected rejections; keep the
   rollback plan armed.

## Hard rules (apply to any future execution)

- Do not weaken pre-activation PoW. Do not change LWMA/base reward except enforcing the PoAW-X split
  after activation.
- Activation must be announced well in advance; never use a current/near height.
- Rollback after activation is **not trivial** (see the rollback doc) — treat activation as one-way
  absent a coordinated reorg/hard-fork.
- Owner/governance approval is required at every gate.

## C1 status

Procedure documented only. No constant set, no release, no deployment, no live mainnet touched.
