# PoAW-X C1 — Mainnet Activation Engineering Summary

**No real activation height is set. No deployment. Mainnet stays PoW-only and PoAW-X hard-off
(`network_id == 0`) until an explicitly-approved future activation.** Not audited; not production-ready;
not mainnet-ready.

## What C1 added (engineering, all gated + disabled by default)

1. **Block-carried reward manifest (`RMF1`)** — `PoawxRewardManifestV1` gained a fixed-size wire format
   and a trailing `RMF1` block section (`poawx_reward.rs`, `poawx.rs`). `connect_block`
   (`validate_block_reward_manifest`) validates it when the reward-manifest gate is active: the carried
   manifest must equal the canonically-derived full 55/22/13/10 split for the block's actual recipients,
   pass the additive caps (total ≤ subsidy+fees, role caps, non-inflation), and not pay a penalized
   finality signer. Required when enforced; absent ⇒ byte-identical pre-activation.
2. **Live role ticket proofs** — the harness now emits `role_ticket_proofs` (epoch H) matching the TKT1
   registrations it made in block H-1, so from H+1 onward the rewarded roles pass Phase 32
   `validate_block_ticket_store_eligibility`.
3. **Phased activation schedule** (`poawx_activation_schedule.rs`) — `MAINNET_POAWX_ACTIVATION_HEIGHT =
   None` (disabled placeholder); warm-up window `W`; `ticket_enforcement_height E = A + W + 1`. Mainnet
   (network 0) always returns no activation regardless of env. Pure, tested gate arithmetic.
4. **Mainnet pre/post-activation tests** — `mainnet_*` tests prove mainnet hard-off by default and the
   full-stack (RMF1+DMC1+ADM1+TKT1+role proofs) block accepts post-activation.
5. **Enhanced devnet proof** — local-only loopback soak with all C1 sections (see
   `poawx-c1-local-devnet-proof.md` if run).

## Activation model (phased; future, not set)

```
height < A      : normal PoW; no PoAW-X sections required (pre-activation compatibility)
height = A      : PoAW-X support begins; warm-up starts (TKT1 registrations collected)
A ..= A + W     : warm-up window (registrations build the store; eligibility NOT yet required)
height >= A+W+1 : full enforcement (RMF1/TKT1 eligibility/DMC1/ADM1 required per their gates)
```

`A` and `W` are **not** chosen here. The mainnet constant is `None`.

## Status

- PoAW-X implementation engineering: **active**
- Live mainnet activation: **no** (no height; disabled)
- Production deployment: **no**
- Release: **no**
- Not audited / not production-ready / not mainnet-ready.

## Remaining blockers before real mainnet activation

1. Choose an activation height (`A`) + warm-up window (`W`) — owner/governance decision.
2. Independent audit (Phases 28–34 + C1) + remediation.
3. Cross-host Stage B devnet soak (owner-approved).
4. Miner / pool / wallet upgrade + advance public announcement.
5. Owner/governance approval + a rollback/recovery plan (see the runbooks in this folder).
