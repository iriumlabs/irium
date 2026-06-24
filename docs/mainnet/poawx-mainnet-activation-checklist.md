# PoAW-X Mainnet Activation Checklist (none scheduled)

**No activation height set; nothing scheduled/deployed; mainnet PoW-only until approved.** Not audited /
not production-ready / not mainnet-ready. All boxes unchecked.

## Engineering readiness
- [ ] Independent audit (Phases 28–34 + C1) complete; Critical/High findings closed (retested).
- [ ] Cross-host Stage B devnet soak passed (full stack under enforcement; fresh-wipe + reorg).
- [ ] Economic-incentive review complete.
- [ ] Deterministic consensus parameter profile pinned (dominance window/lookback, gate heights).
- [ ] Pre-activation compatibility tests green (`mainnet_pre_*`).
- [ ] Post-activation enforcement tests green (`mainnet_*`).

## Activation parameters (owner/governance)
- [ ] Activation height `A` chosen (far future).
- [ ] Warm-up window `W` chosen.
- [ ] `ticket_enforcement_height E = A + W + 1` confirmed.
- [ ] `MAINNET_POAWX_ACTIVATION_HEIGHT` to be set to `Some(A)` in the activation release (NOT in C1).

## Ecosystem
- [ ] Upgraded `iriumd` published.
- [ ] Pool/stratum upgrade published + operators notified.
- [ ] Wallet upgrade published (if any field changes apply).
- [ ] Public announcement issued (height + timeline + upgrade instructions).
- [ ] Sufficient upgrade adoption confirmed before `A`.

## Safety / rollback
- [ ] Rollback/recovery plan reviewed + owner-approved.
- [ ] Monitoring/metrics in place (acceptance, rejects, reorg, finalized checkpoint, adaptive mode).
- [ ] Abort criteria defined.

## Approvals
- [ ] Owner approval.
- [ ] Governance approval.
- [ ] Go/no-go recorded.

Until all are checked, **do not** set an activation height or deploy.
