# PoAW-X Mainnet Activation Risk Register (C1)

Risks specific to a *future* PoAW-X mainnet activation. **No activation is scheduled; mainnet is PoW-only
and PoAW-X hard-off by default.** Not audited / not production-ready / not mainnet-ready.

| # | Risk | Likelihood | Impact | Mitigation (status) | Residual |
|---|---|---|---|---|---|
| M1 | No independent audit of the consensus stack (28–34 + C1) | High | Critical | Commission audit + remediate (NOT done) | High |
| M2 | Activation height chosen too soon / accidental | Low (disabled by default) | Critical | `MAINNET_POAWX_ACTIVATION_HEIGHT = None`; far-future `A`; tests assert default-disabled | Low while None |
| M3 | Incomplete miner/pool/wallet upgrade before `A` | Med | High | Advance announcement + adoption monitoring + far-future `A` (NOT done) | Med |
| M4 | Consensus split from divergent gate/parameter config | Med | Critical | Pinned consensus parameter profile shipped in the activation release (engineering done; ops pending) | Med |
| M5 | Post-activation rollback is not trivial | Med | High | Long warm-up `W`; abort-before-`A`; documented recovery (`poawx-mainnet-rollback-and-recovery.md`) | Med |
| M6 | RMF1/TKT1/DMC1/ADM1 wire bug under real load | Med | High | Cross-host Stage B soak + audit + deserializer fuzzing (NOT done) | Med–High |
| M7 | Ticket warm-up mis-timed → roles ineligible at `E` | Med | High | Phased schedule `E = A+W+1`; warm-up window; upgrade guides (engineering done; ops pending) | Med |
| M8 | Reward manifest mismatch rejects honest blocks | Low | High | RMF1 = canonical manifest (exact match) validated additively; tests (engineering done) | Low–Med |
| M9 | Economic-incentive flaw in combined system | Med | High | Independent economic review (NOT done) | Med–High |
| M10 | No cross-host live validation of the combined stack | Med | High | Owner-approved Stage B soak (NOT done) | Med–High |
| M11 | Governance process for activation undefined | Med | High | Define governance + approval gates (NOT started) | High when approached |

## Posture

These risks keep PoAW-X at **not audited / not production-ready / not mainnet-ready**. The disabled-by-
default activation (M2) and the additive, gated, hard-off-on-mainnet design keep the *current* mainnet
unaffected. No risk here is closed by C1 to the point of authorizing activation; C1 is engineering only.
