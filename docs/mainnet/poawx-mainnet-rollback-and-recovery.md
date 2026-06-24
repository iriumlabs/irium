# PoAW-X Mainnet Rollback & Recovery (DRAFT — no activation scheduled)

**No activation is scheduled or deployed; mainnet is PoW-only and PoAW-X hard-off.** This documents the
rollback reality for a *future* activation. Not audited / not production-ready / not mainnet-ready.

## Key reality: post-activation rollback is NOT trivial

Once PoAW-X is activated at height `A` and the chain accepts PoAW-X blocks, **rolling back is a
coordinated network action**, not a quiet config flip:

- Blocks at/after `A` carry PoAW-X sections and (from `E`) require them. A node that simply reverts to a
  pre-activation binary would **reject** those blocks and fork off.
- Reverting activation network-wide means a **coordinated reorg / hard-fork** below `A`, which discards
  post-activation history — only feasible very early after `A` and with full operator/miner coordination.

## Pre-activation rollback (easy)

Before height `A`, the activation release behaves like the old node. Rolling back to the prior binary is
safe (no PoAW-X blocks exist yet). This is the only "trivial" rollback window.

## Mitigations that make rollback less likely / less costly

- **Long warm-up `W`** before enforcement `E`: issues can surface during warm-up (sections accepted but
  eligibility not yet required) and activation can be re-evaluated before `E`.
- **Conservative, far-future `A`** with strong upgrade adoption monitoring before `A`.
- **Abort-before-A:** if a Critical issue is found before `A`, publish a release that moves/cancels `A`
  (sets the constant back to `None` or a later height) and have operators upgrade before the original `A`.

## Recovery procedure (future, owner/governance-led)

1. **Detect** (monitoring): consensus split, mass rejects, stuck sync, safety-invariant violation.
2. **Freeze**: halt further mining of the affected chain; communicate to operators/pools.
3. **Decide** (owner/governance): fix-forward (patch + new release) vs. coordinated reorg below `A`.
4. **Execute** the agreed path with all operators; verify convergence.
5. **Post-mortem** + update the risk register.

## Hard rules
- No rollback action touches user funds arbitrarily; any reorg must be transparent + coordinated.
- Owner/governance approval required for any post-activation rollback.

## Current status
Nothing to roll back — no activation height, no deployment.
