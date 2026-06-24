# PoAW-X Mainnet Operator Upgrade Guide (DRAFT — no activation scheduled)

For node operators. **No activation is scheduled; mainnet runs PoW-only and PoAW-X is hard-off until an
announced, owner/governance-approved activation height.** Not audited / not production-ready /
not mainnet-ready.

## What changes at activation (future)

Before the announced height `A`, an upgraded node behaves exactly like today (PoW, LWMA, base reward,
block/header serialization all unchanged; no PoAW-X sections required). At `A` the node begins accepting
PoAW-X block sections; from `E = A + W + 1` it enforces them. PoAW-X is **mainnet-disabled by default**;
activation requires a release that sets the activation constant.

## Operator actions (when an activation is announced)

1. **Upgrade `iriumd`** to the announced activation release before height `A`. Verify the binary version
   and the published checksum.
2. **Do not change** your storage, ports, or keys for the upgrade itself. PoAW-X needs no new wallet
   fields for a plain validating node before activation.
3. **Confirm config**: the activation release ships the pinned consensus parameter profile (gate heights,
   dominance window/lookback). Do **not** override these — divergent values can split consensus.
4. **Monitor** your node across `A` and `E`: height/tip convergence with peers, rejected-block reasons,
   finalized checkpoint advancing, no stuck sync.
5. **Keep the prior binary** available for the documented rollback window (see the rollback doc).

## Do not
- Do not set or guess an activation height yourself.
- Do not run a pre-activation node past `E` (it would reject post-enforcement blocks); upgrade in time.
- Do not expose RPC publicly; keep RPC loopback/firewalled as today.

## Current status
No activation height exists; this guide is preparatory. Nothing to upgrade yet.
