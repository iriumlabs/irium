# Pilot Open-Ready Report (Updated)

Date: 2026-03-10
Branch: `testing-codes-before-merging`

## Root cause traced
- Dual-chain assertion fails because `POST /rpc/createhtlc` returns HTTP 400 on the trial runtime, so `run_atomic_swap_dual_chain_assert.sh` receives an empty `txid` and then fails at `assert_txid` (`invalid txid`).
- Confirmed failure sequence:
  1. `createhtlc` request issued by harness
  2. HTTP 400 response body empty
  3. downstream `txid` parse => empty string
  4. hard fail in assertion

## Fixes applied in this pass
- Pushed code fix commit to pilot branch:
  - `7cee62dbf6fa11d664940ccca800f2f0aab1510a`
  - `2dcf04dd877082dce8c2a86ec176b03952a8fb9f`
- Trial runtime env aligned on both hosts:
  - `IRIUM_HTLCV1_ACTIVATION_HEIGHT=0`
  - `IRIUM_TRIAL_ALLOW_IMMATURE_HTLC_FUNDS=1`
- Both hosts redeployed to latest fix commit and services restarted.

## Deployed commit
- VPS: `2dcf04dd877082dce8c2a86ec176b03952a8fb9f`
- EU:  `2dcf04dd877082dce8c2a86ec176b03952a8fb9f`

## Parity proof
- `pilot_preopen_check.sh`: PASS
- `verify_pilot_hosts.sh`: PASS
  - commit parity PASS
  - runtime path PASS (`/home/irium/irium-pilot/target/release/iriumd` both hosts)
  - no `/tmp` drift PASS
  - mainnet activation safety PASS

## Mandatory gate status
- `run_atomic_swap_prepilot_gate.sh`: **FAIL**
- Failure point remains identical:
  - `[FAIL] IRIUM RPC /rpc/createhtlc http=400 body=`
  - `[FAIL] invalid txid:`

## Open decision
- Selected-user pilot open status: **NO**
- Mandatory pre-open gate is still not fully green.

## Safety statement
- HTLCv1 remains OFF by default on Irium mainnet.
- No Irium mainnet activation has been performed.
