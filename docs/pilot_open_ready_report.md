# Pilot Open Ready Report

Date: 2026-03-11
Branch: testing-codes-before-merging

## Blocker Root Cause
- `scripts/run_atomic_swap_prepilot_gate.sh` failed in dual-chain assertion because the assertion/monitoring scripts defaulted to `IRIUM_RPC_URL=http://127.0.0.1:49610` and `IRIUM_STATUS_URL=http://127.0.0.1:49390/status`, while the active pilot node runtime is on `58400/58480`.
- During failure reproduction with the correct pilot RPC endpoint, `createhtlc` returned `400` with exact reason `chain_fee_calculation_failed`.
- Under trial mode (`IRIUM_TRIAL_ALLOW_IMMATURE_HTLC_FUNDS=1`), `create_htlc` allowed immature coinbase UTXOs for selection but still called `chain.calculate_fees(&tx)`, which re-ran maturity checks and rejected.

## Fixes Applied
1. `create_htlc` now returns explicit 400 reasons (`(StatusCode, String)`) for rejection paths.
2. `create_htlc` now honors trial immature-fund mode consistently by computing local tx fee (`sum(inputs)-sum(outputs)`) instead of calling `chain.calculate_fees` when `IRIUM_TRIAL_ALLOW_IMMATURE_HTLC_FUNDS=1`.
3. Updated script defaults to pilot runtime endpoints:
   - dual-chain assertion: `IRIUM_RPC_URL=58400`, `IRIUM_STATUS_URL=58480/status`
   - monitoring check: `IRIUM_RPC_URL=58400`, `IRIUM_STATUS_URL=58480/status`
4. Updated monitoring DB default path to pilot DB:
   - `/home/irium/irium-pilot/swap-coordinator.db`
5. Adjusted `iriumd` HTLC test helper expectations for `(StatusCode, String)` and stabilized one HTLC wrong-preimage test fixture under trial immature-fund env toggle.

## Validation
- `scripts/pilot_preopen_check.sh`: PASS
- `scripts/verify_pilot_hosts.sh`: PASS
- `scripts/run_atomic_swap_prepilot_gate.sh`: PASS
  - lib tests: PASS
  - `iriumd` tests: PASS
  - coordinator tests: PASS
  - `cargo check --tests`: PASS
  - dual-chain assertion: PASS
  - monitoring baseline: PASS

## Open Decision
- Selected-user pilot open readiness: **YES**

## Safety
- HTLCv1 remains OFF by default on Irium mainnet.
- No Irium mainnet activation has been performed.
