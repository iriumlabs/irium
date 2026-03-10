# Pilot Open-Ready Report

Date: 2026-03-10
Branch: `testing-codes-before-merging`
Target commit: `df928c3a6796c11f6671f9d3713030556b935760`

## 1) Deployment
- VPS pilot checkout `/home/irium/irium-pilot` moved to `df928c3a6796c11f6671f9d3713030556b935760`.
- EU pilot checkout `/home/irium/irium-pilot` moved to `df928c3a6796c11f6671f9d3713030556b935760`.
- Pilot node binaries rebuilt from repo checkout path on both hosts.
- Pilot services restarted (trial services only):
  - VPS: `irium-pilot-node`, `irium-pilot-coordinator`
  - EU: `irium-pilot-node`

## 2) Host parity and runtime proof
- Commit parity: VPS = EU = `df928c3a6796c11f6671f9d3713030556b935760`
- Runtime executable path checks:
  - VPS `iriumd`: `/home/irium/irium-pilot/target/release/iriumd`
  - EU `iriumd`: `/home/irium/irium-pilot/target/release/iriumd`
- `/tmp` runtime drift: none detected after EU pilot-node restart.

## 3) Pre-open checks
### `scripts/pilot_preopen_check.sh`
- Result: PASS

### `scripts/verify_pilot_hosts.sh`
- First run: FAIL due EU process running deleted inode.
- Remediation: restarted EU `irium-pilot-node`.
- Re-run result: PASS

### `scripts/run_atomic_swap_prepilot_gate.sh`
- Result: FAIL
- Failure point: dual-chain assertion stage (`scripts/run_atomic_swap_dual_chain_assert.sh`)
- Exact failure:
  - `IRIUM RPC /rpc/createhtlc http=400 body=`
  - subsequent `invalid txid`
- Meaning: gate stack is deployed and test suites pass, but live assertion preconditions for funding/HTLC creation in this runtime were not satisfied at execution time.

## 4) Optional smoke checks
- Service status:
  - VPS `irium-pilot-node`: active
  - VPS `irium-pilot-coordinator`: active
  - EU `irium-pilot-node`: active
- Health:
  - Coordinator `GET /healthz`: `{"ok":true}`
  - VPS node status endpoint reachable
  - EU node status endpoint reachable
- Coordinator API smoke:
  - `POST /v1/swaps` returns valid swap object with UUID.
  - `GET /v1/swaps/{id}` returns created swap state.

## 5) Open decision
- Selected-user pilot open status: **NO (not yet)**
- Reason: mandatory pre-open gate (`run_atomic_swap_prepilot_gate.sh`) is not green.
- Required action before opening:
  1. satisfy dual-chain assertion funding/HTLC preconditions on current pilot runtime,
  2. rerun `scripts/run_atomic_swap_prepilot_gate.sh`,
  3. require full PASS.

## 6) Safety statement
- HTLCv1 remains OFF by default on Irium mainnet.
- No Irium mainnet activation has been performed.
