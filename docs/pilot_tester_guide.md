# Pilot Tester Guide (BTC testnet <-> IRM)

## Scope
This is a controlled pilot for BTC **testnet** <-> IRM pilot swap flow.

- This is **not** a production release.
- This is **not** custodial.
- This is **not** Irium mainnet HTLC activation.

## Requirements
- Tester accepted by operator team.
- Bitcoin Core/testnet wallet access (or approved tester wallet setup).
- Ability to run basic RPC/API commands and share logs when asked.

## High-level flow
1. Request pilot access and receive pilot window details.
2. Generate required BTC testnet and IRM pilot addresses.
3. Create/accept swap via coordinator API.
4. Track swap state until claimed/refunded terminal state.
5. Report outcome and any issues.

## Participation steps
1. Receive assigned pilot configuration from operator.
2. Create a unique secret/hash for your swap session.
3. Confirm IRM HTLC funding state.
4. Confirm BTC HTLC funding state.
5. Complete claim path if both sides are healthy.
6. Use refund path if timeout conditions require it.
7. Submit result (swap_id + txids + timestamps).

## Safety rules
- Use testnet/trial funds only.
- Never reuse secrets across sessions.
- Never share private keys with coordinator/operators.
- Do not run old instructions from prior pilot rounds.

## Known limitations
- Controlled participant intake only.
- Manual operator intervention may be required on incident paths.
- Some recovery actions are operator-gated.

## If stuck
Collect and send:
- `swap_id`
- relevant `txid`s
- UTC timestamps
- exact API responses
- brief expected vs actual behavior

Contact path: follow operator-provided support channel for your cohort.
