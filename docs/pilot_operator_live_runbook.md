# Pilot Operator Live Runbook

## Pre-flight before opening pilot window
1. Run `scripts/verify_pilot_hosts.sh` from code-master VPS.
2. Confirm both hosts are on same pinned commit.
3. Confirm `irium-pilot-node` active on VPS+EU.
4. Confirm `irium-pilot-coordinator` active on VPS.
5. Confirm coordinator and node health endpoints return success.

## Open pilot window
- Announce allowed participant count and window duration.
- Enable intake through approved channel only.

## During pilot
- Watch stuck swap count and error rate.
- Monitor restart events and RPC availability.
- Pause intake on repeated sev1/sev2 issues.

## Pause intake
- Announce pause.
- Keep existing swaps monitored until terminal states.
- Do not take new participants.

## Stop pilot safely
- Announce closure.
- Ensure all active swaps are terminal or explicitly handed off.
- Archive evidence and issue links.

## Stuck swap handling
- classify: claim-eligible, refund-eligible, infra-blocked.
- apply documented recovery action only.
- record actions and timestamps.

## Escalation
- sev1: immediate freeze + incident channel + rollback decision
- sev2: pause intake + investigate + resume criteria
- sev3: continue with tracked fix

## Rollback reference
See: `docs/pilot_rollback_procedure.md`
