# Pilot Metrics Checklist

## Core metrics
- swaps_started
- swaps_completed
- swaps_refunded
- swaps_failed
- stuck_swaps_current

## Health metrics
- coordinator_health (up/down)
- irium_vps_pilot_node_health (up/down)
- irium_eu_pilot_node_health (up/down)
- btc_rpc_health (up/down)
- irium_rpc_health (up/down)

## Stability metrics
- service_restart_events
- alert_count_by_type
- median_time_to_terminal_state

## Alert conditions
- coordinator down > 60s
- any pilot node down > 60s
- stuck_swaps_current > threshold
- repeated RPC reconnect failures

## Minimum acceptable thresholds (pilot window)
- coordinator uptime >= 99%
- both pilot nodes reachable
- stuck swaps triaged within 15m
- no unresolved sev1 during active intake
