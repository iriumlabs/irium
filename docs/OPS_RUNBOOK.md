# Irium Ops Runbook

## Service Matrix
- `iriumd.service`: core node (P2P + RPC + status)
- `irium-miner.service`: local CPU miner
- `irium-explorer.service`: explorer/pool read API bridge
- `irium-wallet-api.service`: wallet API
- `irium-stratum.service` (pool host only): public Stratum endpoint (`:3333`)

Do not run `irium-ckpool`/`irium-pool-shim` together with `irium-stratum` on the same host.

## Required Ports
- `38291/tcp` public: P2P
- `38300/tcp` localhost-only: node RPC HTTPS
- `8080/tcp` localhost-only: node status HTTP
- `3333/tcp` public on pool host: Stratum
- `38310/tcp` public/private per deployment: explorer API

## Canonical Restart Order
1. `sudo systemctl restart iriumd`
2. `sudo systemctl restart irium-miner irium-wallet-api irium-explorer`
3. Pool host only: `sudo systemctl restart irium-stratum`

## Health Checks
```bash
curl -sS http://127.0.0.1:8080/status
curl -sk https://127.0.0.1:38300/status
ss -lntp | egrep "38291|38300|8080|3333|38310"
```

## Explorer/Pool API Compatibility
Both native and `/api/*` aliases are supported:
- `/status`, `/api/status`
- `/stats`, `/api/stats`
- `/blocks`, `/api/blocks`
- `/mining`, `/api/mining`
- `/pool/stats`, `/api/pool/stats`
- `/pool/payouts`, `/api/pool/payouts`
- `/pool/workers`, `/api/pool/workers`
- `/pool/distribution`, `/api/pool/distribution`
- `/pool/health`, `/api/pool/health`
- `/pool/account/{address}`, `/api/pool/account/{address}`

## Incident Triage
- If `height` < `best_header_tip.height`: node catching up; check peers and logs.
- If peer count is 0: verify outbound connectivity + seedlist.
- If miners connect but no valid shares: verify worker format, SHA-256d profile, and miner clock sync.
- If Stratum on `:3333` fails to bind: another service already owns the port.

## Logs
```bash
journalctl -u iriumd -n 200 --no-pager
journalctl -u irium-miner -n 200 --no-pager
journalctl -u irium-explorer -n 200 --no-pager
journalctl -u irium-wallet-api -n 200 --no-pager
journalctl -u irium-stratum -n 200 --no-pager
```


## Weekly Candidate Path Verification

Run weekly to ensure the full mining pipeline is healthy:

```bash
journalctl -u irium-stratum --since "-7 days" --no-pager | egrep "\[block\] candidate_detected|\[block-submit\] attempt|\[block-submit\] result="
curl -s http://127.0.0.1:3334/metrics | jq '.{candidates_detected,candidates_submitted,blocks_accepted,rpc_submit_attempts,rpc_submit_success,rpc_submit_fail}'
```

Expected path: `candidate_detected -> submit attempt -> submit result`

If missing for >7d with active miners, investigate template freshness, network target checks, and submit RPC connectivity.

## Explorer Freshness Tuning
- Set `IRIUM_EXPLORER_MINERS_REFRESH_SECS=15` in `/etc/irium/explorer.env` for faster active-miner telemetry refresh.
- Restart explorer: `sudo systemctl restart irium-explorer`.
