# Irium Public Stratum Pool

## Quickstart (miners)
Port profiles:

- `3333` (strict canonical): `stratum+tcp://pool.iriumlabs.org:3333`
  - Use for: ASIC/modern firmware
- `3335` (legacy compatibility): `stratum+tcp://pool.iriumlabs.org:3335`
  - Use for: CPU/GPU and older Stratum clients (cpuminer/ccminer/legacy cgminer family)
- Direct IP fallback:
  - `stratum+tcp://157.173.116.134:3333` (strict)
  - `stratum+tcp://157.173.116.134:3335` (legacy)
- Username: `IRM_ADDRESS.worker1`
- Password: `x`

Example username:
- `Q8Ni6TJ6Y77vvtMZ1E474kn2jYNawjvaLa.worker1`

## Recommended endpoint selection

- ASIC/modern firmware: use port `3333`
- CPU/GPU/legacy clients: use port `3335`

Recommended failover list for CPU/GPU/legacy clients:
1. `stratum+tcp://pool.iriumlabs.org:3335`
2. `stratum+tcp://157.173.116.134:3335`
3. `stratum+tcp://pool.iriumlabs.org:3333`

Recommended failover list for ASIC/strict clients:
1. `stratum+tcp://pool.iriumlabs.org:3333`
2. `stratum+tcp://157.173.116.134:3333`
3. `stratum+tcp://pool.iriumlabs.org:3335`

This keeps miners online if DNS resolution fails locally while preserving profile compatibility.

## Payout model (SOLO)
This pool runs in SOLO mode.

- Your username must start with your IRM address.
- If your share finds a valid network block, the block reward is paid to that IRM address.
- Worker suffix (for example `.worker1`) is only for rig identification.

## Connectivity troubleshooting
If you cannot connect:

1. Check DNS resolution:
```bash
getent hosts pool.iriumlabs.org
```

2. Check TCP reachability on both ports (hostname + direct IP):
```bash
nc -vz pool.iriumlabs.org 3333
nc -vz 157.173.116.134 3333
nc -vz pool.iriumlabs.org 3335
nc -vz 157.173.116.134 3335
```

3. Test a raw Stratum subscribe (strict + legacy):
```bash
printf '{"id":1,"method":"mining.subscribe","params":[]}\n' | nc 157.173.116.134 3333
printf '{"id":1,"method":"mining.subscribe","params":[]}\n' | nc 157.173.116.134 3335
```

4. If hostname fails but IP works:
- DNS issue on miner network/ISP.
- Keep mining on direct IP and fix resolver settings later.

5. If both fail:
- Confirm outbound TCP/3333 and TCP/3335 are allowed on firewall/router.
- Check ISP/VPS filtering for mining ports.
- Try another network to isolate local filtering.

## How to verify service is up
From any Linux/macOS shell:
```bash
nc -vz pool.iriumlabs.org 3333
nc -vz pool.iriumlabs.org 3335
nc -vz 157.173.116.134 3333
nc -vz 157.173.116.134 3335
```

From the pool host:
```bash
systemctl status irium-stratum --no-pager
systemctl status irium-stratum-legacy --no-pager
ss -lntp | egrep ':3333|:3335|:3334|:3336'
```

## Operator notes

### Required ports
- Public strict: `3333/tcp` (Stratum strict/ASIC)
- Public legacy: `3335/tcp` (Stratum legacy CPU/GPU)
- Node P2P: `38291/tcp` (if this host also runs a node)
- Keep node RPC private: `127.0.0.1:38300` only

### Service control
```bash
sudo systemctl restart irium-stratum
sudo systemctl restart irium-stratum-legacy
sudo systemctl status irium-stratum --no-pager
sudo systemctl status irium-stratum-legacy --no-pager
journalctl -u irium-stratum -f
journalctl -u irium-stratum-legacy -f
```

### Config locations
- Strict env: `/etc/irium-pool/stratum.env`
- Legacy env: `/etc/irium-pool/stratum-legacy.env`
- Service units: `/etc/systemd/system/irium-stratum.service`, `/etc/systemd/system/irium-stratum-legacy.service`
- Source: `/opt/irium-pool/irium-stratum`

### Security requirements
- Keep `/etc/irium-pool/stratum.env` and `/etc/irium-pool/stratum-legacy.env` mode `600`.
- Do not expose `127.0.0.1:38300` publicly.
- Keep `IRIUM_RPC_TOKEN` secret.

## Common log messages
- `[tmpl] fetch failed ... operation timed out`
: Temporary local RPC/connect stall. Stratum retries automatically.

- `[conn] bad json ...`
: Non-Stratum or malformed traffic hit a public Stratum port.

- `[share] reject ... reason=low_difficulty`
: Share did not meet current pool difficulty target.

- `[block] submitted ...`
: A block candidate met network target and was submitted to the node.

## Disclaimer
Current implementation has been validated with local Stratum handshake and submit-path testing. Broader validation with real ASIC miners is welcome.

## Legacy client routing (March 6, 2026)
Use explicit port routing by hardware/client type:

- `3333` strict canonical profile: ASIC/modern firmware
- `3335` legacy profile: CPU/GPU and older Stratum clients

If direct IP TCP connects but your miner still reports subscribe/authorize issues, verify:
- Algorithm is SHA-256/SHA-256d
- SSL/TLS is disabled (`stratum+tcp://`)
- Worker format is `IRM_ADDRESS.worker1`
- You selected the correct port profile (`3333` vs `3335`)

## Miner Compatibility Matrix

| Miner | Class | Status | Known-good launch hint | Notes |
|---|---|---|---|---|
| `cpuminer-opt 26.1` | CPU | Stable on legacy port | `-a sha256d -o stratum+tcp://pool.iriumlabs.org:3335 -u WALLET.worker -p x -t N` | Use legacy profile port `3335`. |
| `ccminer 2.3.1/2.3.2` | GPU | Stable on legacy port | `-a sha256d -o stratum+tcp://pool.iriumlabs.org:3335 -u WALLET.worker -p x` | Use legacy profile port `3335`. |
| `cgminer/bmminer 4.10.0` | ASIC/legacy | Stable on strict port | Pool0 DNS + Pool1/2 direct IP | Use strict port `3333`; fallback `3335` only if firmware requires it. |
| `irium-miner` | Native | Recommended | Use latest `main` build | Baseline for protocol correctness and debugging. |

Use `/metrics` reject reasons (`rejected_stale`, `rejected_low_difficulty`, `rejected_invalid`, `rejected_duplicate`) for triage.
