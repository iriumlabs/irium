# Irium Solo Stratum ASIC Mining

Solo Stratum lets an ASIC mine against a user's own Irium node without using a public pool.

## Architecture

```text
ASIC miner
  -> user's irium-miner solo Stratum listener
  -> user's iriumd RPC
  -> Irium P2P network
```

This is not a consensus upgrade. It only translates ASIC Stratum work into the existing node RPC flow:

```text
/rpc/getblocktemplate
/rpc/submit_block
```

## Run a node

Start and sync `iriumd` first. Keep RPC private whenever possible.

```bash
./target/release/iriumd
```

If the node uses RPC auth, export the same token for the miner:

```bash
export IRIUM_RPC_TOKEN=<same-token-as-iriumd>
```

## Start solo Stratum

```bash
export IRIUM_NODE_RPC=https://127.0.0.1:38300
./target/release/irium-miner --solo-stratum --listen 0.0.0.0:3333
```

You can also use environment variables:

```bash
export IRIUM_SOLO_STRATUM=1
export IRIUM_SOLO_STRATUM_LISTEN=0.0.0.0:3333
export IRIUM_SOLO_STRATUM_DIFFICULTY=1
./target/release/irium-miner
```

## CPU multicore mining

Normal CPU solo mining still supports multicore hashing with --threads N or IRIUM_MINER_THREADS=N. Solo Stratum mode is different: ASICs do the hashing, while irium-miner serves work and submits valid blocks.

## ASIC settings

Use the ASIC's SHA-256/SHA-256d mode and point it at the machine running `irium-miner`:

```text
URL:      stratum+tcp://<YOUR_NODE_LAN_OR_VPS_IP>:3333
Worker:   <YOUR_IRIUM_ADDRESS>.worker1
Password: x
```

The worker username should start with the payout address. If it does not, the miner falls back to `IRIUM_MINER_ADDRESS` when set.

## Security

- Keep `iriumd` RPC on localhost or a private network.
- Expose the Stratum port only to trusted ASIC networks unless you intentionally want remote miners.
- Do not commit `/etc/irium/miner.env`, RPC tokens, wallet seeds, or TLS private keys.
- Use firewall allowlists for private farms.

## Public Pool Relationship

Solo Stratum is independent from the official public pool. Users who want simple shared/solo-pool style mining can connect to the public Stratum endpoint. Users who want independence should run their own `iriumd` plus this solo Stratum mode.

Public pool deployment is separate operator infrastructure. Public miner configuration should use the Stratum DNS hostname after operator cutover, not a backend IP. Users who want independence should run their own `iriumd` plus this solo Stratum mode.
