# Mining Irium

This guide covers all the ways to mine IRM: from a single laptop on the
desktop app to a Bitaxe pointed at the official pool to a multi-GPU rig
running T-Rex. Block reward is 50 IRM per block during the Early Miner
Era; halves every 210,000 blocks. Block target is 10 minutes (actual
mean closer to 1-2 minutes on the current small network).

The easiest entry point for new miners is the **Irium Core desktop app**:
[https://github.com/iriumlabs/irium-core/releases/latest](https://github.com/iriumlabs/irium-core/releases/latest).
It bundles iriumd, irium-wallet, the CPU + GPU miners, and a one-click
pool connector, so you can start hashing in under a minute. The command-
line paths below are for advanced miners and rig operators.

---

## One-Click Mining (Linux / macOS / Windows)

For anyone who wants to start mining immediately without learning
any CLI flags, every release archive at
[github.com/iriumlabs/irium/releases/latest](https://github.com/iriumlabs/irium/releases/latest)
now ships ready-to-run mining scripts alongside the binaries:

| OS      | GPU (pool, recommended) | CPU (solo, local iriumd) |
|---------|--------------------------|---------------------------|
| Linux   | `./mine-gpu.sh`         | `./mine-cpu.sh`           |
| macOS   | `./mine-gpu-mac.sh`     | `./mine-cpu-mac.sh`       |
| Windows | `mine-gpu.bat`          | `mine-cpu.bat`            |

How to use:

1. Download the archive for your platform and extract it.
2. Linux/macOS: open Terminal in the extracted folder. Windows:
   double-click the .bat file.
3. Linux/macOS users: `./mine-gpu.sh` (or the mac variant).
4. When prompted, paste your Irium wallet address (starts with **P**
   or **Q**). It is saved to `mine-config.txt` next to the script so
   you only enter it once.
5. Mining starts automatically and auto-restarts if it crashes.

Every archive ships **all six** scripts so a user who downloaded the
wrong archive or moved a folder between machines still has the right
launcher handy. The Linux scripts call `chmod +x` on themselves and
on the bundled miner. The macOS scripts additionally remove the
`com.apple.quarantine` extended attribute so Gatekeeper does not
block the unsigned binary on first launch.

**GPU scripts** connect to the official Irium pool at
`stratum+tcp://pool.iriumlabs.org:3335`. Direct-payout mode: when one
of your shares meets the network target, the full 50 IRM block reward
goes directly to the address you used as your worker name. Zero fees.

**CPU scripts** run the bundled `irium-miner` against a local iriumd
at `http://127.0.0.1:38300`. Start iriumd first  the Irium Core
desktop app exposes that endpoint automatically. For pool-based CPU
mining install `cpuminer-opt` separately (see the CPU section
below; the bundled `irium-miner` is solo-only).

---

## Important — block 22,888 hard fork

The chain activates Bitcoin-standard block-header serialization at
**block 22,888** (Fix 2a). Pre-fork, only the bundled reference miners
(`irium-miner`, `irium-miner-gpu`) and the official pool's
`irium-stratum` accepted iriumd's legacy header format. Post-fork, every
standard SHA-256d miner (Bitaxe, S19, S21, T-Rex, lolMiner, NBMiner,
cpuminer-opt, ccminer, etc.) produces valid blocks because the chain
now hashes headers exactly like Bitcoin.

**This means external ASIC and GPU miners earn real block rewards
starting at block 22,888**, with no special firmware patches.

Make sure your iriumd is on v1.9.28 or newer (latest tag is v1.9.32 —
see [github.com/iriumlabs/irium/releases/latest](https://github.com/iriumlabs/irium/releases/latest))
before block 22,888 is mined; older nodes will fork off.

---

## Pool endpoints (official pool)

`pool.iriumlabs.org` is the DNS hostname for the official Irium pool.

**Unified direct-payout model:** every port runs the same payout
behaviour. When one of your shares meets the network target, the
**full 50 IRM block reward** is paid by the coinbase **directly to the
IRM address you used as your Stratum worker name**. There is **zero
pool fee** — the pool operator takes nothing. The pool wallet does
not accumulate or redistribute funds.

| Port | Use for |
|------|---------|
| **3333** | ASIC (S19, S21, Bitaxe, Whatsminer, Avalon, etc.). Strict canonical Stratum profile, higher baseline difficulty. |
| **3335** | CPU / GPU / older Stratum clients (cpuminer-opt, ccminer). Legacy profile, lower baseline difficulty. |
| **443** | Firewall-bypass for ISPs that block mining ports (notably China). Same Stratum protocol on the HTTPS port to escape DPI filtering. |

**Worker name format:** `<IRM_ADDRESS>.<worker_id>` — for example
`Q8Ni6TJ6Y77vvtMZ1E474kn2jYNawjvaLa.rig1`. The worker suffix is for
your own bookkeeping only. The IRM address prefix is what the pool
uses to build your coinbase — **a typo or invalid address means the
coinbase has no valid output for you**.

**Password:** literally `x` (the conventional Stratum no-op password).

**Live stats:** [https://pool.iriumlabs.org/stats](https://pool.iriumlabs.org/stats)
shows active miners, accepted/rejected shares, blocks found, and a
rolling 15-minute hashrate estimate. The raw CORS-enabled JSON proxy
is at `http://pool.iriumlabs.org:3337/stats` and per-miner detail at
`http://pool.iriumlabs.org:3337/miners`.

**Hashrate estimation:** the stats-proxy computes a per-miner hashrate
over the rolling 15-minute share window using each worker's live
`current_diff` value scraped from the stratum `/metrics` endpoint.
This means the estimate tracks vardiff drift accurately rather than
assuming a fixed baseline. Workers with `rolling_pct=None` are still
in the warmup window (< 1 minute of samples after a restart or fresh
connection).

---

## Pool mining — by hardware

### ASIC (Bitaxe, S19, S21, Whatsminer, Avalon)

Bitaxe (Antminer S19-compatible firmware) web UI:

| Field | Value |
|-------|-------|
| Stratum URL | `pool.iriumlabs.org` |
| Stratum Port | `3333` (try `443` if your ISP blocks 3333) |
| Stratum User | `<YOUR_IRM_ADDRESS>.bitaxe1` |
| Stratum Password | `x` |
| Algorithm | SHA-256 / SHA-256d |
| TLS | OFF |

After block 22,888 the Bitaxe earns IRM block rewards directly to the
address you set as the Stratum user.

For S19/S21 firmware, the equivalent commit fields are:

| BraiinsOS / Vnish / Stock firmware | Value |
|---|---|
| Pool URL | `stratum+tcp://pool.iriumlabs.org:3333` |
| Worker | `<YOUR_IRM_ADDRESS>.rig1` |
| Password | `x` |

### GPU — T-Rex

```
t-rex -a sha256d \
      -o stratum+tcp://pool.iriumlabs.org:3335 \
      -u <YOUR_IRM_ADDRESS>.gpu1 \
      -p x
```

### GPU — lolMiner

```
lolMiner --algo SHA256D \
         --pool stratum+tcp://pool.iriumlabs.org:3335 \
         --user <YOUR_IRM_ADDRESS>.gpu1 \
         --pass x
```

### GPU — NBMiner

```
nbminer -a sha256d \
        -o stratum+tcp://pool.iriumlabs.org:3335 \
        -u <YOUR_IRM_ADDRESS>.gpu1 \
        -p x
```

### CPU — cpuminer-opt

```
cpuminer-opt -a sha256d \
             -o stratum+tcp://pool.iriumlabs.org:3335 \
             -u <YOUR_IRM_ADDRESS>.cpu1 \
             -p x \
             -t <NUM_THREADS>
```

### CPU/GPU — bundled `irium-miner-gpu` (this repo)

```
irium-miner-gpu \
  --pool stratum+tcp://pool.iriumlabs.org:3335 \
  --wallet <YOUR_IRM_ADDRESS>
```

The bundled miner accepts the same Stratum URL as the third-party
miners above and was the only client that could find blocks pre-fork.
After block 22,888 it has no special advantage over T-Rex / lolMiner /
NBMiner.

---

## Bypassing ISP port blocks (China and similar networks)

Some ISPs block outbound TCP to ports commonly associated with mining
(3333, 4444, etc.). The official pool exposes the same Stratum
protocol on **port 443** specifically to work around this. The bytes
on the wire are still Stratum — the port number is HTTPS-shaped so
that deep-packet-inspection systems pass it through.

For any miner, simply swap the port:

```
stratum+tcp://pool.iriumlabs.org:443     # works even when 3333/3335 fail
```

If 443 also fails, the issue is likely DNS-level filtering — see the
[POOL_STRATUM connectivity-troubleshooting section](POOL_STRATUM.md).

---

## Solo mining (no pool)

For users who want to mine directly against their own node without
sharing rewards. Block discovery is rare on a busy chain — on a small
network like the current Irium mainnet it can be reasonable, but pool
mining gives steadier results.

### Solo CPU (bundled)

`irium-miner` reads its payout address and node URL from environment
variables — there is no `--address` or `--rpc` flag on the CPU miner:

```
IRIUM_MINER_ADDRESS=<YOUR_IRM_ADDRESS> \
IRIUM_NODE_RPC=http://127.0.0.1:38300 \
  irium-miner
```

Optional: `--threads N` (or `IRIUM_MINER_THREADS=N`) to limit worker
threads. See [`docs/WALLET-CLI.md`](WALLET-CLI.md#solo-cpu-mining--irium-miner)
for the full env-var reference.

### Solo GPU (bundled, requires OpenCL)

```
irium-miner-gpu --wallet <YOUR_IRM_ADDRESS> --rpc http://127.0.0.1:38300
```

`--list-platforms` enumerates detected OpenCL platforms and devices.
`--platform <vendor|index>` and `--devices 0,1,2` pin the miner to a
specific GPU set.

### Solo via any standard SHA-256d miner (post-fork)

After block 22,888, you can also run any standard SHA-256d miner
(cpuminer-opt, ccminer, T-Rex) directly against the solo Stratum
bridge. The bridge lives in `irium-miner --solo-stratum`, NOT in
iriumd itself — iriumd exposes only HTTP RPC on port 38300 and has
no Stratum listener of its own.

```
# Start the solo Stratum bridge (binds 0.0.0.0:3333 by default).
irium-miner --solo-stratum --listen 0.0.0.0:3333

# Point your miner at it:
t-rex -a sha256d -o stratum+tcp://127.0.0.1:3333 -u <YOUR_IRM_ADDRESS>.local -p x
```

See [SOLO_STRATUM.md](SOLO_STRATUM.md) for the solo-mining bridge
configuration in detail.

---

## Verifying a miner is producing blocks

Pool stats: every accepted share appears in the
[https://pool.iriumlabs.org/stats](https://pool.iriumlabs.org/stats)
counters within ~30 seconds. Confirmed blocks land in the `blocks_found`
field.

Local node: when your worker finds a block, iriumd's journal logs:

```
[block] accepted height=<N> hash=<HASH> miner=<YOUR_IRM_ADDRESS>
```

Wallet:

```
irium-wallet balance <YOUR_IRM_ADDRESS>
```

The reward credits after 100-block coinbase maturity (~3 hours at
target block time).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Miner connects but submits zero shares | Worker name missing or wrong format | Use `<IRM_ADDRESS>.<worker>` exactly |
| `stratum+tcp` connect refused on 3333 | ISP block | Switch to port 443 |
| Many `rejected_low_difficulty` shares | Hardware below baseline diff | Use port 3335 (lower baseline) instead of 3333 |
| Many `rejected_stale` shares | High network latency or miner clock skew | Sync system clock (NTP); check round-trip latency to `pool.iriumlabs.org` |
| Block found but no reward credit yet | Coinbase maturity (100 blocks ≈ 3 hours) | Wait; or `irium-wallet history <address>` to see unmatured coinbase |
| Pre-fork: standard SHA-256d miner finds shares but no blocks | Header hashing differs pre-Fix-2a | Wait for block 22,888; or use bundled `irium-miner` until then |

---

## See also

- [docs/POOL_STRATUM.md](POOL_STRATUM.md) — operator-level pool details, raw connectivity testing
- [docs/SOLO_STRATUM.md](SOLO_STRATUM.md) — self-hosted solo stratum bridge (run your own node)
- [docs/POOL-OPERATOR.md](POOL-OPERATOR.md) — running your own Irium Stratum pool
- [GPU-MINER.md](../GPU-MINER.md) — bundled GPU miner detailed reference
- [docs/MERGED-MINING.md](MERGED-MINING.md) — AuxPoW merged mining (activates at block 26,500)
