# Irium Blockchain (Rust Mainnet)

<img src="assets/irium-logo.png" alt="Irium Logo" width="160" />

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org)
[![Network: Mainnet Only](https://img.shields.io/badge/network-mainnet--only-red.svg)](#run-the-rust-node)

Irium is a production‑only proof‑of‑work blockchain for the IRM asset. The network launches with no testnet, no DNS seeds, and a locked genesis that enforces founder vesting and a 100 M IRM cap. This repository now contains the Rust implementation of the full node, miner, and SPV tooling.

- Consensus: SHA‑256d, 600s target, 2016‑block retarget, 50 IRM starting subsidy, halving every 210,000 blocks, 100‑block coinbase maturity, 100 M max supply (3.5 M CLTV‑locked at genesis).
- Bootstrap: signed `bootstrap/seedlist.txt` + `anchors.json`; runtime peers cached in `bootstrap/seedlist.runtime`.
- Design goal: mainnet‑first, DNS‑free bootstrap, light‑client friendly, optional relay rewards.

## Layout
- `assets/` – logos/branding used by docs and API frontends.
- `src/` – Rust sources (node, P2P, miner, SPV, wallet primitives).
- `bootstrap/` – signed seedlist, anchors, trust roots.
- `configs/` – genesis/consensus config.
- `systemd/` – systemd unit templates + env examples.
- `scripts/` – optional shell helpers (no Python entrypoints).
- `state/` – legacy repo-local runtime data (do not commit). Current defaults use `~/.irium/state` for volatile state and `~/.irium/blocks` for blocks.



## Latest Mainnet Update (Feb 2026)
- RPC defaults now use `https://127.0.0.1:38300` for wallet/miner, with one-shot HTTPS -> HTTP fallback when HTTPS fails.
- Node storage is split for safer resync:
  - blocks: `~/.irium/blocks` (persistent)
  - state: `~/.irium/state` (volatile)
- Genesis safety/recovery improved: block 0 is enforced and bad genesis files are quarantined safely.
- Sync reliability improved: better stall recovery, peer/seed dedupe, reduced sync spam, and faster catch-up polling.
- Resync rule: delete ONLY `~/.irium/state` (never delete `~/.irium/blocks` unless intentionally starting fully from scratch).
- Mining support in this repo is CPU miner + Stratum client mode. Native CUDA/OpenCL miner is not included by default.

## Super Simple Start (No Tech)
Follow these steps in order. Keep the node running while you mine.

1) Install Rust (one time):
   - Go to https://rustup.rs and install. Open a new terminal.
2) Download the code:
```
git clone https://github.com/iriumlabs/irium.git
cd irium
```
3) Build it:
```
source ~/.cargo/env
cargo build --release
```
4) Start the node (leave this running):
```
./target/release/iriumd
```
5) Make a wallet address (copy the one that starts with Q):
```
./target/release/irium-wallet init
./target/release/irium-wallet new-address
```
6) Start mining (use your address):
```
export IRIUM_MINER_ADDRESS=<YOUR_ADDRESS>
./target/release/irium-miner --threads 2
```
Tip: If you already set `/etc/irium/miner.env`, the miner will load it automatically (manual runs too).
7) Check your balance:
```
./target/release/irium-wallet balance <YOUR_ADDRESS>
```

Quick fixes:
- Miner says height 1? The node is not running. Start `iriumd` first.
- If you see `HTTP 429`, add this before starting the node AND miner (same value in both terminals):
```
export IRIUM_RPC_TOKEN=$(openssl rand -hex 24)
```
- Mining on another machine? Point the miner to a node:
```
export IRIUM_NODE_RPC=https://<node-ip>:38300
```
- If you see no peers: wait a few minutes, make sure outbound TCP 38291 is allowed, and confirm `bootstrap/seedlist.txt` exists. NAT can show 0 inbound peers even when syncing.
- Miner starts at height 0: the node is still syncing or the miner cannot reach RPC. Check `curl -k https://127.0.0.1:38300/status` and verify `IRIUM_NODE_RPC`.


## FAQ / Common issues
- No peers / stuck at height 0: check outbound TCP 38291, verify seeds in `bootstrap/seedlist.txt`, and restart the node. Some networks block inbound peers.
- Miner starts at height 0: let the node finish syncing and confirm RPC is reachable with `curl -k https://127.0.0.1:38300/status`.
- `[warn] Miner could not fetch block template ... InvalidContentType`: miner/node protocol mismatch. If node serves HTTP, set `IRIUM_NODE_RPC=http://127.0.0.1:38300`; if node serves HTTPS, keep `https://`. Verify with both `curl -s http://127.0.0.1:38300/status` and `curl -sk https://127.0.0.1:38300/status`, then restart miner.
- Miner stuck at height 1: the node isn’t running or `IRIUM_NODE_RPC` is wrong.
- `HTTP 401 Unauthorized`: the node has a token set, but the miner/wallet does not. Use the same `IRIUM_RPC_TOKEN` everywhere.
- `HTTP 429 Too Many Requests`: the node rate‑limit is blocking the miner. Set a token or raise `IRIUM_RATE_LIMIT_PER_MIN` in the node env.
- `unknown parent` / `orphan` during sync: normal while headers/blocks catch up; it clears once the node is fully synced.
- Miner ignores `/etc/irium/miner.env`: manual runs now auto‑load it. Shell exports still override the file.

## Support Us FAQ
- If your miner shows `InvalidContentType` while connecting to `https://127.0.0.1:38300`, your node is likely running HTTP on that port. Set `IRIUM_NODE_RPC` to match the node protocol (`http://` vs `https://`), then restart the miner.

## Termux / Mobile notes
- Expect slow builds and limited resources. Keep the session in the foreground or use `tmux`.
- Many mobile networks block inbound P2P; syncing can still work over outbound connections.
- If P2P is unreliable, point the miner at a public node with `IRIUM_NODE_RPC`.

## Get Started (Download + Run Services)
```bash
git clone https://github.com/iriumlabs/irium.git
cd irium
source ~/.cargo/env
cargo build --release
```
Run each service in its own terminal:
```bash
# Terminal 1: node
IRIUM_NODE_CONFIG=configs/node.json RUST_LOG=info ./target/release/iriumd
```
```bash
# Terminal 2: create an address (save the privkey) and start mining
./target/release/irium-wallet init
./target/release/irium-wallet new-address
./target/release/irium-wallet list-addresses
./target/release/irium-wallet address-to-pkh <YOUR_IRIUM_ADDRESS>
export IRIUM_MINER_ADDRESS=<YOUR_IRIUM_ADDRESS>
./target/release/irium-miner
```
```bash
# Terminal 3: check wallet
./target/release/irium-wallet balance <YOUR_IRIUM_ADDRESS>
./target/release/irium-wallet list-unspent <YOUR_IRIUM_ADDRESS>
./target/release/irium-wallet history <YOUR_IRIUM_ADDRESS>
./target/release/irium-wallet estimate-fee
./target/release/irium-wallet qr <base58_address> [--svg] [--out <file>]
```
```bash
# Optional: SPV tool
./target/release/irium-spv --help
```
Notes:
- Resync/clear cache: delete ONLY `~/.irium/state` (keep `~/.irium/blocks` to avoid re-downloading blocks).
- If the node sits at height 0 with peers=0, set `IRIUM_NODE_CONFIG=configs/node.json` and restart the node.
- If the node requires `IRIUM_RPC_TOKEN`, export the same token for the miner and wallet.
- Keep the printed private key safe; it controls the funds for that address.


## Build & Test
```bash
cd /home/irium/irium
source ~/.cargo/env
cargo test --quiet
```

## Run the Rust Node

### Network Hashrate (estimate)
Use the node RPC to estimate network hashrate from recent blocks:
```bash
curl -k https://127.0.0.1:38300/rpc/network_hashrate
# optional window (blocks)
curl -k https://127.0.0.1:38300/rpc/network_hashrate?window=120
```
Response fields: hashrate, difficulty, avg_block_time, window, sample_blocks, tip_height.

### Important runtime env vars
- `IRIUM_BLOCKS_DIR`: override blocks storage directory (default `~/.irium/blocks`).
- `IRIUM_STATE_DIR`: override volatile state directory (default `~/.irium/state`).
- `IRIUM_P2P_BANNED_LOG_COOLDOWN_SECS`: rate-limit repeated banned-inbound reject logs per IP (default 30s).
- `IRIUM_ANCHOR_MIN_SIGNERS`: minimum valid signatures required for `bootstrap/anchors.json` (default 1).
- `IRIUM_SYBIL_DIFFICULTY` / `IRIUM_SYBIL_DIFFICULTY_MAX`: base and cap for sybil handshake PoW (default 10/20).
- `IRIUM_P2P_MAX_PEERS`: maximum connected peers before rejecting new inbound connections (default 100).
- `IRIUM_P2P_SYNC_COOLDOWN_SECS`: base cooldown between repeated sync requests (default 2).
- `IRIUM_P2P_GETBLOCKS_GRACE_SECS`: grace period before pushing blocks when a peer does not request them (default 8).
- `IRIUM_P2P_FALLBACK_BLOCKS`: number of blocks to push per fallback burst (default 32, max 512).
- `IRIUM_RUNTIME_SEED_DAYS`: minimum consecutive days before a peer is promoted into the runtime seedlist (default 2).
- `IRIUM_RUNTIME_SEED_MAX_IDLE_HOURS`: max idle hours for runtime seedlist promotion (default 24).
- `IRIUM_BANNED_LIST` / `IRIUM_BANNED_TRUST`: optional signed banlist path and allowed signer file (default `bootstrap/banned_peers.txt` + `.sig`, `bootstrap/trust/allowed_ban_signers`).
- `IRIUM_TLS_CERT` / `IRIUM_TLS_KEY`: PEM paths to enable HTTPS for the HTTP API (if unset, HTTP is used).
- `IRIUM_RPC_CA`: optional PEM CA/cert to trust when calling HTTPS RPC endpoints.
- `IRIUM_RPC_INSECURE`: set to `1` to skip TLS validation for `https://localhost` or `https://127.0.0.1` only (dev-only). For anything else, use `IRIUM_RPC_CA`.
- `IRIUM_RPC_TOKEN`: optional bearer token required for `POST /rpc/submit_block` and `POST /rpc/submit_tx`.
- `IRIUM_RPC_BODY_MAX`: max HTTP RPC body size in bytes (default 32MB).
- `IRIUM_NODE_WALLET_FILE`: override node-managed wallet file (default `~/.irium/wallet.core.json`).
- `IRIUM_WALLET_AUTO_LOCK_MIN`: auto-lock minutes for node-managed wallet (default 10, set 0 to disable).
- `IRIUM_NODE_PUBLIC_IP` / `IRIUM_PUBLIC_IP`: optional public IP override for seed nodes.
- `IRIUM_PUBLIC_IP_PROBE_TARGET`: optional `host:port` to probe for outbound IP discovery.

```bash
# optional: set a config JSON with p2p_bind, relay_address, etc.
export IRIUM_NODE_CONFIG=/home/irium/irium/configs/node.json
source ~/.cargo/env
RUST_LOG=info cargo run --release --bin iriumd
```
- By default, seeds are taken from signed `bootstrap/seedlist.txt` (verified with `bootstrap/trust/allowed_signers`) and merged with `bootstrap/seedlist.runtime`.
- HTTP API binds to `IRIUM_NODE_HOST:IRIUM_NODE_PORT` (defaults 127.0.0.1:38300).
- P2P bind/seed overrides can be supplied in `configs/node.json`.

## System Services
Run the node/miner as systemd services so they restart after reboots:
```bash
cd /home/irium/irium
./install.sh
# edit env files, then enable miner
sudo systemctl enable --now irium-miner.service
```
- Node env: `/etc/irium/iriumd.env`
- Miner env: `/etc/irium/miner.env`
- Explorer env: `/etc/irium/explorer.env` (service `irium-explorer.service`)
- Wallet API env: `/etc/irium/wallet-api.env` (service `irium-wallet-api.service`)
- Services run as the user who runs `./install.sh`. Override with `IRIUM_SERVICE_USER=<user> ./install.sh`.

## Mining
The miner binary (`irium-miner`) assembles blocks from the local mempool and searches nonces. Always set a payout address so rewards are spendable:
```bash
cd /home/irium/irium
export IRIUM_MINER_ADDRESS=<YOUR_IRIUM_ADDRESS>   # or set IRIUM_MINER_PKH (40-hex)
source ~/.cargo/env
./target/release/irium-miner
```
- Mined blocks are auto-submitted to `IRIUM_NODE_RPC` (default https://127.0.0.1:38300; one-shot fallback to http if https fails).
- RPC auth tokens are user-defined. Example: `export IRIUM_RPC_TOKEN=$(openssl rand -hex 24)` and set the same value in `/etc/irium/iriumd.env` and `/etc/irium/miner.env`.
- Control CPU usage with `--threads N` or `IRIUM_MINER_THREADS=N` (default 1).
- If you run only the miner, point it at a reachable node RPC with `IRIUM_NODE_RPC=https://<node>:38300` (it will retry once over http if https fails) and set `IRIUM_RPC_TOKEN` if required.
- If the node is running HTTPS + `IRIUM_RPC_TOKEN`, set `IRIUM_NODE_RPC=https://127.0.0.1:38300` and export the same `IRIUM_RPC_TOKEN` for the miner.
- If `IRIUM_RPC_TOKEN` is set to an empty value in env files, miners will still send an empty token and get 401; either remove the line or set a real token.
- For HTTPS with a local self-signed cert, set `IRIUM_RPC_CA=/etc/irium/tls/irium-ca.crt` instead of `IRIUM_RPC_INSECURE=1` (which only works for localhost).
- The miner pulls templates from `/rpc/getblocktemplate` and honors `IRIUM_GBT_MAX_TXS`, `IRIUM_GBT_MIN_FEE`, `IRIUM_GBT_LONGPOLL`, and `IRIUM_GBT_LONGPOLL_SECS`.
- If you see `HTTP 429 Too Many Requests`, set `IRIUM_RPC_TOKEN` in both `iriumd` and the miner, or raise `IRIUM_RATE_LIMIT_PER_MIN` in the node env.
- Set `IRIUM_MINER_STRICT_RPC=1` to stop mining if RPC/template fetch fails.
- The miner pauses if the node is behind peers (sync guard). Set `IRIUM_MINER_SYNC_GUARD=0` to disable, or `IRIUM_MINER_MAX_BEHIND=<n>` to allow a small lag.
- Pool mining (Stratum v1, TCP): set `IRIUM_STRATUM_URL`, `IRIUM_STRATUM_USER`, `IRIUM_STRATUM_PASS`.
Optional: set `IRIUM_RELAY_ADDRESS` to advertise a relay payout address in coinbase outputs.


## Mining (Stratum Pool)
Public SOLO Stratum pool:
- Strict ASIC/modern firmware: `stratum+tcp://pool.iriumlabs.org:3333`
- Legacy CPU/GPU/older clients: `stratum+tcp://pool.iriumlabs.org:3335`
- Direct IP strict fallback: `stratum+tcp://157.173.116.134:3333`
- Direct IP legacy fallback: `stratum+tcp://157.173.116.134:3335`
- If DNS fails on your network, keep pool 0 as hostname and pool 1/2 as direct IP fallback.
- Compatibility update (March 2, 2026): pool server now includes legacy Stratum handlers for older cgminer/bmminer handshakes.
- Username: `IRM_ADDRESS.worker1`
- Password: `x`
- Mode: SOLO (full block reward pays to the IRM address in the username)

OS setup and install/download paths:
- ASIC miners (recommended): use Antminer/Whatsminer web UI and set:
  - Algorithm: `SHA-256d`
  - URL: `stratum+tcp://pool.iriumlabs.org:3333` (strict profile)
  - Worker: `YOUR_IRIUM_WALLET_ADDRESS.worker1`
  - Password: `x`
- Windows software miner (CPU/GPU): download a SHA-256d miner build from:
  - `https://github.com/JayDDee/cpuminer-opt/releases`
  - Example command:
    - `minerd.exe -a sha256d -o stratum+tcp://pool.iriumlabs.org:3335 -u YOUR_IRIUM_WALLET_ADDRESS.worker1 -p x`
- Linux software miner (CPU/GPU): install/build from:
  - `https://github.com/JayDDee/cpuminer-opt`
  - Example command:
    - `./minerd -a sha256d -o stratum+tcp://pool.iriumlabs.org:3335 -u YOUR_IRIUM_WALLET_ADDRESS.worker1 -p x`
- macOS software miner: use a SHA-256d compatible binary or build from the same project above, then run the same command as Linux.

Important:
- For pool mining, choose endpoint by client type:
  - `pool.iriumlabs.org:3333` for strict ASIC/modern firmware
  - `pool.iriumlabs.org:3335` for legacy CPU/GPU/older Stratum clients.
- Do not point pool miners at local node RPC (`127.0.0.1:38300`) unless you are intentionally doing local template mining.

See `docs/POOL_STRATUM.md` for full miner quickstart, troubleshooting, and operator runbook.

### Height mismatch troubleshooting
If pool miners report a block height that is far from explorer height (example: `26994` vs `~15080`), run:

```bash
cd /home/irium/irium
export IRIUM_RPC_URL=https://127.0.0.1:38300
export IRIUM_RPC_TOKEN=<your_rpc_token>
./tools/pool_height_doctor.sh diagnose
```

Optional explorer cross-check:

```bash
./tools/pool_height_doctor.sh diagnose --explorer-status-url "https://api.iriumlabs.org/status"
```

Auto-repair (safe, repeatable):

```bash
./tools/pool_height_doctor.sh fix --explorer-status-url "https://api.iriumlabs.org/status"
```

What output means:
- `LIKELY CAUSE: Multiple iriumd instances`
  This host is running more than one node process. Pool may read templates from the wrong one.
- `LIKELY CAUSE: RPC port listener mismatch`
  Port `38300` is not owned by the intended `iriumd` process.
- `LIKELY CAUSE: Shim template drift/caching or wrong upstream`
  Shim template height differs from node height by more than 2 blocks.
- `LIKELY CAUSE: Forked/wrong chain data`
  Local chain appears on a divergent history and needs backup + resync.

The script prints `NEXT ACTION` with exact steps and, in `fix` mode, applies:
- systemd hardening drop-ins for `iriumd`/`irium-pool-shim`/`irium-stratum`
- shim template sanity checks and logging (`height`, `prevhash`, drift)
- optional chain backup + resync only when fork is detected and `fix` is used.
## Wallet
The wallet CLI stores keys in `~/.irium/wallet.json` (override with `IRIUM_WALLET_FILE`).
```bash
cd /home/irium/irium
source ~/.cargo/env
./target/release/irium-wallet init
./target/release/irium-wallet list-addresses
```
```bash
./target/release/irium-wallet balance <base58_address>
./target/release/irium-wallet list-unspent <base58_address>
./target/release/irium-wallet history <base58_address>
./target/release/irium-wallet estimate-fee
./target/release/irium-wallet qr <base58_address> [--svg] [--out <file>]
```
```bash
./target/release/irium-wallet send <from_addr> <to_addr> <amount_irm>
./target/release/irium-wallet send <from_addr> <to_addr> <amount_irm> --coin-select largest
```

Recovery options (all supported):
```bash
# 1) Seed-based recovery
./target/release/irium-wallet init
./target/release/irium-wallet export-seed --out <file>
./target/release/irium-wallet import-seed <64hex> [--force]

# 2) WIF-based recovery
./target/release/irium-wallet export-wif <base58_address> --out <file>
./target/release/irium-wallet import-wif <wif>

# 3) Full wallet backup / restore
./target/release/irium-wallet backup [--out <file>]
./target/release/irium-wallet restore-backup <file> [--force]
```
- Wallet RPC defaults to `IRIUM_NODE_RPC` (or legacy `IRIUM_RPC_URL`), otherwise https://127.0.0.1:38300. If HTTPS fails and the URL starts with `https://`, it retries once over `http://`.
Use `irium-wallet address-to-pkh <base58_address>` to convert an address to its 20-byte pubkey hash.

### Wallet RPC (node-managed)
The node can manage an encrypted wallet for RPC clients. Default file: `~/.irium/wallet.core.json` (override with `IRIUM_NODE_WALLET_FILE`).
- `POST /wallet/create` { passphrase }
- `POST /wallet/unlock` { passphrase }
- `POST /wallet/lock`
- `GET /wallet/addresses`
- `GET /wallet/receive`
- `POST /wallet/new_address`
- `POST /wallet/send` { to_address, amount, from_address?, fee_mode?, fee_per_byte?, coin_select? }
`amount` is an IRM string like `1.25`. `fee_mode` supports `low`, `normal`, `high`.

## SPV Tooling
`irium-spv` verifies merkle proofs and NiPoPoW proofs against stored block JSON snapshots:
```bash
source ~/.cargo/env
cargo run --release --bin irium-spv -- verify <height> <txid> <index> <proof_hex_csv>
```
```bash
cargo run --release --bin irium-spv -- nipopow-score [blocks_dir] [m]
cargo run --release --bin irium-spv -- nipopow-prove [blocks_dir] [m] [k] [out_json]
cargo run --release --bin irium-spv -- nipopow-verify <proof_json>
cargo run --release --bin irium-spv -- nipopow-compare-proofs <proof_a> <proof_b> [m]
```

## Bootstrap Artifacts
- `bootstrap/seedlist.txt` + `seedlist.txt.sig` – signed initial peers.
- `bootstrap/seedlist.runtime` – node‑learned peers (auto‑updated at runtime).
- `bootstrap/anchors.json` – anchor checkpoints (validation planned).
- `state/peers.json` – peer cache used when seeds are unavailable.

## Systemd Example
See `systemd/iriumd.service` and `systemd/irium-miner.service` for units that run the node/miner under journald with automatic restart.


### Banlist signing
Use SSH signatures for banlists: `ssh-keygen -Y sign -f <signing_key> -n file - < bootstrap/banned_peers.txt > bootstrap/banned_peers.txt.sig`.
Verify with `ssh-keygen -Y verify -f bootstrap/trust/allowed_ban_signers -I ban-signer -n file -s bootstrap/banned_peers.txt.sig < bootstrap/banned_peers.txt`.

## Status / TODO
- Fork‑aware sync, header tracking, relay‑address coinbase support are in place.
- Outstanding: anchor enforcement, richer peer scoring/libp2p parity, production monitoring hardening.

- Operator runbook: 
