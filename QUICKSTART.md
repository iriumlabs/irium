# Irium Rust Quickstart (Mainnet)



## Latest Mainnet Update (Feb 2026)
- Wallet/miner RPC default is now `https://127.0.0.1:38300` with one-shot HTTPS -> HTTP fallback.
- Sync/storage split is active by default:
  - `~/.irium/blocks` keeps downloaded blocks
  - `~/.irium/state` stores volatile sync/cache data
- Safe resync procedure: delete ONLY `~/.irium/state`, keep `~/.irium/blocks`.
- Sync reliability improvements include stall recovery + reduced repeated seed/dial noise.
- CPU mining is built-in; Stratum client mode is supported; native GPU/OpenCL/CUDA miner is not bundled.
- Node status and mining RPC now expose `network_era`, `network_era_description`, `network_era_tagline`, and `early_participation_signal`.
- The official `irium-miner` does not require code changes for these status and telemetry additions.

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
IRIUM_NODE_CONFIG=configs/node.json ./target/release/iriumd
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
- Node stuck at height 0 / peers=0: start with `IRIUM_NODE_CONFIG=configs/node.json` so seeds load.
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


If you want the detailed/advanced steps, continue below.



## Public Stratum Pool (SOLO)
> [!IMPORTANT]
> Pool compatibility baseline (March 2026):
> - Officially supported miner: irium-miner.
> - Some third-party GPU miner builds (including some ccminer variants) may connect but still submit rejected shares (for example low_difficulty) due to protocol-handling differences.
> - If this happens, share miner version, exact launch command, and 30-50 lines of logs so compatibility can be triaged quickly.

If you prefer pool mode, use the public Irium Stratum endpoint after the pool DNS cutover is confirmed. This is a Stratum TCP endpoint, not a browser website:

- ASIC/modern firmware pool URL: `stratum+tcp://pool.iriumlabs.org:3333`
- CPU/GPU software miner pool URL: `stratum+tcp://pool.iriumlabs.org:3335`
- Use the DNS hostname only after operator cutover; backend pool IPs are operator-private and may change.
- Compatibility update (March 2, 2026): legacy Stratum handshake support enabled on the pool server for older ASIC and software miner clients.
- Username: `IRM_ADDRESS.worker1`
- Password: `x`
- Mode: SOLO (if your worker finds a valid block, reward pays to the IRM address in the username)

How to start on each OS:
- ASIC miners (recommended): in miner web UI (Antminer/Whatsminer), set:
  - Algorithm: `SHA-256d`
  - URL: `stratum+tcp://pool.iriumlabs.org:3333`
  - Worker: `YOUR_IRIUM_WALLET_ADDRESS.worker1`
  - Password: `x`
- Windows software miner: download SHA-256d miner binaries from:
  - `https://github.com/JayDDee/cpuminer-opt/releases`
  - Run:
```bash
minerd.exe -a sha256d -o stratum+tcp://pool.iriumlabs.org:3335 -u YOUR_IRIUM_WALLET_ADDRESS.worker1 -p x
```
- Linux/macOS software miner: build/install from:
  - `https://github.com/JayDDee/cpuminer-opt`
  - Run:
```bash
./minerd -a sha256d -o stratum+tcp://pool.iriumlabs.org:3335 -u YOUR_IRIUM_WALLET_ADDRESS.worker1 -p x
```

Using `irium-miner` in Stratum mode:
```bash
export IRIUM_STRATUM_URL=stratum+tcp://pool.iriumlabs.org:3335
export IRIUM_STRATUM_USER=IRM_ADDRESS.worker1
export IRIUM_STRATUM_PASS=x
./target/release/irium-miner --threads 2
```

Important:
- For ASIC pool mining, use `pool.iriumlabs.org:3333`; for CPU/GPU software miners, use `pool.iriumlabs.org:3335`.
- Do not use `127.0.0.1:38300` for pool mode (that is local node RPC/template path).

For troubleshooting and operator notes, see `docs/POOL_STRATUM.md`.

## Network Hashrate (estimate)
```bash
curl -k https://127.0.0.1:38300/rpc/network_hashrate
curl -k https://127.0.0.1:38300/rpc/network_hashrate?window=120
```

## FAQ / Common issues
- No peers / stuck at height 0: check outbound TCP 38291, verify seeds in `bootstrap/seedlist.txt`, and restart the node. Some networks block inbound peers.
- Miner starts at height 0: let the node finish syncing and confirm RPC is reachable with `curl -k https://127.0.0.1:38300/status`.
- `[warn] Miner could not fetch block template ... InvalidContentType`: miner/node protocol mismatch. If node serves HTTP, set `IRIUM_NODE_RPC=http://127.0.0.1:38300`; if node serves HTTPS, keep `https://`. Verify with both `curl -s http://127.0.0.1:38300/status` and `curl -sk https://127.0.0.1:38300/status`, then restart miner.
- Miner stuck at height 1: the node isn’t running or `IRIUM_NODE_RPC` is wrong.
- `HTTP 401 Unauthorized`: the node has a token set, but the miner/wallet does not. Use the same `IRIUM_RPC_TOKEN` everywhere.
- `HTTP 429 Too Many Requests`: the node rate‑limit is blocking the miner. Set a token or raise `IRIUM_RATE_LIMIT_PER_MIN` in the node env.
- `unknown parent` / `orphan` during sync: normal while headers/blocks catch up; it clears once the node is fully synced.
- Miner ignores `/etc/irium/miner.env`: manual runs now auto‑load it. Shell exports still override the file.


## Termux / Mobile notes
- Expect slow builds and limited resources. Keep the session in the foreground or use `tmux`.
- Many mobile networks block inbound P2P; syncing can still work over outbound connections.
- If P2P is unreliable, point the miner at a public node with `IRIUM_NODE_RPC`.

This guide runs a Rust Irium node/miner on mainnet (no testnet, no DNS). Assumes Rust toolchain is installed (`source ~/.cargo/env`).

## 0) Download and build
```
git clone https://github.com/iriumlabs/irium.git
cd irium
source ~/.cargo/env
cargo build --release
```

## 1) Verify bootstrap artifacts
```
cd /home/irium/irium
# seeds + sig + trust root
ls bootstrap/seedlist.txt bootstrap/seedlist.txt.sig bootstrap/trust/allowed_signers
# anchors file is in bootstrap/anchors.json
```
The node verifies `seedlist.txt` against `allowed_signers` via `ssh-keygen -Y verify`.

## 2) Test (optional)
```
source ~/.cargo/env
cargo test --quiet
```

## 3) Configure (optional)
Create `configs/node.json` if you want to set P2P bind/seed or relay address:
```json
{
  "p2p_bind": "0.0.0.0:51001",
  "p2p_seeds": [],
  "relay_address": null
}
```
Set env var to use it:
```
export IRIUM_NODE_CONFIG=/home/irium/irium/configs/node.json
```

## 4) Run the node
```
source ~/.cargo/env
IRIUM_NODE_CONFIG=configs/node.json RUST_LOG=info ./target/release/iriumd
```
- Seeds: signed `bootstrap/seedlist.txt` + cached `bootstrap/seedlist.runtime` (unless `p2p_seeds` overrides).
- HTTP API: defaults to 127.0.0.1:38300 (`IRIUM_NODE_HOST`, `IRIUM_NODE_PORT`).
- P2P: bind from config; uses sybil-resistant handshake and header-first sync.

## 5) Create a wallet address
```
./target/release/irium-wallet init
./target/release/irium-wallet new-address
./target/release/irium-wallet list-addresses
./target/release/irium-wallet address-to-pkh <base58_address>
```
This creates `~/.irium/wallet.json` and prints the first address. Back up the wallet file.

## 6) Start mining
Set a payout address (or PKH) so rewards are spendable:
```
cd /home/irium/irium
export IRIUM_MINER_ADDRESS=<YOUR_IRIUM_ADDRESS>   # or set IRIUM_MINER_PKH (40-hex)
source ~/.cargo/env
./target/release/irium-miner
```
- Relies on the local node/mempool and auto-submits mined blocks to `IRIUM_NODE_RPC` (default https://127.0.0.1:38300; one-shot fallback to http if https fails).
- RPC auth tokens are user-defined. Example: `export IRIUM_RPC_TOKEN=$(openssl rand -hex 24)` and set the same value in `/etc/irium/iriumd.env` and `/etc/irium/miner.env`.
- Control CPU usage with `--threads N` or `IRIUM_MINER_THREADS=N` (default 1).
- If you run only the miner, point it at a reachable node RPC with `IRIUM_NODE_RPC=https://<node>:38300` (it will retry once over http if https fails) and set `IRIUM_RPC_TOKEN` if required.
- Uses `/rpc/getblocktemplate`; tune with `IRIUM_GBT_MAX_TXS`, `IRIUM_GBT_MIN_FEE`, `IRIUM_GBT_LONGPOLL`, `IRIUM_GBT_LONGPOLL_SECS`.
- Optional: set `IRIUM_RELAY_ADDRESS` to advertise a relay payout address in coinbase outputs.
- If the node is using HTTPS + `IRIUM_RPC_TOKEN`, set `IRIUM_NODE_RPC=https://127.0.0.1:38300` and export the same `IRIUM_RPC_TOKEN` for the miner.
- If `IRIUM_RPC_TOKEN` is present but empty in `/etc/irium/*.env`, miners will send an empty token and get 401; delete the line or set a real token.
- If you see `HTTP 429 Too Many Requests`, set `IRIUM_RPC_TOKEN` in both `iriumd` and the miner, or raise `IRIUM_RATE_LIMIT_PER_MIN` in the node env.
- For HTTPS with a local self-signed cert, set `IRIUM_RPC_CA=/etc/irium/tls/irium-ca.crt` instead of `IRIUM_RPC_INSECURE=1` (which only works for localhost).
- Set `IRIUM_MINER_STRICT_RPC=1` to stop mining if RPC/template fetch fails.
- The miner pauses if the node is behind peers (sync guard). Set `IRIUM_MINER_SYNC_GUARD=0` to disable, or `IRIUM_MINER_MAX_BEHIND=<n>` to allow a small lag.
- Pool mining (Stratum v1, TCP): set `IRIUM_STRATUM_URL`, `IRIUM_STRATUM_USER`, `IRIUM_STRATUM_PASS`.
- Solo ASIC mining: run `irium-miner --solo-stratum --listen 0.0.0.0:3333`; ASIC worker names should start with the payout address. See `docs/SOLO_STRATUM.md`.

## 7) Check balance
```
./target/release/irium-wallet balance <YOUR_IRIUM_ADDRESS>
./target/release/irium-wallet list-unspent <YOUR_IRIUM_ADDRESS>
./target/release/irium-wallet history <YOUR_IRIUM_ADDRESS>
./target/release/irium-wallet estimate-fee
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
Wallet RPC defaults to `IRIUM_NODE_RPC` (or legacy `IRIUM_RPC_URL`), otherwise https://127.0.0.1:38300. If HTTPS fails and the URL starts with `https://`, it retries once over `http://`.

## 8) SPV check
```
source ~/.cargo/env
cargo run --release --bin irium-spv -- verify <height> <txid> <index> <proof_hex_csv>
```

## 9) systemd (recommended)
Install systemd units so the node/miner survive reboots:
```
cd /home/irium/irium
./install.sh
```
- Edit `/etc/irium/iriumd.env` and `/etc/irium/miner.env` for your paths and wallet.
- Services run as the user who runs `./install.sh`. Override with `IRIUM_SERVICE_USER=<user> ./install.sh`.
- Optional API services: `/etc/irium/explorer.env` and `/etc/irium/wallet-api.env`.
- Enable the miner after setting `IRIUM_MINER_ADDRESS`:
```
sudo systemctl enable --now irium-miner.service
# optional APIs
sudo systemctl enable --now irium-explorer.service
sudo systemctl enable --now irium-wallet-api.service
```
Logs go to `journalctl -u iriumd`, `journalctl -u irium-miner`, `journalctl -u irium-explorer`, and `journalctl -u irium-wallet-api`.

## Resync / Clear Cache (Keep Blocks)

- To resync, delete ONLY `~/.irium/state` (keep `~/.irium/blocks` so you do not re-download blocks).

## Bootstrap/peer cache paths
- Signed seeds: `bootstrap/seedlist.txt` (+ .sig + trust/allowed_signers)
- Runtime peers: `bootstrap/seedlist.runtime`
- Anchors: `bootstrap/anchors.json` (anchor enforcement planned)
- Peer cache: `state/peers.json` (used when seeds are unavailable)
- Runtime state: `state/`
