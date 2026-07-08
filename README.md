# Irium (IRM)

**Settlement-first SHA-256d proof-of-work blockchain for trustless commerce.**

[![Release](https://img.shields.io/github/v/release/iriumlabs/irium?label=release&color=green)](https://github.com/iriumlabs/irium/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)
[![Mainnet](https://img.shields.io/badge/Mainnet-Live-brightgreen)](https://www.iriumlabs.org)

---

## The easiest way to run Irium

**Download the Irium Core desktop app:** [https://github.com/iriumlabs/irium-core/releases/latest](https://github.com/iriumlabs/irium-core/releases/latest)

Bundles `iriumd`, `irium-wallet`, and the CPU/GPU miners. Builds for Windows, macOS, and Linux. Handles wallet creation, marketplace, pool mining, settlement, and explorer in one window. No terminal required.

Use the command-line tooling below if you need a server install, automation, or want to build from source.

---

## Important — block 23,500 hard fork (Fix 2a)

The chain activates Bitcoin-standard block-header serialization at **block 23,500**. **Every node must run iriumd v1.9.28 or newer before block 23,500 is mined.** Older nodes will compute the wrong header hash for post-fork blocks and fork off from the canonical chain. Mainnet tip is currently ~22,500; activation is days away at the current cadence.

The desktop app's auto-update prompt will surface the same warning. Server / pool / ASIC operators should `git pull && cargo build --release` (or pull the v1.9.28 release binary) and restart `iriumd` before activation.

---

## What is Irium

Irium is a proof-of-work blockchain built for trustless escrow and proof-based commerce. Instead of smart contracts, it uses a deterministic settlement layer: buyer and seller lock funds on-chain, an attestor submits a cryptographic proof of delivery, and the chain enforces release or refund automatically. No lawyers, no chargebacks, no intermediaries.

SHA-256d consensus. No premine. No admin keys. 100,000,000 IRM total supply (96.5M from mining + 3.5M genesis CLTV vesting). Mainnet live since January 5, 2026.

---

## At a Glance

| Parameter | Value |
|-----------|-------|
| Current node version | `v1.9.49` (latest tag; v1.9.28 introduced settlement Groups C-H, FIX #128 P2P reputation hygiene, and FIX 2a hard-fork code; v1.9.29-v1.9.32 added GPU-miner and pool-Stratum fixes; later releases added BTC atomic swap activation, LWMA v2 rollout, V2 block-time fork, and the periodic mempool/offer rebroadcast timers) |
| Desktop app version | [`v1.0.77`](https://github.com/iriumlabs/irium-core/releases/latest) (bundles the latest v1.9.x sidecar binaries) |
| Consensus algorithm | SHA-256d proof of work |
| Block target interval | 120 s (2 min) — V2 block time, active since block 24,250 (V1 600 s target before the fork) |
| Difficulty adjustment | LWMA v2 (30-block window) — active since block 19,740 |
| Block reward | 50 IRM during the Early Miner Era; halves every 1,050,000 blocks |
| AuxPoW merged mining | Activates at block 26,500 (still pending; current tip ≈ 22,500) |
| Fix 2a hard fork (Bitcoin-standard header serialization) | Activates at block 23,500 — **all nodes must upgrade to v1.9.28 before this height** |
| Total supply cap | 100,000,000 IRM (96.5M mineable + 3.5M genesis CLTV vest) |
| Address prefix | Single-sig P2PKH uses version byte `0x39`; base58check encoding produces both `Q…` and `P…` leading characters depending on the underlying pubkey-hash — **both prefixes are the same single-sig address format**. A separate multisig version byte `0x28` is used for 2-of-N wallets. |
| Default P2P port | 38291 |
| Default RPC / explorer port | 38300 |
| `/status` lightweight port | 8080 (loopback only by default) |
| Official pool — CPU/GPU | `stratum+tcp://pool.iriumlabs.org:3335` |
| Official pool — ASIC | `stratum+tcp://pool.iriumlabs.org:3333` |
| Official pool — firewall bypass | `stratum+tcp://pool.iriumlabs.org:443` (sslh-multiplexed; for environments blocking high ports) |
| Official pool — solo | `stratum+tcp://pool.iriumlabs.org:3336` (full 50 IRM coinbase payout directly to the block finder; 0% pool fee) |
| Public pool stats proxy | `http://pool.iriumlabs.org:3337/stats` |

---

## Current State

| Feature | Status |
|---------|--------|
| Chain and mining | Live on mainnet |
| Settlement layer | Live |
| Marketplace | Live |
| Reputation system | Live |
| Proof ecosystem | Live |
| Merchant tools | Live |
| Rich list endpoint (`/rpc/richlist?limit=N`) | Live (since v1.9.17) |
| Self-advertised P2P external endpoint (CGNAT escape) | Live (shipped in v1.9.19+) |
| On-chain reputation event anchoring (`rep1:` prefix) | Live (shipped in v1.9.28 — Group H) |
| Escrow receipt export (signed) | Live (shipped in v1.9.28 — Group F) |
| Per-milestone fund + release wallet aliases | Live (shipped in v1.9.28 — Group G) |
| Per-template auto-policy at offer-take + 144-block dispute window | Live (shipped in v1.9.28 — Group E) |
| Auto-release watcher (`irium-wallet watch --auto-release`) | Live (shipped in v1.9.28 — Group C) |
| Proof schema registry (5 standard kinds, GROUP D) | Live (shipped in v1.9.28) |
| Reputation system — dial-fail vs handshake-fail distinction + env-tunable ban threshold | Live (shipped in v1.9.28 — FIX #128) |
| AuxPoW merged mining | Activating at block 26,500 (matches `MAINNET_AUXPOW_ACTIVATION_HEIGHT` in `src/activation.rs`) |
| WebSocket streaming API | Live |
| BIP32/BIP39 key derivation | Live |
| Multisig (2-of-2, 2-of-3) | Live |
| Confidential agreements | Live |
| BTC atomic swaps (SPV-verified, no custodian) | Live since block 23,850 |
| LTC / DOGE atomic swaps | Coming soon |
| Desktop / web / mobile wallet | Desktop wallet (`irium-core`) shipping; web / mobile in development |

---

## Quick Install

**Option 0 — Irium Core desktop app (recommended for most users)**

Download the latest installer for Windows, macOS, or Linux from
[https://github.com/iriumlabs/irium-core/releases/latest](https://github.com/iriumlabs/irium-core/releases/latest).
The app bundles the v1.9.49 sidecars, runs the node + wallet + miner in one
window, and ships pool client + marketplace + settlement Hub.

The CLI options below are for power users, server operators, and developers.

**Option 1 — Pre-built binary (Linux/macOS)**

```bash
curl -fsSL https://raw.githubusercontent.com/iriumlabs/irium/main/install.sh | bash
```

Installs `iriumd`, `irium-wallet`, `irium-miner`, and `irium-miner-gpu` to `/usr/local/bin`.

**Option 2 — Docker**

```bash
cp .env.example .env   # fill in your wallet address
docker-compose up -d
```

**Option 3 — Build from source**

```bash
git clone https://github.com/iriumlabs/irium.git && cd irium
cargo build --release
```

GPU miner:

```bash
cargo build --release --features gpu --bin irium-miner-gpu
```

---

## TypeScript SDK

Web developers can integrate Irium settlement into their apps using the official TypeScript SDK:

```bash
npm install irium-js
```

Full documentation and examples at [`sdk/irium-js/`](sdk/irium-js/). Covers agreement lifecycle, proof submission, offer feed, real-time WebSocket events, and chain queries.

---

## Run a Node

```bash
iriumd                              # start the node (syncs automatically)
curl http://127.0.0.1:38300/status  # confirm it is running
irium-wallet new-address            # generate your first address
irium-wallet list-addresses         # see your addresses
irium-wallet balance <YOUR_ADDRESS> # check balance once synced
```

The node connects to the Irium network automatically. On first run it uses the signed seed list bundled with the software. After the first connection it caches peer addresses locally and never needs the seed nodes again. No configuration needed for a basic setup. Default P2P port: 38291. Default RPC port: 38300.

### Mining options

| Profile | Command / pool |
|---------|----------------|
| Solo CPU | `irium-miner --address Q<your-address>` |
| Solo GPU | `irium-miner-gpu --address Q<your-address>` (build with `--features gpu`) |
| Pool — CPU/GPU | Point any Stratum v1 miner at `stratum+tcp://pool.iriumlabs.org:3335`, worker `Q<your-address>` |
| Pool — ASIC | Point any SHA-256 ASIC at `stratum+tcp://pool.iriumlabs.org:3333`, worker `Q<your-address>` |
| Pool — fallback (port 3333 blocked) | `stratum+tcp://pool.iriumlabs.org:443` — same Stratum protocol on HTTPS port to bypass ISP filtering (notably in China) |

Public pool stats live at [https://pool.iriumlabs.org/stats](https://pool.iriumlabs.org/stats) and at the raw proxy
`http://pool.iriumlabs.org:3337/stats` (CORS-enabled JSON with active miners, accepted shares, blocks found, current
share difficulty, and a rolling-window hashrate estimate per profile).

After block 23,500 activates Fix 2a, every SHA-256d miner (ASIC, GPU, CPU)
that submits valid work earns real block rewards directly to the IRM
address used as the Stratum worker name — the pool runs in SOLO payout
mode (no fee, no aggregation).

---

## Running a Public Node

If your node has a public IP address, you can help new users bootstrap by
advertising your address. Two complementary mechanisms exist:

**Coinbase peer-discovery embed** — your miner stamps the listen address
into every coinbase transaction so new nodes scanning the chain discover
you without DNS or a central seed server:

```bash
export IRIUM_ADVERTISE_ADDR=<your-public-ip>:38291
```

**P2P handshake external endpoint** — your node tells each peer the IP
they should record as your dialable address. This is the CGNAT escape
hatch: without it, peers infer your address from the TCP source IP, which
under carrier-grade NAT (RFC 6598, `100.64.0.0/10`) is the carrier's NAT
address rather than your real public IP. Set this when you know your real
external IPv4:

```bash
export IRIUM_EXTERNAL_ENDPOINT=<your-public-ip>:38291
```

iriumd validates the value (rejects RFC1918 private, RFC6598 CGNAT,
loopback, link-local, multicast, documentation, and IPv6) before
advertising it. Old peers without the field simply fall back to the
TCP-source-IP behavior, so this is fully backwards compatible.

To add your node as a seed for a running node without restarting:

```bash
curl -X POST http://localhost:38300/admin/add-seed \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"addr": "<your-public-ip>:38291"}'
```

### Environment variables (P2P networking)

| Variable | Purpose |
|----------|---------|
| `IRIUM_P2P_BIND` | Listen address/port for incoming P2P (default `0.0.0.0:38291`) |
| `IRIUM_EXTERNAL_ENDPOINT` | Self-advertised public `ip:port` carried in the handshake. **The CGNAT escape — set this when your TCP source IP is a carrier-NAT address.** Validated server-side: loopback, RFC1918, RFC6598 100.64/10, link-local, broadcast, multicast, documentation, and IPv6 are all rejected. |
| `IRIUM_NODE_PUBLIC_IP` | Self-IP filter used only by `local_ip_set()` so iriumd doesn't try to dial itself. Not advertised — set this if you operate multiple addresses behind the same node and want to avoid self-dial loops. |

### Behind CGNAT?

If your ISP gives you a 100.64.0.0/10 address rather than a real public IP,
peers that observe your TCP source IP record an unroutable address and gossip
it onwards. Symptoms: `0 inbound` peers indefinitely, even with port
forwarding configured on the local router.

Fixes, in order of impact:

1. Ask your ISP for a public IPv4 (many offer it free on request) — then set `IRIUM_EXTERNAL_ENDPOINT=<that-public-ip>:38291`.
2. Run a small relay on a VPS and forward port 38291 to your home node.
3. Accept outbound-only operation: iriumd still syncs and submits transactions, you just don't accept inbound connections.

The desktop wallet (`irium-core`) auto-detects your public IPv4 via an
external IP-echo service before launching iriumd, and only sets
`IRIUM_EXTERNAL_ENDPOINT` when the result validates as globally routable.
Manual CLI users on cloud servers should set the env var explicitly.

---

## Settle a Trade

The minimum commands for a complete buyer–seller trade:

```bash
# Seller: create an offer
irium-wallet offer-create \
  --seller <YOUR_ADDRESS> \
  --amount 1.0 \
  --description "Software licence delivery" \
  --policy-template software_delivery

# Buyer: list open offers and take one
irium-wallet offer-list --status open
irium-wallet offer-take --offer <OFFER_ID> --buyer <BUYER_ADDRESS>

# Attestor or seller: submit delivery proof
irium-wallet agreement-proof-submit --proof proof.json

# Check release eligibility (true after 6-block finality)
irium-wallet agreement-release-eligibility <AGREEMENT_HASH>
```

Full walkthrough: [QUICKSTART.md](QUICKSTART.md) | API reference: [docs/API.md](docs/API.md)

---

## Documentation

| Document | What it covers |
|----------|---------------|
| [QUICKSTART.md](QUICKSTART.md) | Zero-to-settlement walkthrough for new users |
| [docs/WHITEPAPER.md](docs/WHITEPAPER.md) | Full protocol specification — all 18 layers |
| [docs/WALLET-CLI.md](docs/WALLET-CLI.md) | Complete wallet command reference |
| [docs/API.md](docs/API.md) | REST API reference for all endpoints |
| [docs/WEBSOCKET.md](docs/WEBSOCKET.md) | WebSocket and SSE streaming event API |
| [docs/SETTLEMENT-DEV.md](docs/SETTLEMENT-DEV.md) | Settlement layer developer guide |
| [docs/SETTLEMENT-EXAMPLE.md](docs/SETTLEMENT-EXAMPLE.md) | Worked agreement examples |
| [docs/KEY-DERIVATION.md](docs/KEY-DERIVATION.md) | Custom and BIP32/BIP39 key derivation |
| [docs/MULTISIG.md](docs/MULTISIG.md) | 2-of-2 and 2-of-3 multisig guide |
| [docs/ATTESTOR-GUIDE.md](docs/ATTESTOR-GUIDE.md) | Attestor bonding and responsibilities |
| [docs/MERGED-MINING.md](docs/MERGED-MINING.md) | AuxPoW merged mining setup |
| [docs/POOL-OPERATOR.md](docs/POOL-OPERATOR.md) | Stratum pool operator guide |
| [docs/POOL_STRATUM.md](docs/POOL_STRATUM.md) | Pool mining for miners |
| [docs/DOCKER.md](docs/DOCKER.md) | Docker deployment guide |
| [docs/SEED-NODE.md](docs/SEED-NODE.md) | Running a public seed node |
| [docs/DEVELOPER-QUICKSTART.md](docs/DEVELOPER-QUICKSTART.md) | Dev environment setup |
| [docs/LISTING-APPLICATION.md](docs/LISTING-APPLICATION.md) | Exchange listing application template |

---

## Community

| | |
|-|--|
| Telegram | [t.me/iriumlabs](https://t.me/iriumlabs) |
| Bitcointalk | [ANN thread](https://bitcointalk.org/index.php?topic=5572239.0) |
| GitHub Issues | [github.com/iriumlabs/irium/issues](https://github.com/iriumlabs/irium/issues) |

---

## License

MIT
