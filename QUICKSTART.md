# Irium Quickstart

This guide takes you from zero to a completed settlement. No blockchain experience needed.

**What you need:** an internet connection and any modern computer (Windows, macOS, or Linux).

**What you will have at the end:** a synced node, a working Irium wallet with your own address, a miner producing IRM (optional), and a complete understanding of how to trade on the Irium marketplace.

---

## Step 0  Windows users: try the one-click .bat files first

If you are on Windows and just want to start mining without learning
any commands, the irium release archive contains two ready-to-run
shortcuts:

1. Download `irium-v<latest>-windows-x86_64.zip` from
   [github.com/iriumlabs/irium/releases/latest](https://github.com/iriumlabs/irium/releases/latest).
2. Extract the .zip.
3. Double-click **`mine-gpu.bat`** (recommended for any GPU) or
   **`mine-cpu.bat`** (requires a local iriumd; see below).
4. Paste your Irium wallet address when prompted. It is saved in
   `mine-config.txt` for next time.
5. Mining starts and auto-restarts if it crashes.

That is the entire setup for a casual GPU miner. Steps 1-9 below are
for operators who want a synced node, a wallet they control,
marketplace listings, and so on. The .bat files use the official
Irium pool in SOLO payout mode: when one of your shares meets the
network target the full block reward (currently 50 IRM) lands at
your wallet address with no pool fee. The Irium Core desktop app
described next does the same thing with a friendlier GUI and bundles
a wallet, sync indicator, and marketplace.

---

## Easiest path — Irium Core desktop app

**For most users, download the Irium Core desktop app from
[https://github.com/iriumlabs/irium-core/releases/latest](https://github.com/iriumlabs/irium-core/releases/latest).**
Pick the installer for your operating system (Windows `.exe`, macOS `.dmg`,
Linux `.AppImage` / `.deb`). The app bundles the latest v1.9.x iriumd
sidecar + wallet + CPU/GPU miners + pool client + marketplace +
settlement Hub. Launch it, follow the
on-screen prompts to create a wallet, and you are ready to receive IRM,
mine, and trade — no terminal required.

The desktop app handles Steps 1, 2, and 4 below automatically. Steps 3 and
5–9 still apply; the in-app **Terminal** tab can run any of the CLI commands
shown.

---

## Important — block 23,500 hard fork

The chain activates Bitcoin-standard block-header serialization at **block
23,500** (Fix 2a). **You must be on iriumd v1.9.28 or newer (latest tag is
v1.9.49; the latest Irium Core desktop app bundles it) before this block
is mined.** Older versions will fork off from the canonical chain. Check
the current tip against the activation height with
`curl http://127.0.0.1:38300/status | jq '.height'`; if your `height` is
already past 23,500 your node has already crossed the fork and is on the
correct chain.

---

## Two paths

You can use Irium in one of two ways. Pick whichever you prefer — they manage the same wallet and the same chain:

| | **Desktop app (recommended for most people)** | **Command line** |
|--|--|--|
| Best for | Day-to-day use, mining, marketplace browsing | Servers, automation, scripting |
| Where to get it | [Latest release](https://github.com/iriumlabs/irium-core/releases/latest) for Windows / macOS / Linux | `curl` install script below |
| Includes | Wallet UI · bundled node · bundled CPU + GPU miners · pool client · live explorer / pool stats | `iriumd`, `irium-wallet`, `irium-miner`, `irium-miner-gpu` |

If you choose the desktop app you can skip Step 1 and Step 2 below — the app handles installation and node startup automatically. The remaining steps still apply (the in-app terminal can run any of the CLI commands shown).

---

## Step 1 — Install (CLI path)

Run this command in your terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/iriumlabs/irium/main/install.sh | bash
```

This installs four programs into `/usr/local/bin`:

- `iriumd` — the full node (connects to the network and keeps it running)
- `irium-wallet` — the wallet and marketplace tool you will use for everything
- `irium-miner` — CPU miner (optional)
- `irium-miner-gpu` — GPU miner (optional)

**Confirm it worked:**

```bash
irium-wallet --version
```

If you see usage output, the install succeeded.

---

## Step 2 — Create a wallet

```bash
irium-wallet create-wallet --bip32
```

**What you will see:**

```
BIP32 wallet created
mnemonic: pass cycle ill pistol glad chapter normal nice shuffle inherit census beef wool solution page fossil rain theory prepare blood field frog hybrid print
derivation path: m/44'/1'/0'/0/0
IMPORTANT: write down your mnemonic -- it cannot be recovered
address: Pzt49NFBU9N15J4GuxNGitxdRtcHwyLGcj
wallet /home/yourname/.irium/wallet.json
```

**Write down your 24-word mnemonic right now.** This is the only backup of your wallet. Anyone who has these words can access your IRM. Store them offline — paper, not a screenshot.

The `--bip32` flag creates a standard hierarchical deterministic wallet. This is the recommended type because it is compatible with hardware wallets and future wallet apps.

Your wallet file is saved at `~/.irium/wallet.json`. Keep this file safe.

---

## Step 3 — Get your address

Generate a new IRM address to receive funds:

```bash
irium-wallet new-address
```

Then list all your addresses:

```bash
irium-wallet list-addresses
```

**What you will see:**

```
Pzt49NFBU9N15J4GuxNGitxdRtcHwyLGcj
Q2mADqCt3fHgvLZUMfdSn12JiKQ284qPEX
```

Your addresses start with `P` or `Q`. Both are valid IRM addresses — the first letter varies based on your specific key. Share any of these addresses to receive IRM.

---

## Step 4 — Check the network

Start the full node in a separate terminal window (leave it running):

```bash
iriumd
```

The node connects to the Irium network automatically. On first run it uses the
signed seed node list bundled with the software. After the first connection it
caches peer addresses locally and never needs the seed nodes again. Miners with
public IPs can set `IRIUM_ADVERTISE_ADDR=ip:port` to embed their address in the
blockchain so new nodes can discover them even without the seed nodes. Once it
starts syncing, check its status:

```bash
curl http://127.0.0.1:38300/status
```

You will see the current block height and peer count. The node is synced when `height` matches the network tip. Network status is also visible at [iriumlabs.org](https://www.iriumlabs.org).

Check your balance:

```bash
irium-wallet balance <YOUR_ADDRESS> --rpc http://127.0.0.1:38300
```

**What you will see:**

```
balance 0 IRM blocks mined 0
```

A new address always starts at zero. To receive IRM, share your address with the sender, mine some yourself (Step 5), or buy from a marketplace offer (Step 7).

---

## Step 5 — Mine some IRM (optional)

You can earn IRM by contributing computing power. There are three ways to mine — pick whichever fits your hardware:

### Option A — Solo CPU mining

Easiest to start. Uses your CPU and mines directly against your local node.

```bash
IRIUM_MINER_ADDRESS=<YOUR_ADDRESS> \
IRIUM_NODE_RPC=http://127.0.0.1:38300 \
  irium-miner
```

Replace `<YOUR_ADDRESS>` with one of your addresses from Step 3. Solo mining a block is rare on a busy network — most CPU miners switch to pool mining (Option C) for steadier rewards.

### Option B — Solo GPU mining

If you have a discrete graphics card (NVIDIA, AMD, or recent Intel Arc), the GPU miner is many times faster than the CPU:

```bash
irium-miner-gpu --wallet <YOUR_ADDRESS> --rpc http://127.0.0.1:38300
```

Auto-detection picks NVIDIA and AMD over integrated Intel iGPUs. To see all detected OpenCL platforms:

```bash
irium-miner-gpu --list-platforms
```

You can force a specific one with `--platform <vendor|index>`, e.g. `--platform nvidia` or `--platform 1`. Run multiple GPUs at once with `--devices 0,1,2`.

### Option C — Pool mining (recommended for steady rewards)

Pool mining splits the reward across many miners so you get small payments regularly instead of waiting for a rare solo block. Connect any Stratum v1 miner — including this repository's `irium-miner-gpu` — to the official public pool:

| Hardware | Pool endpoint |
|----------|--------------|
| CPU or GPU | `stratum+tcp://pool.iriumlabs.org:3335` |
| ASIC | `stratum+tcp://pool.iriumlabs.org:3333` |
| Behind ISP that blocks 3333/3335 (notably China) | `stratum+tcp://pool.iriumlabs.org:443` — same Stratum protocol on the HTTPS port to bypass filtering |
| Solo (full 50 IRM coinbase to block finder, 0% pool fee) | `stratum+tcp://pool.iriumlabs.org:3336` |

For the bundled GPU miner:

```bash
irium-miner-gpu \
  --pool stratum+tcp://pool.iriumlabs.org:3335 \
  --wallet <YOUR_ADDRESS>
```

Your `<YOUR_ADDRESS>` is also your worker name — the pool credits payouts directly to it. Live pool stats (active miners, blocks found, rolling-window hashrate per profile) are available at `http://pool.iriumlabs.org:3337/stats` and are surfaced in the desktop app's Explorer tab.

---

## Step 6 — Browse the marketplace

Sync the offer feed to discover what is available:

```bash
irium-wallet offer-feed-sync --rpc http://127.0.0.1:38300
```

**What you will see:**

```
source   http://207.244.247.86:38300/offers/feed
total    13
imported 0
skipped  13 (already in local store)
```

Then list open offers:

```bash
irium-wallet offer-list --status open
```

**What you will see:**

```
Total: 2 offers

[1] aggr-test-001
    amount:   750000000 IRM
    seller:   Q9KxBRfrnb6v9Vb8vuHjwkZaxj3ZRhJWpg
    payment:  bank_transfer
    source:   remote:http://207.244.247.86:38300/offers/feed
    status:   open
    reputation: 11 agreements

[2] offer-1777297990
    amount:   1 IRM
    seller:   Q9KxBRfrnb6v9Vb8vuHjwkZaxj3ZRhJWpg
    payment:  rpc-check
    status:   open
    reputation: 11 agreements
```

Each offer shows the seller address, amount, payment method, and their reputation based on completed agreements.

---

## Step 7 — Create an offer (seller path)

If you have IRM to sell, create a sell offer:

```bash
irium-wallet offer-create \
  --seller <YOUR_ADDRESS> \
  --amount 0.5 \
  --payment-method "bank_transfer" \
  --timeout 21000 \
  --price-note "Software licence — delivered as download link"
```

Replace `<YOUR_ADDRESS>` with one of your addresses from Step 3. The `--timeout` is the block height deadline (current height plus blocks to wait; ~2 minutes per block at the V2 block-time target, active since block 24,250).

**What you will see:**

```
offer_id         offer-1777888495
status           open
seller           Pzt49NFBU9N15J4GuxNGitxdRtcHwyLGcj
amount_irm       0.50000000 IRM
payment_method   bank_transfer
timeout_height   21000

saved_path      /home/yourname/.irium/offers/offer-offer-1777888495.json

next_step  export and share offer: irium-wallet offer-export --offer offer-1777888495 --out offer.json
```

Export and share the offer file with your buyer:

```bash
irium-wallet offer-export --offer offer-1777888495 --out offer.json
```

Send `offer.json` to the buyer through any channel (email, Telegram, etc.). The buyer imports it with:

```bash
irium-wallet offer-import --file offer.json
```

---

## Step 8 — Take an offer (buyer path)

When you have found an offer to accept, take it with your buyer address:

```bash
irium-wallet offer-take \
  --offer <OFFER_ID> \
  --buyer <YOUR_ADDRESS> \
  --rpc http://127.0.0.1:38300
```

**What you will see:**

```
=== Offer Taken ===

offer_id        offer-1777888495
agreement_id    offer-offer-1777888495-1777888517
agreement_hash  96dfc2a96630e6d6f9b49b404c69ad19bc4f8175055aeb33f098dd681be11f2e
seller          Pzt49NFBU9N15J4GuxNGitxdRtcHwyLGcj
buyer           Q2mADqCt3fHgvLZUMfdSn12JiKQ284qPEX
amount_irm      0.50000000 IRM

=== Next steps ===
1. Export this agreement for seller:
   irium-wallet agreement-pack --agreement 96dfc2a... --out agreement-pkg.json
2. Make external payment via bank_transfer
3. Seller confirms delivery and submits proof
```

The `agreement_hash` is your unique trade identifier. Keep it.

Package the agreement and share it with the seller:

```bash
irium-wallet agreement-pack \
  --agreement <AGREEMENT_HASH> \
  --out agreement-pkg.json \
  --rpc http://127.0.0.1:38300
```

The seller unpacks it on their side:

```bash
irium-wallet agreement-unpack --file agreement-pkg.json
```

The buyer then sends the agreed IRM amount to fund the escrow:

```bash
irium-wallet agreement-fund <AGREEMENT_HASH> --rpc http://127.0.0.1:38300
```

This locks the IRM on-chain. Neither party can access it until the agreement resolves.

---

## Step 9 — Submit proof and release

Once off-chain delivery or payment is complete, the seller submits an attestation:

```bash
irium-wallet otc-attest \
  --agreement <AGREEMENT_HASH> \
  --message "payment confirmed via bank transfer" \
  --address <SELLER_ADDRESS> \
  --rpc http://127.0.0.1:38300
```

**What you will see:**

```
proof_id prf-3c98200364ac8efc
agreement_hash 96dfc2a96630e6d6f9b49b404c69ad19bc4f8175055aeb33f098dd681be11f2e
accepted true
message proof accepted
tip_height 20489
status active
```

Check the full agreement status at any time:

```bash
irium-wallet otc-status \
  --agreement <AGREEMENT_HASH> \
  --rpc http://127.0.0.1:38300
```

Once the proof is buried 6 blocks deep (about 1 hour), the agreement becomes release-eligible. The seller releases the escrowed IRM to complete the settlement:

```bash
irium-wallet agreement-release <AGREEMENT_HASH> \
  --broadcast \
  --rpc http://127.0.0.1:38300
```

The IRM moves from escrow to the seller's address on-chain, automatically and without any third party.

---

## What's next

| Resource | What it covers |
|----------|---------------|
| [docs/WALLET-CLI.md](docs/WALLET-CLI.md) | Every wallet command with flags and examples |
| [docs/SETTLEMENT-DEV.md](docs/SETTLEMENT-DEV.md) | Agreement types, policy templates, proof formats |
| [docs/API.md](docs/API.md) | REST API for building apps on Irium |
| [docs/WEBSOCKET.md](docs/WEBSOCKET.md) | Real-time event streaming for UIs |
| [docs/WHITEPAPER.md](docs/WHITEPAPER.md) | Full protocol specification |
| [Telegram](https://t.me/iriumlabs) | Community — ask questions, find counterparties |
