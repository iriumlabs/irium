# Run your own Irium producer

Irium is a **hardware-neutral** proof-of-work chain. Since the PoW-demotion activation, blocks are produced at a
CPU-reachable floor difficulty — **you do not need an ASIC or a GPU**. A commodity CPU can produce blocks once your
key is eligible, and **becoming eligible needs no one's permission**: you build the node from this repository,
sync, register your key, and start producing. No operator approves you, and by consensus no producer can withhold
your registration.

This guide takes you from a clean machine to a live independent producer.

---

## What you're joining

- **Reward:** the full 50 IRM per block, paid to the block's VRF-selected proposer. From block
  66,400 there is no role split — if you are selected, you receive the entire reward.
- **Hardware-neutral selection:** the proposer is drawn by VRF sortition and an eligible proposer's
  block is checked against a constant floor, so a CPU, a GPU and an ASIC all have the same random
  chance. Extra hashrate does not improve your odds.
- **Permissionless:** proposer registration requires no allowlist, no account, no approval. A small proof-of-work
  (anti-sybil) is the only cost.
- **Censorship-resistant by consensus:** the registration queue is *force-drained* in first-in-first-out order as
  a validity rule — a block that skips, reorders, or drops a queued registration is rejected by every node. No
  producer, however large, can gatekeep who joins.
- **Fair distribution is gossip-sourced:** producers discover each other's role contributions over permissionless
  peer-to-peer gossip (no central server, no registry host). The mechanism is identical whether the network has 2
  producers or 200.

## Requirements

- A 64-bit Linux machine (a modern multi-core CPU is plenty).
- A recent Rust toolchain (`rustup`, stable).
- An always-on internet connection with an outbound path to the network (inbound reachability helps but isn't
  required to sync and produce).

---

## Step 1 — Build from source

Build the exact consensus the network runs. Always build from the published source, not a copy — a node built from
different rules forks off instantly.

```bash
git clone https://github.com/iriumlabs/irium
cd irium
git checkout main          # or the release tag announced for the current consensus
cargo build --release --bin iriumd --bin irium-miner
# optional, to contribute compute/verify/support role bundles to fair distribution:
# cargo build --release --bin poawx-role-worker
```

You now have `./target/release/iriumd` (the full node) and `./target/release/irium-miner` (the producer).

## Step 2 — Run a full node and sync

From the repository root:

```bash
./target/release/iriumd
```

The node reads its peer seeds from `configs/node.json` and the signed seed list in `bootstrap/`, connects to the
network, and syncs. By default it stores data under `~/.irium` and serves a local RPC on `127.0.0.1:38300`; its
peer-to-peer port is `38291`.

- **No token needed.** The RPC requires a bearer token only if you set `IRIUM_RPC_TOKEN`. Leave it unset and your
  own miner talks to your own node over loopback freely.
- Wait until your node's height matches the network before producing. You can watch it:

```bash
curl -s http://127.0.0.1:38300/status | grep -o '"height":[0-9]*'
```

A fresh node performs a header-first sync and pulls the full demoted chain — this is expected to work for any new
node, including yours.

## Step 3 — Create your key and register (automatic, no approval)

Your producer identity is a single 32-byte secret. The miner derives your VRF proposer key **and** your payout
address from it. Generate one and keep it private (never commit it, never share it):

```bash
openssl rand -hex 32 > ~/.irium/producer.secret
chmod 600 ~/.irium/producer.secret
```

You do **not** submit a registration by hand. When you run the miner (Step 4) it automatically:
1. builds a signed proposer registration (with the required anti-sybil proof-of-work and a recent chain anchor),
2. posts it to your own node over loopback, which **gossips it to the network**,
3. and the next block producer is **required by consensus** to include it — in order, without the ability to skip
   or withhold it.

After the registration is included and `FREEZE_DEPTH` (16) blocks pass, your key is eligible. There is no operator
in this loop: inclusion is a consensus rule, not a decision anyone makes about you.

## Step 4 — Produce blocks

Run the miner in PoAW-X mode with your secret:

```bash
export IRIUM_POAWX_MINER_SECRET_HEX="$(cat ~/.irium/producer.secret)"
export IRIUM_NODE_RPC="http://127.0.0.1:38300"
./target/release/irium-miner --poawx --threads 1
```

Once eligible, you win roughly `1/n` of blocks (for `n` eligible producers) by fair VRF sortition, and produce
demoted blocks that a commodity CPU can solve. Raise `--threads` to use more cores.

## Step 5 — (optional) Contribute to and receive fair distribution

Fair distribution pays the Compute/Verify/Support roles to *distinct* participants. Participation is opt-in and
permissionless — no central collector is involved. Set:

```bash
export IRIUM_POAWX_FANOUT_INCLUSIVE=1
```

With this on, when you build a block your miner gathers other eligible participants' role contributions from your
node's **peer-to-peer gossip cache** and folds them in; when others build blocks, they can include yours the same
way. The selection is identity-free — no hardcoded keys or hosts. (Enforcement of distinct-payee fair distribution
is activated network-wide by consensus; until then the fan-out is advisory.)

---

## You're a live independent producer when…

Your key's address appears as the proposer of accepted blocks on the network, distinct from any other producer.
The strongest proof of your independence: the chain keeps advancing on *your* blocks even when other producers are
offline.

## Why this isn't a gated system

- **No auth on registration** — your registration is self-signed and self-valid; there is no allowlist or account.
- **Inclusion is a consensus rule** — the force-drained FIFO registration queue means no producer can refuse yours.
- **Fair-distribution transport is gossip** — discovery is peer-to-peer and identity-free; there is no central
  server that could exclude you.
- **Eligibility is fair** — once registered, proposer selection is uniform VRF sortition; no one can crowd you out.

## Troubleshooting

- **Node won't sync / no peers:** confirm outbound connectivity and that you built from the current `main`/tag.
- **`plain-PoW blocks are rejected`:** you must run with `--poawx` and `IRIUM_POAWX_MINER_SECRET_HEX` set — PoAW-X
  is active, plain proof-of-work is not accepted.
- **Not winning blocks yet:** confirm your key is eligible (registered and past the 16-block freeze) and your node
  is at the network tip.
- **Identify your binary by commit/sha**, not `--version` — the version string may lag the actual build.
