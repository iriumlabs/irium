# Irium Mainnet

Irium is an original proof-of-work blockchain engineered specifically for the IRM asset. The network targets mainnet readiness only—no testnet or demo deployments are packaged in this repository. Every component was designed and implemented for Irium to support DNS-free bootstrapping, self-healing peer discovery, and enforceable genesis vesting without forking existing chains.

## Table of Contents
- [Network Specifications](#network-specifications)
- [Repository Layout](#repository-layout)
- [Getting Started](#getting-started)
- [Bootstrapping Without DNS](#bootstrapping-without-dns)
- [Automatic Peer Persistence](#automatic-peer-persistence)
- [Genesis Configuration](#genesis-configuration)
- [Consensus & Monetary Policy](#consensus--monetary-policy)
- [P2P & Security Enhancements](#p2p--security-enhancements)
- [Light Client Support](#light-client-support)
- [Wallet Integration](#wallet-integration)
- [Mining Toolkit](#mining-toolkit)
- [Development Roadmap](#development-roadmap)
- [Licensing](#licensing)

## Network Specifications

| Parameter | Value |
|-----------|-------|
| Ticker | IRM |
| Consensus | Proof-of-Work (SHA-256d) |
| Block Target | 600 seconds |
| Block Subsidy | 50 IRM |
| Halving Interval | 210,000 blocks |
| Coinbase Maturity | 100 blocks |
| Difficulty Retarget | 2016 blocks |
| Maximum Supply | 100,000,000 IRM |
| Founder Vesting | 3,500,000 IRM CLTV split across 1y/2y/3y UTXOs |
| Public Distribution | 96,500,000 IRM mined over halving schedule |

## Repository Layout

```
irium/                  # Reference Python primitives for blocks, PoW, transactions, and chain state
  network.py            # Auto-updating peer directory and runtime seedlist management
  wallet.py             # Deterministic key management and transaction builder
configs/genesis.json    # Canonical genesis coinbase layout with CLTV vesting commitments
bootstrap/              # Signed seedlist & rolling anchors for DNS-free initialization
  seedlist.runtime      # Node-maintained seed cache refreshed on each inbound connection
scripts/                # Helper scripts (zero-DNS launcher, deterministic genesis builder)
docs/architecture.md    # Protocol high-level architecture
docs/whitepaper.md      # Formal whitepaper capturing protocol rationale and economics
state/                  # Runtime data (peer book, wallet metadata) produced by mainnet nodes
LICENSE                 # Project license
```

No test or demo files are shipped alongside the mainnet resources, ensuring the repository mirrors the production deployment surface.

## Getting Started

1. Install Python 3.11 or later.
2. Clone this repository.
3. Review `docs/whitepaper.md` for a deep dive into protocol goals and implementation notes.
4. Build the genesis artifacts using `python scripts/create_genesis.py` if you need to regenerate the canonical block header.
5. Launch the zero-DNS bootstrap helper as described below to obtain seed peers and anchor checkpoints.

## Bootstrapping Without DNS

Run the provided script to fetch and validate bootstrap artifacts:

```bash
./scripts/irium-zero.sh
```

The helper script performs the following steps:
1. Downloads or reads bundled `seedlist.txt` and `anchors.json` artifacts.
2. Verifies detached secp256k1 signatures using the bundled founder/guardian public keys.
3. Exports multiaddresses for libp2p-compatible dialing.
4. Emits the latest anchor checkpoints that new nodes should validate when syncing headers.

This workflow eliminates DNS dependencies entirely. Mirrors can be distributed via GitHub Releases, IPFS, or torrent bundles to ensure long-term availability.

## Automatic Peer Persistence

Nodes call into `irium.network.PeerDirectory` whenever a new libp2p peer completes its handshake. The peer directory persists metadata to `state/peers.json` and simultaneously refreshes `bootstrap/seedlist.runtime` with the observed multiaddress. This runtime seed cache complements the signed release seedlist without mutating its detached signature, ensuring fresh peers are always available—even if the founding mirrors disappear.

Any tooling consuming the seed material should read both `seedlist.txt` and `seedlist.runtime` (the helper already merges them) to take advantage of the automatically collected peers.

## Genesis Configuration

`configs/genesis.json` encodes the deterministic genesis distribution:
- Three separate CLTV-bound UTXOs lock the founder’s 3,500,000 IRM across 1y, 2y, and 3y absolute block heights.
- No other parties receive genesis funds; 96,500,000 IRM remain unminted so miners can earn them through proof-of-work.
- The `scripts/create_genesis.py` utility constructs the genesis block header, transaction merkle root, and subsidy schedule directly from this configuration.

## Consensus & Monetary Policy

Irium fixes the entire 100 million IRM supply while reserving 96.5 million IRM for proof-of-work mining:
- Blocks target a 600-second interval with SHA-256d proof-of-work and retarget every 2016 blocks.
- Initial block subsidy is 50 IRM with halvings every 210,000 blocks; long-term issuance asymptotically trends to zero.
- Genesis mints exactly 3,500,000 IRM into three CLTV UTXOs (1y/2y/3y); the remaining 96,500,000 IRM are available to miners with no pre-allocation.
- Coinbase outputs mature after 100 confirmations to deter short-term reorg incentives.
- `ChainState` enforces value conservation by verifying that every coinbase transaction is limited to the permitted subsidy plus collected fees, so miners cannot inflate supply or create negative fee situations.

The reference Python modules under `irium/` implement block serialization, PoW validation, difficulty computation, and deterministic chain state transitions without relying on external blockchain libraries. `ChainState` now enforces header continuity, merkle root integrity, proof-of-work targets, and coinbase reward limits while maintaining the UTXO set for transaction validation.

## P2P & Security Enhancements

Key networking innovations include:
- **Zero-DNS Bootstrap:** Nodes trust only signed seed/anchor artifacts, never DNS seeds.
- **Self-Healing Peer Discovery:** libp2p gossip tracks uptime proofs to keep a rolling catalog of reachable peers.
- **Sybil-Hard Handshakes:** Ephemeral keys prove uptime via lightweight PoW/time-bound tokens to mitigate botnet flooding.
- **Anchor-File Consensus:** Signed `anchors.json` files provide rolling checkpoints that harden clients against eclipse attacks.
- **On-Chain Metadata Commitments:** Miners can commit hash pointers to off-chain resources in coinbase transactions without bloating the chain.
- **Hard Supply Guardrails:** Full nodes now reject malformed transactions or coinbases that attempt to overflow output values or exceed the fixed 100 million IRM supply cap.

## Light Client Support

Irium ships with SPV-ready primitives from day one. The `irium` Python package exposes header validation and proof verification utilities that light wallets can leverage alongside anchor checkpoints to validate transactions without a full node.

## Wallet Integration

The reference `irium.wallet.Wallet` class turns the cryptographic primitives into a usable hot wallet:

- Import existing keys via WIF (including the founder key) or generate new compressed/uncompressed key pairs.
- Maintain a catalog of wallet-controlled UTXOs and query balances in satoshis.
- Build and sign P2PKH transactions using deterministic RFC6979 ECDSA, automatically selecting change outputs and refreshing wallet state.

Example usage:

```python
from irium.wallet import Wallet

wallet = Wallet()
# Import a founder or user WIF via environment variable instead of hard-coding
import os
founder_wif = os.environ.get("FOUNDER_WIF")
if founder_wif:
    founder_address = wallet.import_wif(founder_wif)
```

Wallet metadata can be stored alongside the peer directory under `state/` (the repository only tracks an empty placeholder to reserve the path, keeping private keys out of version control).

## Mining Toolkit

`irium.miner` ships a reference miner that assembles block templates, encodes relay reward commitments, and iterates nonces without depending on external blockchain stacks.

- `Miner` takes a `ChainState`, payout address, and optional `Wallet`. It selects the highest fee-rate transactions from provided `TxCandidate` objects, constructs the coinbase, and cycles the extra nonce when the 32-bit nonce space is exhausted.
- `RelayCommitment` lets miners dedicate a portion of collected fees to the peers that relayed transactions. Each commitment adds a standard P2PKH output, plus an optional `OP_RETURN` memo for auditable fee-sharing records.
- `MiningStats` surfaces runtime metrics (height, total fees, attempts, elapsed time) for monitoring dashboards.
- When a wallet instance is supplied, solved coinbase payouts are registered automatically for balance tracking (respect the 100-block coinbase maturity before spending).

Example usage:

```python
from irium import ChainParams, ChainState, Miner, TxCandidate
from irium.pow import Target

# `genesis_block` and `pow_limit` come from configs/genesis.json and network parameters
params = ChainParams(genesis_block=genesis_block, pow_limit=Target(0x1d00ffff))
chain = ChainState(params=params)

# `tx` is a Transaction prepared elsewhere (for example by irium.wallet)
miner = Miner(chain_state=chain, payout_address="IRmExamplePayoutAddr...")
block, stats = miner.mine_block([
    TxCandidate(transaction=tx, fee=1500, weight=tx.weight())
], max_attempts=100_000)

if block:
    print("Solved block in", stats.attempts, "attempts")
    chain.connect_block(block)
else:
    print("No solution within attempt budget; retry with new timestamp/extra nonce")
```

Because mainnet difficulty is high, real deployments distribute the work across dedicated mining hardware while still relying on the shared block assembly logic for deterministic coinbase construction and relay reward accounting.

## Development Roadmap

Upcoming focus areas include:
- Implementing the libp2p gossip layer with relay incentive accounting.
- Finalizing production key material for bootstrap artifact signing.
- Extending the Python primitives into a full node daemon and graphical SPV wallet.
- Conducting third-party audits of the genesis configuration and bootstrap tooling.

## Licensing

The project is distributed under the terms of the MIT License. See [LICENSE](LICENSE) for the full text.

