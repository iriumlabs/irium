# Irium: DNS-Free Proof-of-Work Mainnet

**Technical Whitepaper - Version 1.0**

**Network Status:** LIVE on Mainnet
**Genesis Hash:** 0000000028f25d65557e9d8d9e991f516c00d68f5aeae10b750645b398bd10a3
**Launch Date:** January 5, 2026

---

## Abstract

Irium is a purpose-built proof-of-work blockchain designed to maximize network independence and long-term survivability. The protocol eliminates reliance on DNS infrastructure, enforces transparent founder vesting via on-chain timelocks, incentivizes transaction relay quality without inflation, and prioritizes light client usability from genesis. This whitepaper outlines the core design principles, system architecture, monetary policy, and implementation status of the IRM asset and its supporting network.

**Current Implementation:** Production mainnet is LIVE; core innovations are operational, with NiPoPoW proofs implemented.

---

## 1. Introduction

Most established proof-of-work networks inherit architectural assumptions from Bitcoin, including DNS-based bootstrapping, addrman-driven peer discovery, and an absence of protocol-level incentives for fast relay. Irium rethinks these components to produce a mainnet that can launch and sustain itself even if all founding infrastructure disappears.

**Irium launched on January 5, 2026 with:**
- Mined genesis block at Bitcoin-standard difficulty (0x1d00ffff)
- Zero DNS dependencies
- Complete P2P networking
- All services operational

### 1.1 Goals

1. **Permanent bootstrap viability** without DNS dependencies or trusted third-party domains
2. **Transparent founder vesting** with consensus-enforced, irreversible timelocks
3. **Incentivized relay network** with optional fee-sharing rewards for propagation quality
4. **Sybil-resistant peer discovery** hardened against botnet saturation
5. **Mobile-first architecture** with NiPoPoW-ready light clients from block 1
6. **On-chain notarization** layer for off-chain metadata commitments

**Status:** 6/6 implemented.

### 1.2 Technical Specifications

| Parameter | Value |
|-----------|-------|
| Ticker | IRM |
| Algorithm | SHA-256d (Bitcoin-compatible) |
| Max Supply | 100,000,000 IRM |
| Genesis Vesting | 3,500,000 IRM (3.5%) |
| Mineable Supply | 96,500,000 IRM (96.5%) |
| Block Time | 600 seconds (10 minutes) |
| Initial Reward | 50 IRM |
| Halving Interval | 210,000 blocks (~4 years) |
| Difficulty Retarget | 2016 blocks (~14 days) |
| Coinbase Maturity | 100 blocks |
| Min Transaction Fee | 0.0001 IRM (10,000 satoshis) |
| P2P Port | 38291 |

---

## 2. System Architecture

Irium separates responsibilities into modular subsystems:

### 2.1 Core Modules (src/)

- **block.rs** - Block and BlockHeader structures
- **chain.rs** - ChainState, consensus validation, chain state
- **tx.rs** - Transaction, TxInput, TxOutput structures
- **wallet.rs** - Address helpers, signing utilities
- **pow.rs** - SHA-256d hashing, target difficulty
- **network.rs** - Peer directory, seedlist management
- **protocol.rs** - P2P binary message protocol
- **p2p.rs** - P2P node with peer management and header-first sync
- **mempool.rs** - Transaction pool with fee prioritization
- **reputation.rs** - Peer scoring and ban tracking
- **sybil.rs** - Sybil-resistant handshake protocol
- **relay.rs** - Relay reward calculation and tracking
- **anchors.rs** - Checkpoint verification, eclipse protection
- **spv.rs** - Header chain + merkle proof verification

### 2.2 Binaries

- **iriumd** - Full node with HTTP API and P2P networking
- **irium-miner** - PoW miner with block broadcasting
- **irium-wallet** - Wallet CLI (address creation, balance queries)
- **irium-spv** - SPV proof verification tool
- **irium-p2p** - P2P-only diagnostic node

---



## 3. Consensus Mechanics

### 3.1 Proof-of-Work (SHA-256d)

Irium uses double SHA-256 hashing, identical to Bitcoin:

```
block_hash = SHA256(SHA256(header))
valid_block = block_hash < target
```

**Benefits:**
- 16+ years of battle-testing
- Compatible with Bitcoin mining hardware (ASICs, GPUs)
- Well-understood security properties
- Existing mining infrastructure

**Genesis Block:**
- Nonce: 1,842,179,559
- Hash: 0000000028f25d65557e9d8d9e991f516c00d68f5aeae10b750645b398bd10a3 (valid mainnet PoW)
- Mined: January 5, 2026

### 3.2 Difficulty Adjustment

**Target:** 600 seconds per block (10 minutes)
**Retarget Interval:** Every 2016 blocks (~14 days)

**Algorithm:**
```text
expected_time = 2016 * 600  # 1,209,600 seconds
actual_time = last_block_time - first_block_time
new_difficulty = old_difficulty * (actual_time / expected_time)
```

Adjustments are clamped to prevent manipulation.

### 3.3 Block Validation

Each block must satisfy:
1. `block_hash < target` (proof-of-work)
2. Merkle root matches transaction tree
3. Timestamp within consensus range
4. All transactions valid (no double-spends)
5. Coinbase reward ≤ subsidy + fees
6. Block connects to valid chain tip

**Implementation:** src/chain.rs (block header validation)

---

## 4. Economic Model

### 4.1 Supply Distribution

**Total Supply:** 100,000,000 IRM (hard cap)

**Genesis Vesting (3.5%):** 3,500,000 IRM
- 1,000,000 IRM unlocks at block 52,560 (~1 year)
- 1,250,000 IRM unlocks at block 105,120 (~2 years)
- 1,250,000 IRM unlocks at block 157,680 (~3 years)

**Mineable Supply (96.5%):** 96,500,000 IRM
- Distributed via block rewards
- Halves every 210,000 blocks
- Fair distribution through mining

### 4.2 Block Rewards Schedule

| Block Range | Reward | Blocks | Total IRM |
|-------------|--------|--------|-----------|
| 1 - 210,000 | 50 IRM | 210,000 | 10,500,000 |
| 210,001 - 420,000 | 25 IRM | 210,000 | 5,250,000 |
| 420,001 - 630,000 | 12.5 IRM | 210,000 | 2,625,000 |
| 630,001 - 840,000 | 6.25 IRM | 210,000 | 1,312,500 |
| ... | Continues halving | ... | ... |

**Total mineable:** 96,500,000 IRM over ~80 years

### 4.3 Transaction Fees

**Minimum Fee:** 0.0001 IRM (10,000 satoshis)

**Fee Distribution:**
- 90% to block miner
- 10% to relay nodes (up to 3 relays)
  - First relay: 50% of relay pool
  - Second relay: 30% of relay pool
  - Third relay: 20% of relay pool

**Comparison:**
- Bitcoin: ~0.001 BTC (~$30-50 USD)
- Irium: 0.0001 IRM (fraction of a cent)

Ultra-low fees enable micropayments and frequent transactions.

---

## 5. The 8 Core Innovations

### 5.1 Zero-DNS Bootstrap

**Problem:** DNS is centralized, censorable, and a single point of failure.

**Irium Solution:**
- Signed `seedlist.txt` with raw IP multiaddrs (IPv4 + IPv6)
- Signed `anchors.json` with checkpoint block headers
- Bootstrap script: `scripts/irium-zero.sh` (no DNS queries)
- Distributed via GitHub, IPFS, torrents
- Signature verification via SSH signatures (sshsig), validated with `ssh-keygen -Y verify` and `bootstrap/trust/allowed_signers`

**Status:** ✅ Implemented and operational

**Files:**
- `bootstrap/seedlist.txt` - Seed node IPs
- `bootstrap/anchors.json` - Chain checkpoints
- `scripts/irium-zero.sh` - Bootstrap script

### 5.2 Self-Healing Peer Discovery

**Problem:** Networks need stable, honest peers; centralized trackers create vulnerabilities.

**Irium Solution:**
- Uptime proof system (HMAC challenges)
- Peer reputation scoring (0-1000 scale)
- Automatic peer promotion/demotion
- Network 'remembers' reliable peers
- `seedlist.runtime` updated automatically

**Status:** ✅ Implemented (src/reputation.rs, src/network.rs, src/p2p.rs)

**Implementation Notes:**
- P2P message types: `UptimeChallenge`, `UptimeProof`
- Capability: `uptime_hmac_v1`
- HMAC key derived from node ID pair; timestamp window defaults to 5 minutes


**Reputation Factors:**
- Successful connections: +2 points each
- Failed connections: -5 points each
- Valid blocks shared: +10 points each
- Invalid blocks: -50 points each
- Uptime proofs: +5 points each

**Thresholds:**
- Trusted peer: Score > 80
- Banned peer: Score < 20

### 5.3 Genesis Vesting with On-chain CLTV

**Problem:** Founder allocations often lack transparency or enforcement.

**Irium Solution:**
- 3.5M IRM locked in genesis block
- 3 separate UTXOs with OP_CHECKLOCKTIMEVERIFY
- Unlock heights: 52,560 / 105,120 / 157,680 blocks
- Consensus-enforced (cannot be spent early)
- Fully transparent in genesis.json
- Irreversible timelock

**Status:** ✅ Implemented in genesis block

**Genesis Allocations:**
```json
{
  "founder_vesting_1y": 1000000 IRM (52560 blocks)
  "founder_vesting_2y": 1250000 IRM (105120 blocks)
  "founder_vesting_3y": 1250000 IRM (157680 blocks)
}
```

### 5.4 Per-Transaction Relay Rewards

**Problem:** No incentive to run relay nodes; slow transaction propagation.

**Irium Solution:**
- Relay nodes earn 10% of transaction fees
- Up to 3 relays per transaction
- Distribution: 50%, 30%, 20%
- Included in coinbase transaction
- No supply inflation (comes from tx fees)

**Status:** ✅ Implemented (src/relay.rs)

**Example:**
- Transaction fee: 0.001 IRM
- Relay pool: 0.0001 IRM (10%)
- First relay earns: 0.00005 IRM (50%)
- Second relay earns: 0.00003 IRM (30%)
- Third relay earns: 0.00002 IRM (20%)
- Miner earns: 0.0009 IRM (90%)

### 5.5 Sybil-Resistant P2P Handshake

**Problem:** Botnets can saturate networks with fake peers.

**Irium Solution:**
- Proof-of-work challenge during handshake
- Ephemeral key signing
- Timestamp validation (5 minute window)
- Configurable difficulty (default: 8 bits)
- Trivial for legitimate nodes, prohibitive for bots

**Status:** ✅ Implemented (src/sybil.rs)

**Process:**
1. Node A sends PoW challenge to Node B
2. Node B solves challenge (8-bit PoW)
3. Node B returns proof with signature
4. Node A verifies proof and timestamp
5. Connection established if valid

### 5.6 Anchor-File Consensus

**Problem:** Eclipse attacks can feed new nodes false chains.

**Irium Solution:**
- Signed checkpoint headers (`anchors.json`)
- Multiple trusted signers
- New nodes verify chain against anchors
- Protects even if all peers are malicious

**Status:** ✅ Implemented (src/anchors.rs)

**Anchor Structure:**
```json
{
  "height": 0,
  "hash": "0000000028f25d65557e9d8d9e991f516c00d68f5aeae10b750645b398bd10a3",
  "timestamp": 1767583930,
  "signatures": ["..."]
}
```

### 5.7 Light Client First (SPV + NiPoPoW)

**Problem:** Mobile devices can't store full blockchain.

**Irium Solution:**
- SPV (Simplified Payment Verification)
- NiPoPoW (Non-Interactive Proofs of Proof-of-Work)
- Header-only sync
- Merkle proof verification
- Superblock proofs for ultra-light clients

**Status:** ✅ Implemented (header chain, merkle proofs, and NiPoPoW proofs)

**Light Client Benefits:**
- Download only headers (~80 bytes per block)
- Verify transactions with merkle proofs
- NiPoPoW: Logarithmic proof size
- Mobile wallet ready

### 5.8 On-chain Metadata Commitments

**Problem:** No native way to timestamp documents.

**Irium Solution:**
- Coinbase metadata field
- Hash pointers to off-chain data
- Notarization layer
- Immutable timestamp proofs

**Status:** ✅ Implemented (coinbase OP_RETURN via IRIUM_COINBASE_METADATA / IRIUM_NOTARY_HASH)

**Runtime Controls:**
- `IRIUM_COINBASE_METADATA`: arbitrary string (hashed if not 32-byte hex)
- `IRIUM_NOTARY_HASH`: 32-byte hex hash

**Use Cases:**
- Document timestamping
- Code release verification
- Copyright proof
- Supply chain tracking

---

## 6. Consensus Implementation

### 6.1 Block Structure

**Header (80 bytes):**
```
Version (4 bytes)
Previous Hash (32 bytes)
Merkle Root (32 bytes)
Time (4 bytes)
Bits (4 bytes)
Nonce (4 bytes)
```

**Block:**
- Header (80 bytes)
- Transaction count (varint)
- Transactions (variable)

### 6.2 Transaction Structure

**UTXO Model** (like Bitcoin):
- Inputs: References to previous outputs
- Outputs: New spendable amounts
- Signature: Proves ownership

### 6.3 Merkle Tree

Transactions are organized in a merkle tree:
- Leaves: Transaction hashes
- Root: Included in block header
- Allows SPV proofs

---

## 7. Network Protocol

### 7.1 P2P Binary Protocol

**Message Format:**
```
[Version:1][Type:1][Length:4][Payload:N]
```

**Message Types:**
- HANDSHAKE (1) - Connection establishment
- PING (2) / PONG (3) - Keepalive
- GET_PEERS (4) / PEERS (5) - Peer exchange
- GET_BLOCKS (6) / BLOCK (7) - Block sync
- TX (10) - Transaction propagation

### 7.2 Peer Management

**Configuration:**
- Default port: 38291
- Max peers: 8000 per node (production-optimized for network scale)
- Ping interval: 60 seconds (public nodes), 30 seconds (NAT nodes for keepalive)
- Peer timeout: 180 seconds
- Message timeout: 180 seconds
- Cleanup check: 30 seconds

**NAT Traversal:**
- Nodes behind NAT use 30-second ping interval to maintain session keepalive
- Public nodes use 60-second interval for efficiency
- Both configurations fully compatible and interoperable

**Security:**
- Sybil-resistant handshake
- Peer reputation tracking
- Automatic cleanup of dead peers
- DoS protection (message size limits)

---

## 8. Security Analysis

### 8.1 Consensus Security

**51% Attack:**
- Requires majority of network hashpower
- Economically infeasible for established network
- Detected via peer consensus

**Double-Spend:**
- Prevented by UTXO model
- Each output can only be spent once
- Validated in every block

**Long-Range Attack:**
- Mitigated by anchor checkpoints
- New nodes verify against signed anchors
- Multiple trusted signers

### 8.2 Network Security

**Eclipse Attack:**
- Mitigated by anchor file verification
- Suspicious peers detected and banned
- Multiple seed nodes

**Sybil Attack:**
- PoW handshake prevents mass bot connections
- Peer reputation system
- Connection limits

**DoS Attack:**
- Message size limits (100KB max per tx)
- Mempool limits (1000 tx max)
- Peer connection limits (8 max)
- Rate limiting

### 8.3 Wallet Security

- Standard secp256k1 key derivation
- WIF private key format
- Local storage only (no custodial)
- User-controlled backups

**Security Audit Summary:**
- ✅ Consensus: Secure
- ✅ P2P Network: Secure
- ✅ Transactions: Secure
- ✅ Wallet: Secure

---

## 9. Implementation Status

### 9.1 Completed (100%)

**Core Blockchain:**
- ✅ Genesis block specification and mining
- ✅ Block validation and chain state
- ✅ SHA-256d proof-of-work
- ✅ Difficulty adjustment
- ✅ UTXO tracking
- ✅ Transaction validation

**P2P Networking:**
- ✅ Binary message protocol
- ✅ Peer discovery and management
- ✅ Block propagation

**P2P Network Architecture:**
- ✅ Binary message protocol (13 message types)
- ✅ Peer discovery and management (runtime seedlist)
- ✅ Block propagation (PUSH-based broadcasting)
- ✅ Transaction broadcasting
- ✅ Handshake and adaptive keepalive (60s public, 30s NAT)
- ✅ NAT traversal support (outbound connections)
- ✅ IP:PORT deduplication (multi-service support)
- ✅ Self-connection detection (public IP aware)

**NAT Support:**

Irium fully supports nodes behind NAT/firewalls (same as Bitcoin):

- **NAT Nodes:** Can mine, sync, and broadcast via outbound connections
- **Public Nodes:** Accept inbound connections, help bootstrap network
- **Network Topology:** Mesh network through public nodes
- **Limitation:** NAT-to-NAT direct connections not possible (network limitation)

The network requires at least one public bootstrap node. Bootstrap seeds are listed in:
- `bootstrap/seedlist.txt` (signed baseline)
- `bootstrap/seedlist.extra` (unsigned additions)

**Runtime Seedlist:**

Nodes maintain a dynamic peer list (`bootstrap/seedlist.runtime`):
- Automatically saves discovered peers (incoming + outgoing)
- Persists between restarts for network resilience
- Enables decentralized peer discovery
- Reduces dependency on hardcoded bootstrap nodes
- ✅ Transaction broadcasting
- ✅ Handshake and keepalive

**Wallet System:**
- ✅ Key generation and management
- ✅ Transaction creation and signing
- ✅ QR code generation
- ✅ REST API

**Advanced Features:**
- ✅ Blockchain explorer API
- ✅ Advanced mempool with fee prioritization
- ✅ Uptime proofs and peer reputation
- ✅ Sybil-resistant handshake
- ✅ Relay reward system
- ✅ Anchor verification
- ✅ SPV + NiPoPoW proofs

### 9.2 Network Launch

**Mainnet Status:** ✅ LIVE

- Genesis mined: January 5, 2026
- All services operational
- Public endpoints active
- Ready for miners and users

**Public Services:**
- Explorer API: self-hosted via `/api` (reverse proxy optional)
- Wallet API: self-hosted via `/wallet` (reverse proxy optional)
- P2P Network: see `bootstrap/seedlist.txt` for bootstrap seeds

---

## 10. Governance

Irium follows **rough consensus** and **public review**.

**Upgrade Process:**
1. Draft improvement proposal
2. Community review and discussion
3. Prototype implementation
4. Multi-stakeholder audit
5. Network upgrade via miner signaling

No on-chain governance; decisions made through code and consensus.

---

## 11. Future Roadmap

- [x] Core blockchain implementation
- [x] PoW mining system
- [x] P2P networking
- [x] All 8 innovations
- [x] Mainnet genesis
- [x] Network launch
- [ ] Mobile wallet app
- [ ] Mining pool software
- [ ] Hardware wallet integration
- [ ] Exchange listings
- [ ] Block explorer web UI

---

## 12. Conclusion

Irium represents a new generation of blockchain technology that addresses fundamental challenges in decentralization, security, and accessibility. With all 8 core innovations implemented and operational, Irium is ready to serve as a foundation for the next era of cryptocurrency.

**Network Status:** Mainnet LIVE and operational
**Code Status:** Production-ready, open source
**Community:** Welcome to join and contribute

---

## 13. References

1. Satoshi Nakamoto, "Bitcoin: A Peer-to-Peer Electronic Cash System," 2008
2. Aggelos Kiayias et al., "Non-Interactive Proofs of Proof-of-Work (NiPoPoWs)," 2017
3. libp2p Project, "libp2p Specification," https://github.com/libp2p/specs
4. BIP-34: Block Height in Coinbase
5. BIP-65: OP_CHECKLOCKTIMEVERIFY

---

## Appendix A: Genesis Block

**Hash:** 0000000028f25d65557e9d8d9e991f516c00d68f5aeae10b750645b398bd10a3
**Nonce:** 1,961,837,199
**Timestamp:** 1767583930 (January 5, 2026)
**Merkle Root:** cd78279c389b6f2f0a4edc567f3ba67b27daed60ab014342bb4a5b56c2ebb4db
**Difficulty:** 0x1d00ffff (mainnet)

**Mining Stats:**
- Total hashes: 5,405,910,517
- Mining time: 7 hours 4 minutes
- Hashrate: 212,670 H/s average

---

**Irium Blockchain © 2025**
**MIT License - Open Source**

*Built for true decentralization*

## 9. Difficulty Adjustment (v1.0 Release)

**v1.0 uses standard Bitcoin difficulty:** 0x1d00ffff

The genesis block was mined with proper Bitcoin-standard difficulty calculation:

- **Difficulty bits**: 0x1d00ffff (standard Bitcoin genesis difficulty)
- **Expected block time**: ~10 minutes
- **Proper PoW validation**: No hardcoded overrides
- **Automatic adjustment**: Every 2016 blocks (~14 days)

### Technical Implementation

```text
# Standard Bitcoin compact target calculation
def to_target(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0xFFFFFF
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    else:
        return mantissa << (8 * (exponent - 3))
```

