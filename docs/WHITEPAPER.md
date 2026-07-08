# Irium: A Settlement-First Proof-of-Work Blockchain

**Technical Whitepaper — Version 2.2 (post-Groups-C-H)**

**Network Status:** Live on Mainnet (launched January 5, 2026) · node `v1.9.49` released (current); desktop app [Irium Core v1.0.77](https://github.com/iriumlabs/irium-core/releases/latest) bundles the latest v1.9.x sidecars. V2 block-time fork (120 s target) active since block 24,250; LWMA v2 active since block 19,740; BTC atomic swaps (SPV-verified, no custodian) live since block 23,850 (LTC/DOGE coming soon).

**Snapshot (block ~22,500):** ~18 connected peers per VPS node · circulating supply ~1.12M IRM · max supply 100,000,000 IRM (96.5M mineable + 3.5M genesis CLTV vest) · genesis hash `0000000028f25d…` · network era *Early Miner Era* · official-pool live (`pool.iriumlabs.org:3333` ASIC, `:3335` CPU/GPU, `:443` ISP-block fallback, `:3337` public stats proxy, `https://pool.iriumlabs.org/stats` HTML stats page)

**Upcoming hard fork (Fix 2a, activation height 23,500):** the chain
activates Bitcoin-standard block-header serialization at block 23,500.
After this height, every standard SHA-256d miner (Bitaxe, S19/S21,
T-Rex, lolMiner, NBMiner, cpuminer-opt, ccminer) produces valid blocks
without any firmware patch. All nodes must run iriumd v1.9.28 or newer
before block 23,500 is mined to avoid forking off the canonical chain.

---

## What's new in v1.9.28 (May 2026)

The release adds a complete second-generation settlement stack (Groups
C through H, plus a follow-up to auto-emit reputation anchors) and
hardens the peer-reputation system on small networks. None of these
require a hard fork — they layer on top of the existing
[Phase 2 proof automation engine](#7-proof-automation-engine).

- **Group C — Auto-release watcher:** `irium-wallet watch --auto-release`
  is a long-running daemon that subscribes to iriumd's
  `agreement.satisfied` WebSocket events and automatically broadcasts
  the release transaction the moment proof finality is reached. The
  daemon enforces the agreement's dispute_window (see Group E) before
  releasing.
- **Group D — Proof schema registry:** five canonical proof types are
  now schema-validated by iriumd's `ProofStore::submit` — `payment_received`,
  `delivery_confirmed`, `work_completed`, `milestone_delivered`,
  `deposit_conditions_met`. Each requires specific attributes in
  `typed_payload.attributes`. Unknown proof types pass through
  unchanged for forward compatibility.
- **Group E — Auto-policy by template type, plus dispute window:** every
  offer-take now generates the right `ProofPolicy` for its template
  (OTC → seller attests `payment_received`; freelance → contractor
  attests `work_completed`; milestone → N policies, one per milestone;
  deposit → no policy). Freelance and milestone agreements bake
  `agreement.deadlines.dispute_window = 144 blocks` (~2.4 h at the
  current 1–2 min/block cadence). The auto-release watcher waits the
  window before triggering release.
- **Group F — Signed escrow receipts:** new `GET /rpc/agreementreceipt`
  endpoint plus `irium-wallet agreement-export-receipt` produces a
  party-signed JSON snapshot of the full on-chain story of an
  agreement (funding txids, release/refund txids, dispute resolution,
  proofs with anchored heights, lifecycle state). Schema:
  `irium.escrow_receipt.v1`. Designed as a non-repudiation artifact
  for accounting and dispute documentation; verifiable offline.
- **Group G — Per-milestone fund and release:** `/rpc/fundagreement`
  gains an optional `milestone_id` field; new wallet aliases
  `agreement-milestone-fund` and `agreement-milestone-release` make
  the per-milestone path explicit. The `PartiallyReleased` lifecycle
  state is now exercised end-to-end.
- **Group H — On-chain reputation event anchoring:** a new `rep1:`
  OP_RETURN prefix carries four event kinds — `s` SuccessfulTrade,
  `w` DisputeWin, `l` DisputeLoss, `n` ResolverNonResponse. Release
  txs auto-embed two `rep1:s` outputs (one for each party).
  Dispute-resolve txs auto-embed `rep1:w` + `rep1:l`. A new
  `agreement-flag-non-response` wallet command broadcasts a standalone
  `rep1:n` tx once a resolver misses their response window. The
  `GET /rpc/reputation/:address` endpoint returns lifetime + recent
  (4320-block window) counts; the wallet's `compute_reputation` now
  overlays chain counts on top of the local outcomes file with the
  chain winning on conflict.
- **FIX #128 — Reputation hygiene:** dial failures (peer unreachable,
  no bytes exchanged) are no longer scored against the peer — only
  handshake-stage failures (peer reachable, sent bad data) subtract
  reputation. New env var `IRIUM_REPUTATION_BAN_SCORE_THRESHOLD`
  (default 20) lets operators on small networks relax or disable
  the reputation-based ban without rebuilding.

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Introduction and Motivation](#2-introduction-and-motivation)
3. [Protocol Architecture](#3-protocol-architecture)
4. [Consensus Mechanism](#4-consensus-mechanism)
5. [Supply Economics](#5-supply-economics)
6. [Settlement Layer](#6-settlement-layer)
7. [Proof Automation Engine](#7-proof-automation-engine)
8. [Dispute Resolution](#8-dispute-resolution)
9. [Decentralized Marketplace](#9-decentralized-marketplace)
10. [Reputation and Trust System](#10-reputation-and-trust-system)
11. [Business and Merchant Infrastructure](#11-business-and-merchant-infrastructure)
12. [Multi-Signature and Advanced Security](#12-multi-signature-and-advanced-security)
13. [Networking](#13-networking)
14. [Key Management and Addresses](#14-key-management-and-addresses)
15. [Mining](#15-mining)
16. [Security Properties](#16-security-properties)
17. [Roadmap](#17-roadmap)
18. [Conclusion](#18-conclusion)

---

## 1. Abstract

Irium is a proof-of-work blockchain built specifically for trustless commerce. Where
general-purpose blockchains require smart contract programming to express commercial
agreements, Irium provides a purpose-built settlement layer as a first-class protocol
primitive. Buyers and sellers can create cryptographically binding agreements, fund
them with IRM, submit proof of delivery or service completion, and release funds —
all without trusting any intermediary, custodian, or smart contract platform.

The base chain uses SHA-256d proof of work with the LWMA v2 difficulty algorithm, 2-minute
block targets (V2, active since block 24,250), and AuxPoW merged mining. The settlement layer implements deterministic
spend-path evaluation: release requires verified proof, refund requires timeout,
and every outcome is determined by on-chain observable data. A proof automation engine
handles three categories of real-world evidence (software delivery, service completion,
physical delivery), with an attestor bonding mechanism that creates economic incentives
for honest attestation. A decentralized marketplace enables P2P offer discovery without
DNS, central servers, or trusted directories. A reputation system derives objective
trust signals from agreement outcome history, with sybil resistance built in.

Irium is live on mainnet. No premine of unlocked coins. No admin keys. No freeze
powers. The founder vesting allocation is locked with on-chain CLTV timelocks. All
IRM beyond that allocation is earned through proof of work.

---

## 2. Introduction and Motivation

Global commerce depends on trust — trust that the buyer will pay, trust that the seller
will deliver, trust that a third party will arbitrate fairly when things go wrong.
Existing mechanisms for establishing this trust are expensive, slow, and inaccessible.

**Banks and payment processors** provide chargeback protection for buyers but can freeze
accounts, hold funds without explanation, and charge significant fees. Merchants in
many jurisdictions cannot access these services at all. Chargebacks can be weaponized
by bad-faith buyers. Sellers bear the cost of disputes they win.

**Lawyers and escrow agents** offer legally binding enforcement, but only within
jurisdiction, only after significant cost, and only with substantial time delays.
A cross-border dispute involving a $500 transaction cannot economically justify legal
proceedings. Most disputes in this range are simply absorbed as losses.

**PayPal and similar platforms** act as private intermediaries, making opaque decisions
about disputes and acting as a single point of failure. Their terms of service can
change. Their decisions are not auditable. Their geographic availability is limited.

**Ethereum smart contracts** offer programmable settlement, but require Solidity
expertise to deploy safely. Gas fees make small transactions uneconomical. Contract
bugs have caused hundreds of millions of dollars in losses. The programmability
introduces the same attack surface it was meant to eliminate.

Irium takes a different approach. Instead of requiring programmability for every use
case, it builds the most common commercial settlement patterns directly into the
protocol. Buyers and sellers interact using structured agreement objects whose
evaluation is deterministic and fully defined in the node software. There is no
contract to audit, no bytecode to deploy, no gas to optimize. The protocol handles
the mechanical enforcement; the parties supply the evidence.

The design principles are: determinism over programmability, proof over trust,
decentralization over convenience, and transparency over opacity.

---

## 3. Protocol Architecture

Irium consists of five distinct protocol layers. Each layer is separable in concept,
but they interact to form the complete system.

**Base chain layer.** The foundation is a SHA-256d proof-of-work blockchain with
2-minute block targets (V2, active since block 24,250) and the LWMA v2 difficulty adjustment algorithm. This layer
handles block production, transaction ordering, and IRM token issuance. It is
intentionally similar to Bitcoin's base layer to allow easy integration with
existing mining infrastructure and tooling.

**Settlement layer.** Built on top of the base chain, the settlement layer defines
structured agreement objects with cryptographic hash anchoring. Agreements encode
the terms of a commercial transaction: parties, amounts, deadlines, proof requirements,
and spend paths. When a proof is submitted and verified, the corresponding spend path
becomes available. When a timeout is reached without proof, the refund path opens.
The settlement layer is implemented in the node software and does not require
on-chain scripting beyond standard HTLC outputs.

**Proof automation engine.** The proof layer manages the lifecycle of settlement proofs:
submission, signature verification, policy evaluation, expiry, and gossip propagation.
Attestors can be designated in agreement policies to provide third-party evidence
signatures, and the bonding mechanism holds them economically accountable.

**Marketplace layer.** Irium nodes exchange offer feed URLs during P2P handshakes,
enabling decentralized discovery of buy and sell offers without any central directory.
The marketplace layer handles offer creation, syndication, filtering, and
trust-aware browsing — all through P2P gossip.

**Reputation layer.** The reputation system derives objective trust signals from
local agreement outcome history. Completion rate, dispute rate, proof response time,
and default history are calculated from verifiable on-chain data, giving counterparties
objective metrics before entering an agreement.

---

## 4. Consensus Mechanism

### Technical Specifications

| Parameter | Value |
|---|---|
| Ticker | IRM |
| Algorithm | SHA-256d (Bitcoin-compatible) |
| Max Supply | 100,000,000 IRM |
| Genesis Vesting | 3,500,000 IRM (3.5%) |
| Mineable Supply | 96,500,000 IRM (96.5%) |
| Block Time | 120 seconds (2 minutes), V2 target active since block 24,250 (V1 was 600 s) |
| Initial Reward | 50 IRM |
| Halving Interval | 1,050,000 blocks (~4 years at the 2-min V2 target) |
| Difficulty Retarget | 2,016-block retarget until height 16,462, then LWMA v2 |
| Coinbase Maturity | 100 blocks |
| Min Fee Rate | 1 sat/byte (~250 sat for a typical transaction) |

### SHA-256d Proof of Work

Block hashing uses SHA-256d: two sequential applications of SHA-256 over the
serialized block header. This is identical to Bitcoin's hashing scheme and allows
Irium blocks to be mined by any SHA-256d-capable hardware.

`block_hash = SHA256(SHA256(header_bytes))`

The implementation is in `src/pow.rs`:

```rust
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    ...
}
```

### Block Header Structure

Each block header is exactly 80 bytes, serialized in little-endian byte order:

| Field | Size | Description |
|---|---|---|
| version | 4 bytes | Block version. Bit 8 (value 256) indicates AuxPoW. |
| prev_hash | 32 bytes | SHA-256d hash of the preceding block header |
| merkle_root | 32 bytes | Merkle root of all transactions in this block |
| time | 4 bytes | Unix timestamp |
| bits | 4 bytes | Compact difficulty target |
| nonce | 4 bytes | Miner-controlled nonce field |

The block is valid when `SHA256d(header_bytes)` is less than or equal to the target
derived from the `bits` field. A block's time may be at most 7,200 seconds ahead of
the network-adjusted time (`MAX_FUTURE_BLOCK_TIME = 7200` from `src/constants.rs`).

### Difficulty Algorithm: LWMA

Irium uses the Linearly Weighted Moving Average (LWMA) algorithm for difficulty
adjustment. LWMA applies linearly increasing weight to recent solve times, giving
the most recent block the highest influence on the next target. This produces fast
difficulty response to hashrate changes while remaining resistant to manipulation.

**LWMA v1** was activated at block 16,462 (`MAINNET_LWMA_ACTIVATION_HEIGHT = Some(16_462)`
in `src/activation.rs`) with the following parameters (`src/constants.rs`):

- Window: N = 60 blocks
- Solvetime clamp: [1 second, 6T] where T = 600 seconds
- Maximum target ease per block: 2×
- Maximum target tighten per block: 2×

**LWMA v2** was activated at block 19,740 (`MAINNET_LWMA_V2_ACTIVATION_HEIGHT = Some(19_740)`)
after real-world observation (blocks 19,639–19,704) showed that the 60-block window
diluted slow-block signal so heavily that after a dominant miner left the network,
it took approximately 7.5 days for difficulty to reach usable levels. LWMA v2
parameters (`src/constants.rs`):

- Window: N = 30 blocks (reduced from 60 for faster response)
- Solvetime clamp: [1 second, 10T] (increased from 6T for stronger slow-block signal)
- Maximum target ease per block: 2× (unchanged)
- Maximum target tighten per block: 2× (unchanged)

The 2× per-block step clamp on both sides preserves manipulation resistance while
allowing rapid recovery. The smaller window and larger clamp both increase the
signal each slow block contributes without weakening the per-block cap.

Simulation results for the v1→v2 upgrade (infrastructure at 16.7 MH/s,
difficulty 1.02×10¹²):
- LWMA v1 (N=60, clamp=6T): usable after 7.1 days, near-target after 7.5 days
- LWMA v2 (N=30, clamp=10T): usable after 2.6 days, near-target after 2.7 days

### AuxPoW Merged Mining

At block 26,347 (`MAINNET_AUXPOW_ACTIVATION_HEIGHT = Some(26_347)` in
`src/activation.rs`), Irium begins accepting merged-mining proofs from SHA-256d
parent chains such as Bitcoin. Standard single-hash PoW blocks remain valid after
activation; AuxPoW is an additive option, not a replacement.

AuxPoW is signaled by setting version bit 8 (`AUXPOW_VERSION_BIT = 1 << 8 = 256`)
in the block version field. An AuxPoW-signaled block carries additional data after
the 80-byte header: the parent chain's coinbase transaction, Merkle branch connecting
the Irium hash to the coinbase, and the parent block header.

The commitment magic bytes are `0xfa 0xbe 0x6d 0x6d` (`AUXPOW_COMMIT_MAGIC` in
`src/auxpow.rs`). A merged miner includes `MAGIC || sha256d(irium_header) || chain_count`
in the parent coinbase, committing to one or more auxiliary chains in a single
mining operation.

Validation (`src/auxpow.rs: validate()`):
1. Verify the Irium header hash appears in the parent coinbase commitment.
2. Verify the coinbase transaction is in the parent block via the Merkle branch.
3. Verify the parent block header hash meets the Irium difficulty target.

Maximum Merkle branch depth is 20 (`MAX_BRANCH_DEPTH = 20`), allowing up to 2²⁰
(~1 million) auxiliary chains per merged mining operation.

### HTLCv1 Settlement Outputs

HTLCv1 (Hash Time-Locked Contract version 1) was activated at block 18,677
(`MAINNET_HTLCV1_ACTIVATION_HEIGHT = Some(18677)`). HTLCv1 is the on-chain output
type used to fund settlement agreements. It enforces two mutually exclusive spend
paths: release via secret preimage, or refund via block height timeout.

---

## 5. Supply Economics

### Block Rewards

Block rewards follow a Bitcoin-style halving schedule scaled to Irium's parameters.
The initial block reward is 50 IRM per block. Rewards halve every 1,050,000 blocks
(~4 years at the V2 2-minute target). The block reward at any height is computed
as (`src/constants.rs`):

```rust
pub const INITIAL_SUBSIDY: u64 = 50 * 100_000_000;  // 50 IRM
pub const HALVING_INTERVAL: u64 = 1_050_000;

pub fn block_reward(height: u64) -> u64 {
    let halvings = (height - 1) / HALVING_INTERVAL;
    if halvings >= 64 { return 0; }
    INITIAL_SUBSIDY >> halvings
}
```

The genesis block (height 0) has zero block reward. Mining rewards begin at height 1.

Halving schedule:

| Era | Block range | Reward per block | Era total |
|---|---|---|---|
| 1 | 1 – 1,050,000 | 50 IRM | 52,500,000 IRM |
| 2 | 1,050,001 – 2,100,000 | 25 IRM | 26,250,000 IRM |
| 3 | 2,100,001 – 3,150,000 | 12.5 IRM | 13,125,000 IRM |
| 4 | 3,150,001 – 4,200,000 | 6.25 IRM | 6,562,500 IRM |
| 5 | 4,200,001 – 5,250,000 | 3.125 IRM | 3,281,250 IRM |
| 6 | 5,250,001 – 6,300,000 | 1.5625 IRM | 1,640,625 IRM |
| ... | ... | ... | ... |
| All eras (bounded by cap) | Converging | Halving every 1,050,000 blocks | 96,500,000 IRM total mining emission |

The sum of all block rewards across all halving eras converges to 96,500,000 IRM,
bounded by the `MAX_MONEY = 100,000,000 IRM` consensus cap (which leaves
3,500,000 IRM headroom for the genesis CLTV vesting allocation described below).

### Genesis Vesting Allocation

The genesis block contains a single CLTV-locked output of 3,500,000 IRM
(`genesis.json: amount_sats = 350,000,000,000,000`, where 1 IRM = 100,000,000 atoms).
This allocation is labeled `founder_vesting_cltv` and is enforced by a consensus-level
CLTV (Check Lock Time Verify) script that prevents spending until the defined timelock
heights are reached. This is not a freely spendable premine — the coins cannot be
moved until on-chain conditions are satisfied.

Total fixed supply: **100,000,000 IRM** (96,500,000 from block rewards
+ 3,500,000 from the genesis CLTV vesting output).

The `MAX_MONEY` constant (`src/constants.rs: MAX_MONEY = 100_000_000 * 100_000_000`)
enforces the 100,000,000 IRM hard supply cap. No block reward can cause the total
minted supply to exceed this limit.

### Transaction Fees

Miners collect transaction fees in addition to block rewards. The minimum fee rate
is **1 satoshi per byte** (`min_fee_per_byte = 1.0` in `src/bin/iriumd.rs`), enforced
by the node mempool policy. A typical single-input two-output transaction of approximately
250 bytes requires a minimum fee of ~250 satoshis (0.0000025 IRM). Fee revenue becomes
increasingly important after multiple halvings, providing long-term miner incentive
without inflation.

### Coinbase Maturity

Coinbase outputs require 100 blocks of confirmation before they can be spent
(`COINBASE_MATURITY = 100` in `src/constants.rs`). This protects against spending
coinbase outputs from orphaned blocks.

---

## 6. Settlement Layer

### Agreement Model

A settlement agreement in Irium is a structured JSON object with a canonical
schema identifier `irium.phase1.canonical.v1` (defined as
`AGREEMENT_SCHEMA_ID_V1` in `src/settlement.rs`). The agreement encodes:

- **Parties**: Each party has a `party_id`, `display_name`, optional `address`,
  and optional `role`. The `payer` and `payee` fields reference party IDs.
- **Amount**: Total value in atoms (1 IRM = 100,000,000 atoms).
- **Deadlines**: `settlement_deadline`, `refund_deadline`, optional `dispute_window`.
- **Release conditions**: One or more conditions that must be satisfied for
  release. Conditions reference proof requirements with specific `proof_type`
  and optional attestor threshold.
- **Refund conditions**: Timeout-based spend path specifying `refund_address`
  and `timeout_height`.
- **Document hash**: SHA-256 hash of the supporting commercial document.
- **Metadata hash**: Optional hash of additional off-chain metadata.

Template types currently implemented:
- `simple_settlement` — bilateral settlement with a single release condition
- `otc_settlement` — over-the-counter bilateral trade with HTLC funding
- `deposit_payment` — payer-to-payee deposit with purpose reference
- `milestone_payment` — multi-milestone payment with per-milestone proof requirements

### Agreement Hash Anchoring

The canonical agreement hash is computed by serializing the agreement object
to its canonical JSON form and applying SHA-256d. The hash is the unique identifier
for an agreement across all nodes. It is used in proof submission, agreement-status
queries, and all settlement lifecycle operations.

Anchoring means this hash is recorded in the node's settlement store. Once anchored,
the agreement can be referenced by its 64-character hex hash rather than by
transmitting the full agreement object.

### Funding

An agreement is funded when an on-chain HTLC transaction output is linked to the
agreement hash. The node software discovers funding by scanning transaction outputs
for the agreement's script pattern. The `agreement-status` RPC reports `funded_amount`,
`released_amount`, and `refunded_amount`.

### Release and Refund Conditions

Every agreement encodes one or more release conditions and one or more refund
conditions. These are the spend paths that the settlement engine evaluates.

A release condition (`AgreementReleaseCondition`) specifies:
- `mode`: The release mechanism. Currently `"secret_preimage"` (HTLC-based release
  requiring the preimage of a committed hash) is the primary on-chain release mode.
- `secret_hash_hex`: The SHA-256 hash whose preimage unlocks the HTLC output.
- `release_authorizer`: Optional — identifies which party controls the secret
  (e.g., `"buyer"` in an OTC agreement where the buyer reveals the preimage on
  receipt of goods).
- `notes`: Human-readable description of the release path.

A refund condition (`AgreementRefundCondition`) specifies:
- `refund_address`: The address that receives funds if the timeout is reached.
- `timeout_height`: The block height at which the refund path becomes active.
- `notes`: Human-readable description of the refund path.

An agreement can have multiple release conditions (all of which must be satisfied)
and multiple refund conditions (any of which can trigger a refund after the
corresponding timeout). This structure allows complex multi-party agreements where
different parties control different spend paths.

### Agreement Bundles

An `AgreementBundle` (schema `irium.phase1.bundle.v1`) packages an agreement
together with its lifecycle metadata: funding transaction IDs, chain observation
snapshots, audit records, and signed statements. Bundles serve as portable
settlement receipts — a complete record of an agreement's lifecycle that can be
shared with counterparties, auditors, or dispute resolvers.

Bundles are created with `agreement-bundle-create` and can be cryptographically
verified with `agreement-bundle-verify`, which checks that the agreement hash in
the bundle matches the canonical hash of the embedded agreement object.

### Agreement Lifecycle States

Agreements progress through a set of well-defined states (`src/settlement.rs:
AgreementLifecycleState`):

| State | Description |
|---|---|
| `funded` | Agreement has received its expected deposit; awaiting proof |
| `partially_released` | Some milestones released; others still pending |
| `refunded` | Timeout reached; deposit returned to payer |
| `expired` | Agreement deadline passed without completion |
| `disputed_metadata_only` | Dispute raised; resolution pending |

### Deterministic Policy Evaluation

Policy evaluation is purely deterministic: given the same agreement object, the same
set of submitted proofs, and the same chain tip height, the evaluation result is
always identical across all nodes. There is no runtime state, no mutable on-chain
storage of the policy result, and no governance mechanism that can alter evaluation.

The `evaluate_policy_rpc` function in `src/settlement.rs` takes the agreement, the
known proofs, and the tip height, and returns one of three `PolicyOutcome` values:
`Satisfied`, `Timeout`, or `Unsatisfied`. Release eligibility requires `Satisfied`
and proof finality confirmation (Section 7).

The evaluation algorithm (simplified):
1. Filter proofs to those that are within their validity window (`expires_at_height`
   not yet reached).
2. Verify each proof's ECDSA signature against the attested message.
3. Check whether the set of verified proofs satisfies all release conditions in the
   agreement (including any attestor threshold requirements).
4. If all release conditions are satisfied: return `Satisfied`.
5. If any refund deadline has passed and the corresponding release condition remains
   unsatisfied: return `Timeout`.
6. Otherwise: return `Unsatisfied`.

This evaluation is run identically by every node. There is no committee, no vote,
and no privileged observer. Any node with the agreement and its proofs can
determine the outcome independently.

---

## 7. Proof Automation Engine

### Proof Submission and Structure

A settlement proof is submitted to the local node's RPC and gossipped to peers
via the `ProofGossip` P2P message (message type 19, `src/protocol.rs`). The proof
structure (`src/settlement.rs: SettlementProof`) contains:

| Field | Type | Description |
|---|---|---|
| `proof_id` | String | Unique identifier for this proof |
| `schema_id` | String | Proof schema version |
| `proof_type` | String | Matches the release condition requirement |
| `agreement_hash` | String | 64-char hex hash of the agreement |
| `milestone_id` | String? | For milestone agreements: which milestone |
| `attested_by` | String | Attestor address that signed the proof |
| `attestation_time` | u64 | Unix timestamp of attestation |
| `evidence_hash` | String? | SHA-256 hash of supporting evidence |
| `evidence_summary` | String? | Human-readable summary |
| `expires_at_height` | u64? | Block height after which proof expires |
| `signature` | Envelope | ECDSA signature payload and type |
| `typed_payload` | Object? | Normalized proof payload metadata |

### Proof Lifecycle

A proof's lifecycle state is derived from its submission record and the current chain
tip (`src/settlement.rs: PolicyOutcome`):

- **Active**: Proof is within its validity window and eligible for policy evaluation.
- **Expired**: The `expires_at_height` has been reached; proof is skipped in
  `evaluate_policy_rpc` (but not in `check_policy_rpc`, which is height-independent).
- **Satisfied**: Policy evaluation returns `Satisfied` — all required proofs are
  present and signature-verified.
- **Timeout**: Deadline passed without all required proofs; refund path activates.
- **Unsatisfied**: Proofs missing, expired, or failing signature verification.

### Proof Templates

Three real-world proof kinds are implemented in the wallet CLI (`irium-wallet.rs`):

**`software_delivery`**
Used for digital goods, software releases, and file deliveries. Requires a
`--content-hash` parameter: the SHA-256 hash of the delivered artifact. The proof
payload encodes `proof_kind: "software_delivery"` and `content_hash` so the
recipient can verify the delivered file matches the attested hash.

**`service_completion`**
Used for professional services, consulting, and work milestones. The attestor
signs a message confirming the service was completed. No hash is required —
the attestor's identity and bond (see Section 12) provide accountability.

**`physical_delivery`**
Used for shipped goods. Requires a `--reference-id` (tracking number or logistics
reference). The proof payload encodes `proof_kind: "physical_delivery"` and
`reference_id` so any party can independently verify the shipment status.

### Proof Gossip Propagation

When a proof is submitted to any node, it is broadcast to all connected peers
using the `ProofGossip` message (type 19). Peers who have the corresponding
agreement anchored will store the proof and re-evaluate their policy state.
This ensures all network participants observing the same agreement converge to
the same lifecycle state without any central coordination.

### Proof Finality Depth

To protect against chain reorganizations invalidating submitted proofs, the node
requires a configurable number of confirmations before considering a proof final.
The default finality depth is 6 blocks (`IRIUM_PROOF_FINALITY_DEPTH`, default 6
in `src/bin/iriumd.rs`).

The `agreement-status` RPC returns three fields for proof depth tracking:

| Field | Meaning |
|---|---|
| `proof_depth` | How many blocks deep the proof transaction is (null if no proof) |
| `proof_final` | `true` when `proof_depth >= IRIUM_PROOF_FINALITY_DEPTH` |
| `release_eligible` | `true` when `proof_final` is true and state is releasable |

If a reorg reorganizes away the block containing the proof, iriumd detects this
and emits an `agreement.proof_reorged` WebSocket event, resetting the agreement
to `proof_pending` state and prompting the seller to resubmit.

Parties should wait for `release_eligible: true` before considering a settlement
complete.

---

## 8. Dispute Resolution

### Raising a Dispute

A dispute is raised when a party believes the settlement conditions have been met
but the counterparty is not cooperating with release, or when there is a genuine
disagreement about whether proof requirements were satisfied. The `disputed_metadata_only`
flag on an agreement indicates that a dispute is active while the parties and their
designated resolver work toward resolution.

### Resolver Roles

Agreements may designate a `resolver_reference` — an identifier or address for the
party who will adjudicate disputes. The resolver is agreed upon at agreement creation
time and is part of the agreement's canonical hash. This means neither party can
change the resolver after the agreement is funded without creating a new agreement
and transferring funds.

Resolvers may be:
- A designated attestor who has been pre-approved by both parties
- A mutually trusted third party address
- A professional arbitration service that operates as an Irium attestor

### Dispute Workflow

When a dispute is active:
1. The agreement enters `disputed_metadata_only` lifecycle state.
2. Release is suspended — the `release_eligible` field returns false regardless of
   proof state.
3. The designated resolver reviews the evidence (proofs, communication, delivery
   records) off-chain.
4. The resolver issues a signed attestation in the agreed format, referencing the
   agreement hash and their resolution decision.
5. This resolver attestation is submitted as a proof. If it satisfies the agreement's
   release conditions, release becomes eligible. If it confirms a refund, the
   refund path is triggered at timeout.

The dispute mechanism does not require any on-chain transaction to initiate or
resolve — it operates through the proof submission layer that already exists for
normal settlement.

### Relationship Between Attestors, Resolvers, and Parties

Attestors provide evidence of delivery or completion. Resolvers adjudicate disagreements
about whether evidence is sufficient. A single entity can act as both attestor and
resolver in a transaction, though parties should evaluate whether this concentration
of trust is appropriate for their use case. Attestors with active bonds (Section 12)
provide stronger trust guarantees than unbonded attestors.

---

## 9. Decentralized Marketplace

### P2P Offer Feed Discovery

Irium nodes discover marketplace offer feeds through the existing P2P handshake
protocol. When two nodes connect, each node optionally includes its `marketplace_feed`
URL in the handshake payload (`src/p2p.rs`). The receiving node records this URL
using `record_discovered_feed()`, making it available for future offer-list queries.

This mechanism requires no DNS, no central directory, and no trusted registry.
As long as at least one known peer is advertising a feed URL, a new node can
discover the marketplace automatically.

### Multi-Source Feed Aggregation

The `offer-list` command aggregates offers from multiple sources simultaneously:

- **Local**: Offers created on this node and stored locally
- **Imported**: Offers received from counterparties or imported from files
- **Remote**: Offers fetched from known feed URLs in real time

Offers are deduplicated by `offer_id`. When an offer appears in multiple sources,
the most recent version is used. Filters supported: seller address, payment method,
minimum and maximum amount, offer status (open, taken, settled).

### Offer Lifecycle

| State | Description |
|---|---|
| `open` | Offer is available for a buyer to take |
| `taken` | Buyer has initiated an agreement against this offer |
| `settled` | Agreement has reached a terminal state |

An offer transitions from `open` to `taken` via the `offer-take` command, which
creates a corresponding agreement and links it to the offer ID. The offer record
is updated locally and syndicated via the feed so other nodes see the updated status.

### Feed Registry Management

Nodes maintain a local feed registry. Operators manage it with:

- `feed-add <url>` — add a feed URL to the local registry
- `feed-remove <url>` — remove a feed URL
- `feed-list` — list all registered feed URLs
- `feed-bootstrap` — populate the registry from the compiled-in `BOOTSTRAP_FEEDS`
  constant (`src/bin/irium-wallet.rs: BOOTSTRAP_FEEDS`)

The `offer-feed-sync` command fetches and caches offers from all registered feeds.
`offer-feed-prune` removes cached offers older than a configurable threshold.

### Trust-Aware Browsing

The `offer-list` command integrates with the reputation system (Section 10) to
surface trust signals alongside offer details. Offers from sellers with established
reputation and low dispute rates appear with higher ranking scores. Offers from
sellers with insufficient agreement history are marked with sybil suppression
warnings.

---

## 10. Reputation and Trust System

### Reputation Architecture

The reputation system operates entirely locally. Each node maintains its own
reputation database derived from its own observation of agreement outcomes. There
is no central reputation server, no shared reputation ledger, and no oracle.

This design has important properties:
- **No single point of failure**: A reputation server going offline does not
  disable the reputation system.
- **No manipulation target**: There is no central database for an attacker to
  compromise or censor.
- **Local accuracy**: A node that has directly observed many agreements with a
  counterparty has higher-quality reputation data than a node that has observed
  none.
- **Portability**: Sellers can export their reputation records and share them with
  nodes that have no direct history, using cryptographic signatures to prove
  authenticity.

### Signal Derivation

Reputation is computed locally from the node's stored agreement outcome records.
These records are created by the node operator using `reputation-record-outcome`
after each completed agreement. The signals are derived from observable agreement
outcomes — no oracle, no on-chain state, no governance.

Trust signals (`src/bin/irium-wallet.rs`):

| Signal | Definition |
|---|---|
| `completion_rate` | `(satisfied_count / total_count) × 100` |
| `dispute_rate` | `(disputed_count / total_count) × 100` |
| `avg_proof_response_secs` | Average time from funding to proof submission |
| `default_count` | Number of agreements ending in timeout or unsatisfied outcome |
| `risk_signal` | Categorical: `low`, `moderate`, `high`, `very_high` |
| `self_trade_count` | Detected instances of trading with affiliated addresses |

The `risk_signal` field is derived from `default_count` as a fraction of total
agreements, providing a human-readable summary of seller reliability.

### Sybil Resistance

A minimum of 3 completed agreements is required before a seller's ranking is
displayed (`SYBIL_MIN_AGREEMENTS = 3` in `src/bin/irium-wallet.rs`). Sellers
below this threshold are marked `sybil_suppressed: true` in API responses.

This threshold prevents new addresses from immediately appearing with perfect
reputation scores. Establishing a meaningful reputation requires genuine
agreement history, making Sybil attacks expensive — each false positive requires
a real funded agreement to generate.

Self-trade detection identifies cases where the buyer and seller addresses share
a common key derivation root or have a known historical relationship. Self-trade
counts are surfaced separately in reputation output to allow counterparties to
apply additional skepticism.

### Recent vs. Lifetime History

The reputation system tracks both lifetime history and recent history (a rolling
window of the most recent agreements). The `recent` section of reputation output
provides:
- `recent_default_count`: Defaults in the recent window
- `recent_risk`: Risk signal based on recent history only

This two-layer view allows a counterparty to see both a seller's lifetime track
record (which may include early struggles) and their current operating quality
(which is more predictive of near-term behavior). A seller who had early problems
but has operated cleanly for the last 50 agreements can demonstrate this through
the recent history field.

### Reputation Portability

Reputation data can be cryptographically exported and shared. `reputation-export`
produces a signed JSON file containing the seller's outcome history. Counterparties
can independently verify the signature against the seller's public key using
`reputation-import` and `reputation-verify`. This allows a seller's track record
to travel across nodes that have not directly observed their agreements.

The export format is designed for public sharing — sellers can post their reputation
exports on their websites, in offer listings, or in community forums, giving buyers
verifiable evidence of their history without requiring any interaction with the
seller's node.

---

## 11. Business and Merchant Infrastructure

### Merchant Payment Flows

The wallet CLI includes purpose-built commands for common business scenarios.

**Invoice generation**: `invoice-generate` creates a payment request with a
specified recipient address, amount, reference string, and optional expiry height.
The invoice object can be shared as a JSON file or URL-encoded link. Buyers import
invoices with `invoice-import` and pay them using `send`.

**Seller dashboard**: `seller-status` shows all active agreements where the
configured address is the payee — funding state, proof submission status, release
eligibility, and estimated revenue.

**Buyer dashboard**: `buyer-status` shows all active agreements where the configured
address is the payer — amounts committed, proof requirements outstanding, and
estimated refund amounts if applicable.

### Business Settlement Templates

Pre-built agreement templates for common business scenarios are accessible via
`agreement-template`:

- **`simple`**: Bilateral settlement with a single proof requirement
- **`otc`**: Over-the-counter trade with asset reference and payment method
- **`deposit`**: Deposit payment with purpose reference and refund path
- **`milestone`**: Multi-milestone contract with per-milestone proof requirements
  and independent release for each milestone

The milestone template allows complex service contracts — a software development
agreement might have three milestones (design, implementation, delivery), each
requiring a `service_completion` proof from the designated attestor and independently
releasable.

### Contractor Milestone Payments

The milestone payment template supports contracts where a single total amount is
split across multiple independently releasable milestones. Each milestone has its
own `required_proof_type`, deadline, and release address. A buyer funds the full
amount in a single HTLC output. As each milestone is completed and its proof is
verified, the corresponding fraction is released. Remaining milestones retain their
independent refund timeout.

Each milestone in the `AgreementMilestone` structure (`src/settlement.rs`) contains:
- `milestone_id`: Unique identifier for this milestone
- `title`: Human-readable milestone name
- `amount`: Amount in atoms to release upon completion
- `recipient_address`: Address that receives this milestone's payment
- `refund_address`: Address that receives refund if this milestone's deadline passes

A typical three-milestone software contract might be structured as:
- Milestone 1 (33%): Design phase — `service_completion` proof at project start
- Milestone 2 (33%): Implementation — `service_completion` proof at code delivery
- Milestone 3 (34%): Final delivery — `software_delivery` proof with content hash

Each milestone releases independently. If milestone 1 is completed but milestone 2
is not, only milestone 1 releases and the remaining 67% enters the timeout path
for milestone 2's deadline.

### REST API Layer

The node exposes a REST API for programmatic access to all settlement, proof, and
marketplace operations. Key endpoints include:

| Endpoint | Description |
|---|---|
| `GET /status` | Node health, block height, peer count, era |
| `GET /rpc/balance?address=Q…` | Address balance and UTXO count |
| `GET /rpc/utxos?address=Q…` | Full UTXO list for an address |
| `GET /rpc/history?address=Q…` | Transaction history for an address |
| `GET /rpc/block?height=N` | Full block including coinbase miner and serialized txs |
| `GET /rpc/tx?txid=…` | Single transaction lookup |
| `GET /rpc/fee_estimate` | Current minimum fee per byte |
| `GET /rpc/network_hashrate` | Estimated network hashrate + difficulty |
| `GET /rpc/richlist?limit=N` | Top-N IRM holders by balance (since v1.9.17) |
| `POST /rpc/submitproof` | Submit a settlement proof |
| `POST /rpc/agreementstatus` | Agreement status and lifecycle |
| `POST /rpc/listproofs` | List submitted proofs |
| `GET /offers/feed` | List marketplace offers |
| `GET /explorer/reputation/:pubkey` | Public reputation data |
| `GET /explorer/stats` | Network-wide settlement statistics |

Default RPC port: `38300`. Default P2P port: `38291`. Lightweight `/status`
server runs on `127.0.0.1:8080` by default (override with
`IRIUM_STATUS_HOST` / `IRIUM_STATUS_PORT`). Full schema, request shapes and
authentication requirements are in [docs/API.md](API.md).

### SDK Availability

**Python SDK**: `sdk/irium_client.py` provides a Python wrapper over the REST API
covering the complete settlement lifecycle.

**JavaScript/TypeScript SDK**: `sdk/irium-js/` is a TypeScript SDK (`package.json`
package name `irium-js`) with full TypeScript types for all API objects. The SDK
covers status, balance, offers, agreements, proof submission, release eligibility,
reputation, and WebSocket event subscriptions.

### WebSocket Streaming API

Irium nodes expose a WebSocket endpoint for real-time push events. Clients connect
and send a subscription message specifying which event types they want:

```json
{
  "action": "subscribe",
  "events": ["agreement.satisfied", "block.new"],
  "filter": { "agreement_hash": "abc123..." }
}
```

Implemented event types:
- `agreement.funded` — deposit received
- `agreement.proof_submitted` — proof submitted for an agreement
- `agreement.satisfied` — release eligibility reached
- `agreement.timeout` — deadline passed without proof
- `agreement.disputed` — dispute raised
- `agreement.proof_reorged` — proof transaction reorganized out of the chain
- `proof.gossip_received` — proof arrived via P2P
- `offer.created` — new offer in the local store
- `offer.taken` — offer taken by a buyer
- `block.new` — new block with height and hash
- `peer.connected` / `peer.disconnected` — P2P peer events

A Server-Sent Events (SSE) fallback is available at `GET /events` for clients
that cannot use WebSocket.

---

## 12. Multi-Signature and Advanced Security

### Multisig Address Format

Irium supports M-of-N multisig addresses as a first-class address type. A multisig
address encodes the threshold M, the count N, and the N compressed secp256k1
public keys (33 bytes each) into a single Base58Check string using version byte
`0x28` (`IRIUM_MULTISIG_VERSION = 0x28` in `src/bin/irium-wallet.rs`).

Create a multisig address:
```sh
irium-wallet multisig-create --m 2 --pubkeys <key1> <key2> <key3>
```

### Partial Signing Flow

Multisig spending requires M-of-N independent signatures. The workflow:

1. One party creates the unsigned transaction: `multisig-spend-build`
2. Each signer signs independently: `multisig-sign <txhex> <wallet>`
3. Signatures are combined: `multisig-combine <partial1> <partial2>`
4. When M signatures are combined, the transaction is broadcast:
   `multisig-broadcast <fulltx>`

### 2-of-2 OTC Escrow

For over-the-counter trading, a 2-of-2 multisig escrow requires both buyer and
seller to co-sign both the funding and release transactions. Neither party can
unilaterally move funds. The timeout path provides a mutual refund if one party
becomes unresponsive. This is a stronger trust model than the default single-key
OTC flow.

### Attestor Bonding

Attestors currently operating without a bond provide no economic accountability.
The bonding mechanism changes this. An attestor registers a bond by locking IRM
in a special output linked to their public key hash:

```sh
irium-wallet attestor-register --bond <amount_irm>
```

The bond record is stored on-chain. The `attestor-list` command shows each
attestor's bond amount, last attestation, and slash history.

**Slashing conditions** (`src/attestor_bond.rs`):
If two proofs signed by the same attestor carry contradictory claims for the
same agreement (one asserting satisfied, one asserting unsatisfied), the node
constructs a slashing transaction. The slashing anchor script format is:
`slash1:<attestor_pkh_hex>:<agreement_hash_hex>` (see `SLASH_ANCHOR_PREFIX`).
Slashed funds flow to the non-attesting party in the affected agreement.

**Withdrawal cooldown**: An attestor may withdraw their bond only after
1,000 blocks have elapsed since their last attestation
(`BOND_COOLDOWN_BLOCKS = 1000` in `src/attestor_bond.rs`). This window allows
any pending slashing claims to be processed before funds are released.

### Private Agreements (Confidential Terms)

Business parties often need to keep commercial terms confidential. The `--private`
flag on any `agreement-create-*` command anchors only the agreement hash on-chain
while storing the full content locally in `~/.irium/private-agreements/`.

Selective disclosure is implemented using ECIES (Elliptic Curve Integrated Encryption
Scheme) over secp256k1 with AES-256-GCM:

```sh
irium-wallet agreement-share <hash> <recipient_pubkey_hex> [--out blob.json]
```

The encrypted blob is self-describing JSON containing `scheme`, `version`,
`ephemeral_pubkey`, `nonce`, and `ciphertext`. The recipient decrypts using
their wallet private key:

```sh
irium-wallet agreement-decrypt blob.json --wallet wallet.json
```

The agreement content is never transmitted over the P2P network. The only
on-chain data is the 32-byte hash anchor.

---

## 13. Networking

### P2P Protocol

Irium uses a custom binary P2P protocol (version 1, `PROTOCOL_VERSION = 1` in
`src/protocol.rs`). Each message has the format:

```
[version: 1 byte][type: 1 byte][length: 4 bytes LE][payload: length bytes]
```

Maximum message size: 32 MB (`MAX_MESSAGE_SIZE = 32 * 1024 * 1024`).
Maximum block size: 4 MB (`MAX_BLOCK_SIZE = 4 * 1024 * 1024`).

Full message type table:

| Type | ID | Description |
|---|---|---|
| Handshake | 1 | Initial peer handshake with version, height, node ID |
| Ping | 2 | Liveness probe |
| Pong | 3 | Liveness response |
| GetPeers | 4 | Request peer addresses |
| Peers | 5 | Peer address response |
| GetBlocks | 6 | Request block hashes from a known tip |
| Block | 7 | Full block transmission |
| GetHeaders | 8 | Request block headers |
| Headers | 9 | Block header response |
| Tx | 10 | Transaction broadcast |
| Mempool | 11 | Mempool transaction list request |
| SybilChallenge | 12 | Anti-sybil proof-of-work challenge |
| SybilProof | 13 | Anti-sybil proof-of-work response |
| RelayAddress | 14 | Relay a peer address to neighbors |
| Inv | 15 | Inventory announcement |
| GetData | 16 | Request specific inventory items |
| UptimeChallenge | 17 | Uptime proof challenge |
| UptimeProof | 18 | Uptime proof response |
| ProofGossip | 19 | Settlement proof gossip |
| Disconnect | 99 | Graceful disconnect notification |

### DNS-Free Bootstrap System

Irium uses a three-layer DNS-free peer discovery system. No DNS resolution
occurs at any layer. No domain names are hardcoded anywhere in the software.

**Layer 1 — Peer Gossip and Runtime Cache**

When a node connects to any peer, it immediately receives up to 1000 known
dialable peer addresses. These addresses are stored in a local runtime peer
cache (`~/.irium/bootstrap/seedlist.runtime`) which is written to disk every
10 minutes and on clean shutdown. On subsequent startups the node loads from
this cache first. Once a node has connected to the network even once, it becomes
self-sufficient and never requires seed nodes or any external infrastructure again.

**Layer 2 — Signed Seedlist**

For nodes starting for the first time with an empty peer cache, a
cryptographically signed IP seedlist (`seedlist.txt`) is bundled with the
software. The signature (Ed25519 via `ssh-keygen`) prevents eclipse attacks by
ensuring the seedlist cannot be tampered with. The seedlist is read from the
user's data directory (`~/.irium/bootstrap/seedlist.txt`) rather than embedded
in the binary, allowing it to be updated without a software release. Node
operators can also inject peers directly at startup using the
`--add-seed <ip:port>` flag or at runtime via the `POST /admin/add-seed` RPC
endpoint, bypassing the signed seedlist entirely.

**Layer 3 — Blockchain-Embedded Peer Discovery**

Miners and node operators who wish to be publicly discoverable can set the
`IRIUM_ADVERTISE_ADDR=<ip:port>` environment variable. When set, the miner
embeds the listen address in every coinbase transaction as a zero-value
`OP_RETURN` output with the payload `IRIUM_PEER <ip:port>`. On cold start, if
the runtime peer cache has fewer than 5 entries, iriumd scans the last 2016
blocks for `IRIUM_PEER` announcements and bootstraps directly from addresses
found in the chain. As the network grows and more miners advertise their
addresses, the blockchain itself becomes the peer directory.

**Progressive self-sufficiency**

This architecture means the network becomes progressively more self-sustaining
over time. Early nodes rely on the signed seedlist. As more nodes connect and
populate their peer caches, the gossip layer takes over. As miners embed their
addresses in the chain, even brand new nodes with empty caches can bootstrap
without any seed infrastructure — creating a network that can survive
indefinitely without any centrally operated seed servers.

Seed node records are managed in three files:
- `~/.irium/bootstrap/seedlist.txt` — signed baseline seeds (copied from binary on first run)
- `~/.irium/bootstrap/seedlist.extra` — operator-added extra seeds
- `~/.irium/bootstrap/seedlist.runtime` — dynamically discovered peers, auto-generated

### Marketplace Feed Discovery via Handshake

During the initial P2P handshake, nodes optionally include their
`marketplace_feed` URL in the handshake payload. Receiving nodes record this
URL in their local feed registry (`record_discovered_feed()` in `src/p2p.rs`).
This allows marketplace feeds to propagate organically through the network
without any central feed directory.

### Self-Advertised External Endpoint (CGNAT Escape)

The handshake payload also carries an optional `external_endpoint` field
(`"<ip>:<port>"`, IPv4 only) which receivers prefer over the TCP source IP
when recording a peer as dialable. This is the CGNAT escape hatch: a node
behind carrier-grade NAT (RFC 6598, `100.64.0.0/10`) sees its peers from
the carrier's NAT44 address, not its real public IP. Without an explicit
advertisement, receivers would record that carrier address as the peer's
dialable endpoint and gossip it to others — poisoning every downstream
PeerDirectory with unroutable records.

Operators set the field via `IRIUM_EXTERNAL_ENDPOINT=<ip>:<port>` (env)
or `external_endpoint` in the node config JSON. Routability is validated
identically on both sender and receiver: loopback, RFC1918 private,
RFC6598 CGNAT, link-local, broadcast, multicast, RFC5737 documentation,
unspecified, port 0, and IPv6 are all rejected and fall back to the
legacy TCP-source-IP behaviour. The field is `#[serde(default)]`, so old
peers without it are unaffected.

`irium-core` (the desktop wallet) populates `IRIUM_EXTERNAL_ENDPOINT`
automatically: it asks an external IP-echo service (ipify), validates the
returned address, and — if UPnP IGD reports a different external IP — it
trusts ipify (because under CGNAT, UPnP returns the modem's WAN side, not
the public internet). When neither service produces a routable IPv4, no
endpoint is advertised; iriumd remains operational in outbound-only mode.

Reference: `src/p2p.rs::dialable_multiaddr_from_advertised` and
`src/protocol.rs::HandshakePayload::external_endpoint`. Live on
`testing-codes-before-merging`, scheduled for v1.9.19.

### Public Block-Explorer Endpoints

In addition to the chain-query API surface, `iriumd` exposes a handful of
read-only endpoints that power public block explorers and node-status
dashboards without requiring authentication:

- `GET /status` — chain tip + peer summary
- `GET /peers` — connected peer table
- `GET /rpc/richlist?limit=N` — top-N IRM holders ranked by spendable
  balance over the live UTXO set (added in v1.9.17)
- `GET /rpc/network_hashrate` — estimated network hashrate / difficulty
- `GET /offers/feed` — marketplace offer feed
- `GET /explorer/*` — explorer-specific views (stats, agreements, proofs,
  reputation per pubkey)

Full schema in [docs/API.md](API.md).

---

## 14. Key Management and Addresses

### Address Format

Irium P2PKH (pay-to-public-key-hash) addresses are generated as follows:

1. Generate a secp256k1 private key (32 bytes)
2. Derive the compressed public key (33 bytes)
3. Apply SHA-256 to the compressed public key
4. Apply RIPEMD-160 to the result (20-byte public key hash)
5. Prepend version byte `0x39` (`IRIUM_P2PKH_VERSION = 0x39`)
6. Append 4-byte double-SHA256 checksum
7. Encode the 25-byte payload in Base58

`address = Base58Check(0x39 || RIPEMD160(SHA256(compressed_pubkey)))`

The version byte `0x39` (decimal 57) produces addresses beginning with the
character `Q` in Base58 encoding. All standard Irium addresses begin with Q.

Multisig addresses use version byte `0x28` (`IRIUM_MULTISIG_VERSION = 0x28`),
producing addresses beginning with `P`.

Implementation (`src/bin/irium-wallet.rs`):

```rust
const IRIUM_P2PKH_VERSION: u8 = 0x39;

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rip = Ripemd160::digest(&sha);
    ...
}

fn base58_p2pkh_from_hash(pkh: &[u8; 20]) -> String {
    let mut body = Vec::with_capacity(1 + 20);
    body.push(IRIUM_P2PKH_VERSION);
    body.extend_from_slice(pkh);
    // double-SHA256 checksum
    ...
}
```

### Custom Derivation Scheme (Legacy)

The original key derivation scheme generates keys from a 32-byte seed using
SHA-256-based HMAC derivation. Keys derived by this scheme are stored in the
wallet file as raw 64-character hex private keys. This scheme remains fully
supported and is the default when creating wallets without the `--bip32` flag.

### BIP32/BIP39 Hierarchical Deterministic Keys

BIP32 HD key derivation is supported as an additional option (`--bip32` on
`create-wallet`). New wallets created with this flag generate a 24-word BIP39
mnemonic. The derivation path follows BIP44:

`m/44'/1'/0'/0/<index>`

Coin type 1 is used pending official BIP44 registration for IRM. The master
key is derived using HMAC-SHA512 with the "Bitcoin seed" label (standard
BIP32 master key derivation). Child key derivation follows the standard BIP32
`ckd_priv` function.

```sh
irium-wallet create-wallet --bip32
# Generates 24-word mnemonic

irium-wallet import-mnemonic "word1 word2 ... word24"
# Restores wallet from mnemonic
```

BIP32-derived keys produce the same Irium address format as custom-scheme keys
(version byte 0x39, Base58Check). The scheme difference is only in how the
private key is derived from the seed — the address format is identical.

### WIF Import and Export

The `import-wif` and `export-wif` commands support standard Wallet Import Format
for private keys. The WIF format uses the standard encoding:

`WIF = Base58Check(0x80 || private_key_bytes [|| 0x01 if compressed])`

Imported WIF keys are decoded by `wif_to_secret_and_compression()` in
`src/bin/irium-wallet.rs` and stored alongside regular wallet keys. The founder
vesting wallet private key uses this format.

### Hardware Wallet Compatibility

The BIP32/BIP44 derivation path `m/44'/1'/0'/0/<index>` is compatible with
any hardware wallet that supports custom coin types. Full hardware wallet
integration requires the wallet repository (in development; out of scope for
this release).

---

## 15. Mining

### CPU Mining

The `irium-miner` binary provides CPU-based SHA-256d mining. It connects to an
iriumd node via the RPC API to fetch block templates and submit solutions.
Operators configure the mining address and RPC endpoint via environment variables.

Key environment variables:
- `IRIUM_MINER_ADDR` — coinbase payout address
- `IRIUM_NODE_URL` — iriumd RPC endpoint

### GPU Mining

The `irium-miner-gpu` binary provides OpenCL-based GPU mining. It uses the same
RPC API as the CPU miner but offloads the SHA-256d inner loop to the GPU using
an OpenCL kernel.

Supported GPU families:
- NVIDIA (CUDA/OpenCL via proprietary driver or `nvidia-opencl-dev`)
- AMD (ROCm or `amdgpu-opencl-icd`)
- Intel (via `intel-opencl-icd`)

GPU selection via environment variables:
- `IRIUM_GPU_PLATFORM` — OpenCL platform index or vendor name substring
  (default: auto, prefers discrete GPUs over integrated)
- `IRIUM_GPU_DEVICE` — OpenCL device index within selected platform (default: 0)
- `IRIUM_GPU_DEVICES` — Comma-separated device indices (overrides single device)
- `IRIUM_GPU_BATCH` — Nonces per GPU dispatch (default: 4,194,304 = 2²²)

Platform enumeration is available via `irium-miner-gpu --list-platforms`, which
prints all detected OpenCL platforms and their devices.

### Stratum Pool Mining

The GPU miner includes a Stratum v1 client for pool-based mining. When
`IRIUM_STRATUM_URL` is set to a `stratum+tcp://` or `stratum://` URL, the miner
connects to the pool and mines against the pool's work assignment rather than
a local node.

Stratum configuration:
- `IRIUM_STRATUM_URL` — pool endpoint
- `IRIUM_STRATUM_USER` — pool username (defaults to mining address)
- `IRIUM_STRATUM_PASS` — pool password

**Official public pool** (`pool.iriumlabs.org`):

| Profile | Endpoint | Default share difficulty | Worker name |
|---------|----------|--------------------------|-------------|
| ASIC / strict | `stratum+tcp://pool.iriumlabs.org:3333` | 16 (vardiff 1–2048) | your `Q…` payout address |
| CPU / GPU / legacy | `stratum+tcp://pool.iriumlabs.org:3335` | 1 (vardiff 1–1024) | your `Q…` payout address |
| Firewall bypass (sslh-multiplexed) | `stratum+tcp://pool.iriumlabs.org:443` | Same as ASIC | your `Q…` payout address |
| Solo (full 50 IRM coinbase to block finder, 0% pool fee) | `stratum+tcp://pool.iriumlabs.org:3336` | 10000 (vardiff capped) | your `Q…` payout address |

The pool runs the `irium-stratum` daemon from this repository
(`pool/irium-stratum/`) split into two systemd units (`irium-stratum.service`
ASIC, `irium-stratum-legacy.service` CPU/GPU) so vardiff bounds and default
difficulty can be tuned independently per hardware class. The pool operator's
runbook is in `docs/POOL-OPERATOR.md`.

**Public pool stats** are served on `:3337` as JSON
(`http://pool.iriumlabs.org:3337/stats`) by a small Python proxy on the pool
host. The proxy scrapes both loopback `/metrics` endpoints, combines them, and
emits a per-profile rolling-window hashrate estimate
(`(Δ accepted_shares × default_difficulty × 2³²) / Δ seconds`) along with the
window length and a confidence level. The proxy is CORS-enabled so any web
explorer or wallet UI can render the data directly.

Pool operators can use `irium-miner-gpu` as a reference for the client protocol.
Full pool operator setup instructions are documented in `docs/POOL-OPERATOR.md`
and `docs/POOL_STRATUM.md`.

### AuxPoW Merged Mining for Pools

After block 26,347, pool operators can offer merged mining. A Bitcoin pool that
includes the Irium commitment in coinbase outputs allows Bitcoin miners to
simultaneously earn IRM rewards without any additional hashing — the same
SHA-256d work satisfies both chains. The `docs/MERGED-MINING.md` document
covers setup for pool operators integrating AuxPoW.

---

## 16. Security Properties

### No Admin Keys

There are no privileged key pairs in the Irium protocol with special powers.
No address can freeze funds, reverse transactions, modify difficulty, or change
consensus rules. The codebase contains no `admin_key`, `freeze`, or `governance`
mechanism beyond normal consensus.

### No Unlocked Premine

No freely spendable coins exist at the genesis block. The 3,500,000 IRM genesis
allocation is locked with on-chain CLTV timelocks (`founder_vesting_cltv` in
`configs/genesis.json`). All IRM in free circulation must be earned through
proof of work. The founding team's allocation cannot be moved without satisfying
the on-chain time conditions.

### Deterministic Policy Evaluation

Settlement policy evaluation is a pure function: agreement + proofs + height →
outcome. The result is identical on every node, in every execution, with no
external inputs. There is no runtime state for an attacker to manipulate.

### Proof Finality Depth

The configurable `IRIUM_PROOF_FINALITY_DEPTH` (default: 6 blocks) prevents
release eligibility from being granted based on proofs that could be reorganized
out of the chain. Parties who observe `proof_final: false` should not release
funds or ship goods.

### Reorg Protection

The node tracks the chain depth of every submitted proof. On a reorg, proof
heights are re-evaluated against the new canonical chain. Proofs in reorganized
blocks lose their depth count and emit `agreement.proof_reorged` events.
This prevents an attacker from submitting a proof in a block they privately
mine and then reorganizing it away after receiving goods.

### Decentralization

No hardcoded peer IP addresses appear in any source file other than
`bootstrap/seedlist.txt` and `configs/node.json`. All ports are configurable via
environment variables. No DNS lookups are required for operation. The three-layer
bootstrap system (gossip cache, signed seedlist, blockchain-embedded peer
announcements) ensures nodes can discover peers and rejoin the network without
any DNS infrastructure or centrally operated seed servers.

### Open Source

Irium is released under the MIT licence. The complete source code is available
at [github.com/iriumlabs/irium](https://github.com/iriumlabs/irium). The build
is reproducible from source using `cargo build --release`.

### Network Era Model

The node software tracks three eras based on block height (`src/network_era.rs`):

| Era | Block range | Description |
|---|---|---|
| Early Miner Era | 0 – 25,000 | Bootstrap phase, early participants shaping the network |
| Growth Era | 25,001 – 100,000 | Expanding beyond bootstrap, growing infrastructure |
| Mature Network Era | 100,001+ | Established history and infrastructure |

Era information is included in the `/status` RPC response and can be used by
applications to communicate network maturity context to users.

### Validated Continuous Integration

All Rust code is covered by a test suite of 126 tests (`cargo test`) covering:
- Consensus rule enforcement
- Settlement policy evaluation (all outcome states)
- Proof lifecycle and signature verification
- Difficulty algorithm calculations
- AuxPoW validation
- P2P protocol message serialization
- Reputation signal calculation
- Key derivation (custom scheme and BIP32)
- Multisig address encoding/decoding
- Attestor bond slashing logic
- ECIES encryption/decryption round-trip

Tests are run in CI on every push to the testing branch. No merge to main
proceeds without a clean test run.

---

## 17. Roadmap

### Live Today

| Feature | Status |
|---|---|
| SHA-256d PoW base chain | Live — block ~22,000+ |
| LWMA v2 difficulty (N=30) | Live since block 19,740 |
| HTLCv1 settlement outputs | Live since block 18,677 |
| Settlement layer (agreements) | Live |
| Proof automation engine | Live |
| Three proof templates | Live |
| Attestor bonding mechanism | Live |
| Decentralized marketplace | Live |
| P2P offer feed discovery | Live |
| Reputation system | Live |
| Merchant tools (invoices, dashboards) | Live |
| Public block-explorer endpoints (incl. rich list at `/rpc/richlist`) | Live since v1.9.17 |
| Official public mining pool (CPU/GPU and ASIC profiles) | Live |
| Public pool stats proxy with rolling-window hashrate | Live |
| REST API | Live |
| WebSocket streaming API | Live |
| Server-Sent Events fallback | Live |
| BIP32/BIP39 HD key derivation | Live |
| 2-of-2 and 2-of-3 multisig | Live |
| Private agreement off-chain storage | Live |
| ECIES selective disclosure | Live |
| Proof finality depth and reorg protection | Live |
| Settlement-aware block explorer | Live |
| Desktop wallet (`irium-core`) | Shipping (Tauri-based; bundled iriumd, miner, GPU miner) |
| CPU miner (`irium-miner`) | Live |
| GPU miner (`irium-miner-gpu`) | Live (NVIDIA / AMD prioritised over Intel iGPU, since v1.9.18) |
| Stratum pool mining | Live |
| Python SDK | Live |
| JavaScript/TypeScript SDK | Live |
| Three-layer DNS-free bootstrap (gossip, signed seedlist, blockchain-embedded) | Live |
| Blockchain-embedded peer discovery (`IRIUM_ADVERTISE_ADDR`) | Live |
| P2P handshake-level external endpoint advertisement (`IRIUM_EXTERNAL_ENDPOINT`, CGNAT escape) | On `testing-codes-before-merging`, scheduled v1.9.19 |
| Runtime peer injection (`--add-seed` flag, `POST /admin/add-seed` RPC) | Live |
| AuxPoW merged mining | Activating at block 26,347 |

### In Development

- **Desktop wallet (`irium-core`)** — a Tauri-based native wallet wrapping the
  full settlement + marketplace + miner stack (CPU + GPU + Stratum pool client).
  Currently shipping on `testing-codes-before-merging`; bundled iriumd binary,
  rich-list explorer, pool stats tab, and the multi-locale UI (15 languages)
  are all live.
- **Web wallet** — a browser-based interface for marketplace browsing, agreement
  creation, and proof submission.
- **Mobile wallet** — iOS and Android applications with QR code payment flows,
  push notifications for settlement events, and hardware wallet pairing.
- **Additional proof templates** — expanding the three current templates to cover
  more commercial categories (escrow, real estate, insurance claims).

### Parked

- **Exchange and cross-chain swaps** — atomic swap readiness analysis is complete
  (documented in `docs/atomic_swaps.md`), but active development is deferred.
- **MPSOv1** — multi-party settlement output version 1 is activated at block 20,000
  but not yet exposed through the wallet CLI pending further review.
- **On-chain governance** — no governance mechanism is planned for the current phase;
  parameter changes require node software upgrades.

---

## 18. Conclusion

Irium is a proof-of-work blockchain that makes trustless commercial settlement
accessible without smart contract programming, custodians, or trust in intermediaries.
The settlement layer expresses common commercial patterns — bilateral trades,
service contracts, milestone payments — as deterministic protocol primitives
evaluated identically by every node in the network.

The proof automation engine brings real-world evidence into the blockchain context
through cryptographically signed attestations, three standardized proof templates,
and an economic bonding mechanism that holds attestors accountable for their
assertions. The decentralized marketplace enables offer discovery through the
existing P2P layer without any DNS or central directory. The reputation system
derives objective trust signals from agreement outcomes, giving counterparties
a verifiable track record rather than a self-reported one.

All of this operates on a SHA-256d proof-of-work foundation that allows Irium to
leverage the existing Bitcoin mining ecosystem — initially through standalone mining,
and from block 26,347 onward through AuxPoW merged mining. The economic model
scales Bitcoin's halving curve to Irium's parameters: 50 IRM per block, halving every
1,050,000 blocks (~4 years at the V2 2-minute target), converging to 96.5M IRM from
block rewards plus 3.5M IRM from the genesis CLTV vesting allocation — a fixed
100,000,000 IRM total supply enforced by the `MAX_MONEY` consensus cap.

Irium is designed to be a durable layer for commercial trust on the internet —
censorship-resistant, deterministic, and verifiable without requiring any party
to trust anyone they have not chosen to trust.

---

*Irium Whitepaper Version 2.0 — May 2026*

*Every technical claim in this document has been verified against the live Irium
source code. Source file references are provided inline. The current mainnet genesis
hash is `0000000028f25d65557e9d8d9e991f516c00d68f5aeae10b750645b398bd10a3`
(block 0, timestamp 2026-01-05 03:32:10 UTC).*
