# Changelog

All notable changes to Irium are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.9.154] - 2026-07-30

Node fix. **Not a consensus change** — adds template fields only.

### Added

- **`getblocktemplate` now tells external builders the PoW-demotion floor.** The Stratum pool was
  asking miners for the full network target (difficulty **1,721,700**, ~7.4e15 hashes) for a block the
  chain accepts at the **20-bit floor** (~1e6 hashes) from an eligible proposer — roughly **7 billion
  times more work than required**, which is why no pool share ever became a block. The pool cannot
  work this out for itself: it has no view of the demotion activation height or the frozen proposer
  registry. Three new fields:
  - `poawx_demotion_available` — demotion is in force at this height,
  - `poawx_job_bits` — compact bits of the floor, same `{:08x}` encoding as `bits`,
  - `poawx_job_target` — the floor as a 256-bit target hex, same encoding as `target`.

  The header must still **declare** `bits`; only the threshold a share must beat changes. Mirrors the
  validator exactly, which sets `pow_target = floor_target(anti_spam_bits)` — it *replaces* the
  network target rather than taking a max, so adopting the floor is correct even where the floor is
  the harder of the two (devnet).

  Deliberately **not** gated on `poawx_proposer_eligible_count > 0`: with an empty registry
  `check_block_proposer` skips the eligibility test and `proposer_threshold(0, _)` is permissive, so
  demotion applies *more* readily then — gating on a non-empty registry would wrongly report
  "unavailable" during bootstrap.

  Not derived from `poawx_effective_sybil_bits`, which is `poawx_ticket::effective_sybil_bits()` — the
  *ticket* sybil constant that merely happens to equal 20 on mainnet today. Coupling to that
  coincidence is how the difficulty freeze ended up silently inert. A regression test pins that the
  floor is ~1e9+ times easier than the frozen target.

## [1.9.153] - 2026-07-30

Node fix. **Not a consensus change** — no activation height, no fork. It only stops a node from
discarding its own valid block.

### Fixed

- **A node threw away its own better-ranked block, so fork choice never saw it.** Both miners wake
  at `parent + 120s`; whichever finishes building first submits and its block propagates. The other
  node accepted that block, advanced its tip, and then rejected *its own* block for the now-previous
  height: `[submit_block_extended] reject height_mismatch req=64482 chain=64483`. Because fork choice
  can only rank blocks that **exist**, `proposer_rank_chain_better` never got to prefer the
  better-ranked one — so the height went to whichever node built faster, a latency race, which is
  precisely the advantage PoAW-X removes hashrate in order to avoid. Measured live on 2026-07-30: the
  lower-ranked key lost heights it should have won.

  `submit_block_extended` now admits a **sibling of the current tip** via `process_block` — the same
  fork path P2P blocks already take, with full validation against the block's real parent — and lets
  fork choice decide. The local submit path had been *stricter* than the P2P path, which already
  accepts an equal-height block and reorgs on rank; this makes them consistent. It admits no block a
  peer could not already have delivered, which is why it needs no activation height.

  Bounded to exactly one height below the tip (`submit_block_routing`), so old heights cannot be
  pushed through the submit endpoint. The response tip is now read from the chain rather than from the
  submitted header, so a miner whose sibling loses fork choice is no longer told it won.

## [1.9.152] - 2026-07-30

Consensus release. **Hard fork at height 64,465.** A node on an older binary does not apply the
minimum block spacing and will accept blocks this build rejects, so it forks at the first
too-early block after 64,465.

### Fixed

- **Block spacing is now bounded. Mainnet was emitting 2.48x too fast.** Under PoW demotion
  nothing governed how quickly blocks could be produced: an eligible proposer validates against
  the constant 20-bit anti-spam floor rather than the header target (and since 64,291 the target
  is frozen outright), so difficulty had no rate authority — and `min_time_for_round(parent, 0, iv)`
  returned `parent_time`, i.e. round 0 opened the instant the parent landed, with no minimum gap.
  Measured over 956 consecutive-height gaps: **mean spacing 48.4s against the 120s
  `BLOCK_TARGET_INTERVAL_V2` target**, with 65% of blocks landing a mean 8.9s after their parent
  and the other 35% waiting ~123s only because neither node passed round-0 sortition. That emitted
  **89,334 IRM/day against a designed 36,000** and pulled the first post-fork halving in from
  ~3.99 years to ~1.61. `validate_block_header` now refuses a block whose timestamp is below
  `parent_time + min_block_spacing_secs()`; the rule reads only the parent's recorded timestamp,
  never a local clock, so every node reaches the same verdict.

  Sortition is deliberately preserved. The floor equals `DEFAULT_PROPOSER_ROUND_INTERVAL_SECS`, so
  at the earliest permitted moment round 1 is open too — and because `block_proposer_rank` is
  `(round, priority)`, a round-0 winner's `(0, _)` still beats every `(1, _)` in fork choice. What
  the floor removes is the advantage that had nothing to do with the VRF: at a 9s gap the winner
  was whichever node refreshed its template first, i.e. the one with lower network latency.

- **Test-suite env race.** `bootstrap_materialisation_includes_the_signer_set` and
  `runtime_seed_count_is_distinct_hosts_not_file_lines` both drive the process-global
  `IRIUM_BOOTSTRAP_DIR`, so one test's `remove_var` landed inside the other's set/read window and
  the first failed in the full suite while passing in isolation. Both now take a shared lock.

### Added

- `getblocktemplate` publishes `poawx_min_block_time`, the earliest header time the block may
  carry. `time` is also clamped up to it, so a stale miner or the Stratum pool — which copy the
  template's time verbatim — keep producing valid blocks even when only the node is upgraded. An
  updated `irium-miner` additionally sleeps until that instant, so timestamps track wall clock
  instead of drifting into the future.

### Note

One-role-per-identity exclusivity (`MAINNET_EXCLUSIVE_ROLE_ACTIVATION_HEIGHT`) remains `None` and
is **not** armed here. It is an independent hard fork with no effect at two participants, and
bundling two consensus activations is what produced the 2026-07-23 halt.

## [Unreleased]

### Fixed

- OTC agreement direction: `build_otc_agreement` now wires `payer = seller_id` and `payee = buyer_id`, with `refund_address = seller.address` and `release_authorizer = "seller"`. The seller funds the on-chain HTLC escrow; the buyer pays off-chain and receives IRM on release; the seller reclaims via the timeout refund path if no release happens. This corrects a long-standing inversion in the builder where the buyer was placed in the payer slot, which contradicted the actual flow and `docs/SETTLEMENT-DEV.md`.
- iriumd `/rpc/agreementreleaseeligibility` and `/rpc/agreementrefundeligibility` (via `evaluate_agreement_spend_eligibility`) now hash the supplied secret preimage with single SHA256 to match the consensus HTLC script (`HTLC_V1_HASHALG_SHA256 = 1`) and `chain.rs`. Previously the advisory check used double SHA256 and falsely reported `secret_hash_mismatch` for valid preimages, blocking release.

### Changed

- `agreement-fund` (wallet) refuses OTC agreements whose payer party has role `"buyer"` (legacy direction) with a clear error message directing the user to create a new agreement. No on-chain HTLCs are affected; this is a wallet-side rejection only.

## [1.9.149] - 2026-07-29

Consensus release. **Hard fork at height 64,291.** A node on an older binary computes a
different required target and forks at exactly that height.

### Fixed

- **The demotion difficulty freeze now actually applies.** It was armed at height 63,824 but
  never fired: `demotion_frozen_target` gated correctly on a const-controlled activation, then
  resolved its baseline through `pow_demotion_activation_height()` — an accessor that reads only
  an environment variable which mainnet deliberately ignores. It returned `None`, the function
  silently gave up, and nothing was logged. Meanwhile the declared network target ran away from
  **1.72e6 at height 61,413 to ~9.7e56 by 64,290**, compounding. New
  `pow_demotion_effective_activation()` resolves the activation the same const-vs-env way the
  gate decides. **Activated at 64,291**, holding the target at the value in force immediately
  before demotion began (height 61,413, difficulty **1,721,700**, bits `1a09be94`).
- **Hashrate is derived from work actually proved, not from the declared target.**
  `/rpc/mining_metrics`, `/rpc/network_hashrate` and `/rpc/network_status` computed
  `declared_difficulty * 2^32 / avg_block_time`, which under demotion is meaningless — demoted
  blocks satisfy only the anti-spam floor. `/api/pool/stats` was reporting **~3.3e59 H/s**, more
  than any hardware in existence could produce. Now ~1.5e4 H/s, which matches two CPU miners.
- `require_rpc_auth` now fails **closed**: an unset or empty `IRIUM_RPC_TOKEN` previously
  authorised every token-guarded endpoint, including `POST /admin/add-seed`. Set
  `IRIUM_RPC_ALLOW_NO_AUTH=1` to deliberately run an isolated node without credentials.
- P2P gossip and the HTTP enrollment surface no longer share one per-IP rate-limit budget.
  Continuous peer gossip consumed the whole allowance, so role workers on the same IP were
  answered `429` and every block self-filled instead of paying its four role participants.

### Added

- `difficulty_demonstrated` on `/rpc/mining_metrics` — the difficulty actually being solved, as
  distinct from the declared target. `difficulty` continues to report the declared value.

## [Consensus activations on mainnet since 1.1.0]

The 1.1.0 notes below describe the chain as originally launched. Several parameters and rules
have since changed by activation height. Current behaviour:

- **Block interval is 120 seconds, not 600** — `BLOCK_TARGET_INTERVAL_V2` takes effect at height
  **24,250**. The halving interval expands 5× at the same fork
  (`HALVING_INTERVAL_V2 = 1,050,000`, from 210,000) so the emission calendar stays roughly four
  years per halving. Total supply is unchanged.
- **PoAW-X activated at height 50,000.** Every block from that height carries deterministic role
  receipts committed to the coinbase via an `irx1` `OP_RETURN`, plus proposer-VRF, registration,
  anti-domination, puzzle, finality-committee and candidate-admission validation.
- **Non-exclusive proposer eligibility at height 59,900**, closing a lockout in which only the
  incumbent producer's key could propose.
- **PoW demotion active at height 61,414.** A validly-selected proposer's block is checked
  against a constant anti-spam floor instead of the full network target, so block production is
  hardware-independent. In practice ASIC hashrate no longer wins mainnet blocks — see the mining
  note in `README.md`.
- **Difficulty-demotion freeze at height 64,291** (this release).

## [1.1.0] - 2026-05-01

This release documents everything built across Phases A–F of the Irium chain
upgrade and marks the first official tagged release of the codebase.

### Added

**Core chain**
- SHA-256d proof-of-work consensus — fully compatible with Bitcoin ASIC hardware and merged mining
- P2PKH address scheme with custom version byte; IRM addresses begin with `I`
- Block reward of 50 IRM per block, halving every 210,000 blocks; maximum supply 100,000,000 IRM
- 600-second target block interval, difficulty retarget every 2,016 blocks
- COINBASE_MATURITY of 100 blocks before coinbase outputs are spendable
- Genesis block locked and immutable in `configs/genesis-locked.json`
- LWMA (Linearly Weighted Moving Average) difficulty algorithm, window N=60, active from mainnet height 16,462
- LWMA v2 with reduced window (N=30) and larger solvetime clamp (10×T) for faster post-hashrate-collapse recovery, active from mainnet height 19,740
- HTLCv1 (Hash Time-Locked Contracts v1) active from mainnet height 18,677
- All activation heights configurable via environment variable overrides for testnet and devnet

**Settlement layer**
- Offer creation, listing, filtering, sorting, and ranked display via CLI and REST API
- Agreement formation: offer-take locks both parties into a verifiable on-chain agreement object
- Three built-in policy templates: basic OTC escrow, contractor milestone, preorder deposit
- Proof submission against active agreements with configurable policy evaluation
- Full agreement lifecycle: offer → agreement → funded → proof submitted → released or expired
- Agreement anchor outputs embedded in chain transactions for independent on-chain verifiability
- Agreement audit trail with full timestamped activity timeline and linked transaction references
- Timelock-enforced refund paths when agreements expire without a valid proof
- Settlement receipt export in plain text and HTML
- `POST /rpc/submitproof` — submit a proof against an active agreement
- `POST /rpc/sendtx` — broadcast a signed raw transaction
- `GET /api/offers` — list offers with filter and sort support
- `POST /api/offers` — create a new offer
- `POST /api/agreements` — take an offer and form an agreement
- `GET /api/agreements/:id` — query agreement status and full detail
- `POST /api/proofs` — submit a proof via REST
- `GET /offers/feed` — public unauthenticated offer feed for cross-node discovery

**Reputation system**
- Per-seller trust scoring derived entirely from on-chain agreement history
- Recency weighting: outcomes from the past 30 days carry more weight than older history
- Sybil resistance: new identities begin with a lower trust ceiling until outcome history accumulates
- Dispute rate, late-proof rate, and default tracking as explicit risk signals
- Reputation portability: scores follow the seller public key, not a centralised account
- `GET /api/reputation/:pubkey` — query reputation and risk signals for any public key
- Offer ranking score computed from seller reputation, surfaced in `offer-list` output

**P2P marketplace discovery**
- Multi-source offer feed aggregation: nodes pull, validate, and merge feeds from configured sources
- Feed registry commands: `feed-add`, `feed-remove`, `feed-list`, `feed-bootstrap`
- Feed validation: response size cap, malformed-entry rejection, health status output
- Feed pruning command to remove stale entries and reclaim space
- Peer-to-peer proof gossip: submitted proofs propagate to all connected nodes
- Proof templates for common escrow patterns with variable substitution
- Attestor discovery: nodes advertise willingness to act as third-party proof witnesses

**Wallet CLI (`irium-wallet`)**
- Key generation, import, and encrypted wallet store backup
- Balance and UTXO queries against a live node
- Transaction construction, signing, and broadcast
- Offer commands: `offer-create`, `offer-list`, `offer-show`, `offer-take`, `offer-export`
- Agreement commands: `agreement-pack`, `agreement-unpack`, `agreement-show`
- Proof commands: `proof-build`, `proof-submit`
- Reputation command: `reputation-show` with full risk signal breakdown
- Feed commands: `feed-add`, `feed-remove`, `feed-list`, `feed-fetch`, `feed-bootstrap`
- Policy commands: `policy-build-otc`, `raw-policy`
- Guided OTC demo flow: `flow-otc-demo`
- Settlement receipt export: `receipt-export` outputs text and HTML
- Phase 4 Rust integration layer: wallet reads UTXO set and broadcasts directly against node state
- Human-readable timestamps on all agreement and proof outputs
- Next-step hints after each command guide users through the complete flow

**Miners**
- CPU miner (`irium-miner`) with configurable address, RPC endpoint, and thread count
- GPU miner (`irium-miner-gpu`) using OpenCL; enumerates available platforms and devices at startup
- GPU miner degrades gracefully to a clear error when no OpenCL platform is found (`--list-platforms`)
- Miner coinbase address validation: refuses to mine without a valid, funded payout address
- LWMA v2 activation-boundary detection in miner prevents stale `bits` mismatch at activation height

**Node daemon (`iriumd`)**
- Full node with persistent block storage and state recovery across restarts
- P2P peer discovery via signed seedlist in `bootstrap/seedlist.txt`
- Bootstrap trust framework: anchor signers verified against `bootstrap/trust/allowed_anchor_signers`
- Rate limiter on all RPC and P2P endpoints to resist abuse
- CORS headers on all HTTP endpoints for browser-based tooling
- TLS support via rustls with opt-in configuration
- Network era display on startup (currently: Early Miner Era)
- All ports and addresses configurable via environment variables — no hardcoded values in source

**SPV client (`irium-spv`)**
- Lightweight client for balance and transaction queries without downloading full block history

**Wallet API server (`irium-wallet-api`)**
- HTTP server exposing settlement, balance, and transaction endpoints for wallet front-ends

**Infrastructure**
- systemd unit files for `iriumd`, `irium-miner`, `irium-explorer`, `irium-wallet-api`
- Environment variable templates for all services in `systemd/*.env.example`
- Rust SDK stub in `sdk/` as the integration surface for third-party applications
- Business templates for invoice generation, seller status, and buyer status flows

### Fixed

- Late-proof vulnerability: proofs submitted after the agreement deadline are now rejected
- LWMA v2 boundary edge case in miner causing incorrect `bits` value on the activation block
- Offer ID path traversal: IDs validated to alphanumeric characters, hyphens, and underscores only on both read and write paths
- Reputation pubkey resolution for 66-character compressed pubkeys (was silently returning no data)
- `offer-list` default sort order restored to newest-first after offer ranking refactor changed it
- `ring` CryptoProvider not being installed before TLS initialisation in `iriumd`
- HTTP RPC scheme defaulting to the wrong protocol in wallet CLI

### Security

- All source files audited and cleaned of hardcoded IP addresses and port numbers
- Miner coinbase address validation hardened; empty-script fallback removed entirely
- Offer ID write-path and read-path validation hardened against path traversal attacks
- Dependency update: `rustls-webpki` DoS vulnerability patched (Dependabot advisory)
- Cleartext session data logging removed from all log paths
- XSS vulnerability in explorer output sanitised
