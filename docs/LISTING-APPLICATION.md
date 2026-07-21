# Irium — Exchange and Pool Listing Application

This document is ready to copy and send to exchange listing teams, pool aggregator sites, and mining pool operators.

---

## Chain Specification

| Field | Value |
|-------|-------|
| **Full name** | Irium |
| **Ticker symbol** | IRM |
| **Algorithm** | SHA-256d (double SHA256, identical to Bitcoin) |
| **Consensus** | Proof of Work |
| **Block time target** | 600 seconds (10 minutes) |
| **Difficulty algorithm** | LWMA v2 (Linear Weighted Moving Average, 30-block window) |
| **Block header format** | Standard Bitcoin 80-byte header (+ AuxPoW extension when merged mining) |
| **Block reward** | 50 IRM |
| **Halving interval** | 210,000 blocks |
| **Max supply** | 100,000,000 IRM |
| **Coinbase maturity** | 100 blocks |
| **Min fee rate** | 1 sat/byte (~250 sat for a typical transaction) |
| **Address prefix** | Q (version byte 0x39, Base58Check) |
| **P2P port** | 38291 (configurable) |
| **RPC port** | 38300 (configurable) |
| **AuxPoW merged mining** | Activates at height 26,347 (~12 June 2026) |
| **Premine** | None |
| **Admin keys** | None |
| **Freeze/censor capability** | None |
| **Licence** | MIT |

## Supply Schedule

| Halving | Start block | Block reward | Cumulative supply |
|---------|-------------|--------------|-------------------|
| Era 0 | 1 | 50 IRM | 0 to 10,500,000 IRM |
| Era 1 | 210,001 | 25 IRM | 10,500,000 to 15,750,000 IRM |
| Era 2 | 420,001 | 12.5 IRM | 15,750,000 to 18,375,000 IRM |
| Era 3 | 630,001 | 6.25 IRM | 18,375,000 to 19,687,500 IRM |
| ... | ... | ... | ... |
| Terminal | ~1,930,000+ | ~0 | 100,000,000 IRM |

## Current Network State (as of May 2026)

| Metric | Value |
|--------|-------|
| Chain height | 20,299 |
| Genesis hash | `0000000028f25d65557e9d8d9e991f516c00d68f5aeae10b750645b398bd10a3` |
| Network era | Early Miner Era |
| Block reward | 50 IRM (first era; no halvings yet) |
| Connected peers | 5 |
| Circulating supply | ~1,014,950 IRM (height x 50 IRM) |

## What Is Live Today

- Fully operational mainnet running continuously since genesis
- Proof-of-work consensus enforced, chain secured by real hashrate
- Wallet CLI (`irium-wallet`) for address generation, sending, and receiving
- Settlement layer: HTLC-based escrow with offer/agreement/proof lifecycle
- Marketplace: on-chain OTC offer feed and agreement execution
- Reputation system: on-chain outcome tracking per seller pubkey
- REST API on every node: balance queries, block/tx lookup, mempool, offer feed
- Public Stratum pool: `pool.irium.org:3333` (ASIC), `:3335` (CPU/GPU)
- Docker images: `ghcr.io/iriumlabs/irium:latest`
- Pre-built release binaries: Linux x86_64/ARM64, macOS Intel/ARM, Windows

## Upcoming: AuxPoW Merged Mining

AuxPoW merged mining activates at block height 26,347 (estimated 12 June 2026). After activation, any SHA-256d pool mining Bitcoin can simultaneously mine Irium at zero additional energy cost by embedding the Irium block commitment in the parent coinbase transaction.

The full AuxPoW implementation is in the current codebase. See `docs/MERGED-MINING.md` for technical details.

## What Is on the Roadmap

- Desktop/web/mobile wallet applications (separate development track)
- Additional community mining pools
- Hardware wallet integration (after BIP44 coin type registration)

## Links

| Resource | URL |
|----------|-----|
| Website | https://www.irium.org |
| GitHub | https://github.com/iriumlabs/irium |
| Whitepaper | https://github.com/iriumlabs/irium/blob/main/docs/WHITEPAPER.md |
| Block explorer | https://www.irium.org/explorer |
| Public pool | https://www.irium.org/pool |
| Telegram | https://t.me/iriumlabs |
| RPC API reference | https://github.com/iriumlabs/irium/blob/main/docs/API.md |
| Wallet CLI reference | https://github.com/iriumlabs/irium/blob/main/docs/WALLET-CLI.md |
| Settlement dev guide | https://github.com/iriumlabs/irium/blob/main/docs/SETTLEMENT-DEV.md |
| Merged mining guide | https://github.com/iriumlabs/irium/blob/main/docs/MERGED-MINING.md |
| Pool operator guide | https://github.com/iriumlabs/irium/blob/main/docs/POOL-OPERATOR.md |
| Docker guide | https://github.com/iriumlabs/irium/blob/main/docs/DOCKER.md |
| Developer quickstart | https://github.com/iriumlabs/irium/blob/main/docs/DEVELOPER-QUICKSTART.md |

## Security Statement

- No premine. The genesis block coinbase is unspendable (standard null input, miner address holds nothing).
- No admin keys. No entity can freeze accounts, reverse transactions, or modify the chain.
- No freeze capability. No transaction censorship mechanism exists in the codebase.
- Open source. Full source code at https://github.com/iriumlabs/irium under the MIT licence.
- No venture capital. No foundation with allocation. No token sale.

## Integration Resources

**REST API:** Every `iriumd` node exposes a complete HTTP API for balance queries, transaction submission, block lookup, and settlement operations. See `docs/API.md`.

**Wallet integration:** Custom deterministic key derivation (SHA256-based, non-BIP32). Address format: Base58Check with version byte `0x39`. See `docs/KEY-DERIVATION.md` for the full derivation specification.

**Transaction format:** Standard Bitcoin transaction serialisation (version, inputs, outputs, locktime). P2PKH locking scripts. SHA256d transaction IDs.

**Mining integration:** Standard Bitcoin getblocktemplate protocol via `GET /rpc/getblocktemplate`. Submit blocks via `POST /rpc/submit_block`. SHA-256d algorithm, standard 80-byte header. AuxPoW blocks additionally include `auxpow_hex` field.

**Merged mining:** AuxPoW activates at height 26,347. Commitment magic: `0xfa 0xbe 0x6d 0x6d`. Version bit: `1 << 8`. Full protocol documented in `docs/MERGED-MINING.md`.

## Contact

For listing inquiries, technical integration questions, or partnership discussion:

- Telegram: https://t.me/iriumlabs
- GitHub Issues: https://github.com/iriumlabs/irium/issues
- Email: info@iriumlabs.org
