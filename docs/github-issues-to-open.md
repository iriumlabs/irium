# GitHub Issues to Open

These issues cover the remaining adoption roadmap. Open via `gh` CLI or manually on GitHub.

---

## Documentation and Accessibility

**Title:** Add binary downloads to README for non-developer users
**Labels:** documentation, good first issue
**Body:**
The README currently directs all users to install Rust and compile from source. Pre-built binaries are now available on GitHub Releases. Update README to lead with the binary download option and show the install.sh one-liner. Source build remains as a secondary option.

---

**Title:** Add plain-language FAQ to website and repository
**Labels:** documentation, good first issue
**Body:**
Many potential users do not have blockchain backgrounds. Add a non-technical FAQ covering: what Irium is for, how escrow works without a bank, what happens if something goes wrong, what it costs, and how to get started. Target audience: freelancers, contractors, small business owners.

---

**Title:** Add multilingual documentation (Mandarin, Spanish)
**Labels:** documentation, translation, good first issue
**Body:**
AI-generated translations of README.md and SETTLEMENT-EXAMPLE.md have been added to docs/translations/zh/ and docs/translations/es/. Native speaker review is needed for both. Corrections and improvements welcome via pull request.

---

## Developer Tools and Integration

**Title:** Publish irium-wallet as a standalone crate on crates.io
**Labels:** enhancement
**Body:**
The irium-wallet library code should be published as a standalone crate so developers can integrate Irium settlement into Rust applications without forking the full repo. This would enable third-party wallet implementations and settlement integrations.

---

**Title:** Add JavaScript/TypeScript SDK for settlement API
**Labels:** enhancement
**Body:**
A lightweight TypeScript SDK wrapping the iriumd HTTP API would make it significantly easier for web developers to integrate Irium settlement. Minimum viable scope: agreement creation, funding, status polling, and proof submission. This does not require any node changes.

---

**Title:** Publish official Docker images to GitHub Container Registry
**Labels:** enhancement
**Body:**
Docker images for iriumd and irium-miner are built in the GitHub Actions release pipeline but not yet confirmed published to ghcr.io/iriumlabs/irium. Confirm publication and add pull instructions to DOCKER.md and README.

---

## Mining and Pool Infrastructure

**Title:** List community mining pools on irium.org once operators apply
**Labels:** community
**Body:**
The pool operator guide (docs/POOL-OPERATOR.md) and recruitment outreach content are in place. Once community pool operators apply via Telegram or GitHub Issues, add verified pools to the mining page at irium.org/docs/mining/. Minimum requirements: public Stratum endpoint, at least one valid block submitted to mainnet.

---

**Title:** Add AuxPoW support notes to pool listing page
**Labels:** documentation
**Body:**
The mining page merged mining section mentions irium-stratum but does not yet link to a list of pools that have enabled AuxPoW support. Add a placeholder section that will be populated when pool operators confirm AuxPoW is active at height 26,347.

---

## Network Infrastructure

**Title:** Expand seed node list to minimum 6 community-operated nodes
**Labels:** community, infrastructure
**Body:**
The network currently bootstraps from 2 seed nodes operated by Irium Labs. Seed node recruitment outreach has been posted to Telegram and Bitcointalk. To apply, operators should reply with their IP and port. Ibrahim verifies each node is publicly reachable before adding to bootstrap/seedlist.txt. Target: 6 community nodes minimum.

---

## Exchange and Listing

**Title:** Submit listing application to TradeOgre
**Labels:** exchange-listing
**Body:**
docs/LISTING-APPLICATION.md contains a ready-made listing application package. Submit to TradeOgre via their listing request form. Include GitHub repo, whitepaper, chain spec, and API documentation links. This is a manual action for Ibrahim.

---

**Title:** Register BIP44 coin type for IRM
**Labels:** standards, documentation
**Body:**
docs/KEY-DERIVATION.md documents the derivation path currently used for IRM addresses. A formal BIP44 coin type registration pull request should be submitted to the bitcoin/bips repository. The document covers the required information. This is a manual action for Ibrahim. Prerequisite for hardware wallet integration.

---
