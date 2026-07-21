# Pool Operator Recruitment — Bitcointalk Post

---

**[ANN] Irium (IRM) — SHA-256d — AuxPoW Merged Mining Activating June 2026 — Seeking Pool Operators**

---

**About Irium**

Irium is a SHA-256d proof-of-work blockchain with a built-in settlement layer for trustless escrow agreements. The chain has been running continuously since genesis with real hashrate. No premine. No admin keys. MIT licence.

- Algorithm: SHA-256d
- Block time: 600 seconds
- Block reward: 50 IRM (halves every 210,000 blocks, same schedule as Bitcoin)
- Max supply: 100,000,000 IRM
- Current height: 20,299
- No premine. No admin keys. MIT licence.

Full chain spec: https://github.com/iriumlabs/irium/blob/main/docs/LISTING-APPLICATION.md

---

**AuxPoW Merged Mining — Activating Height 26,347**

Irium implements Namecoin-compatible AuxPoW merged mining. The activation is hardcoded at block height 26,347, estimated around 12 June 2026.

After activation:
- Any SHA-256d pool mining Bitcoin can simultaneously mine IRM
- No hardware or firmware changes required for miners
- The pool embeds an Irium block commitment in the Bitcoin coinbase
- When a share meets the Irium difficulty, an AuxPoW block is submitted to the Irium network
- Miners earn IRM block rewards on top of their existing Bitcoin earnings

This is the same Namecoin-style merged mining that major SHA-256d pools have supported for over a decade. The Irium-specific details are documented at:
https://github.com/iriumlabs/irium/blob/main/docs/MERGED-MINING.md

---

**Hardware Compatibility**

Every SHA-256d ASIC works:
- Antminer S19 / S21
- Whatsminer M50 / M60
- All Bitmain and MicroBT hardware
- Any SHA-256d USB miner
- Software miners (cpuminer-opt, CGMiner, BFGMiner)

---

**Stratum Server (Included)**

The Irium repository includes a complete Stratum V1 server at `pool/irium-stratum`. It handles both standard solo mining today and AuxPoW merged mining after activation. No third-party pool software required.

```bash
cd irium/pool/irium-stratum
cargo build --release
export IRIUM_RPC_BASE=http://localhost:38300
export IRIUM_RPC_TOKEN=your_token
export STRATUM_BIND=0.0.0.0:3333
export IRIUM_AUXPOW_ACTIVATION_HEIGHT=26347
./target/release/irium-stratum
```

All settings are environment variables. No hardcoded addresses or ports.

Pool operator guide: https://github.com/iriumlabs/irium/blob/main/docs/POOL-OPERATOR.md

---

**We Are Seeking Community Pool Operators**

If you operate a SHA-256d pool or have the infrastructure to run one, we want to list your pool on irium.org.

Requirements:
- Public Stratum endpoint, reachable and responding
- Fully-synced Irium node
- At least one valid block submitted to mainnet
- Published contact method

To register interest:
- Telegram: https://t.me/iriumlabs
- GitHub Issue: https://github.com/iriumlabs/irium/issues (title: "Pool listing request: [name]")

---

**Links**

- GitHub: https://github.com/iriumlabs/irium
- Website: https://www.irium.org
- Telegram: https://t.me/iriumlabs
- Pool operator guide: https://github.com/iriumlabs/irium/blob/main/docs/POOL-OPERATOR.md
- Merged mining guide: https://github.com/iriumlabs/irium/blob/main/docs/MERGED-MINING.md
- API docs: https://github.com/iriumlabs/irium/blob/main/docs/API.md

---
*Ibrahim posts this manually. Do not post directly.*
