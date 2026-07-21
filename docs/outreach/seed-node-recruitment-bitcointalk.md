# Seed Node Recruitment — Bitcointalk Post

---

**[ANN] Irium (IRM) — Seeking Community Seed Node Operators**

---

**About Irium**

Irium is a live SHA-256d proof-of-work blockchain with a built-in settlement layer. No premine. No admin keys. MIT licence.

AuxPoW merged mining activates at block 26,347 (~June 2026). Full chain info: https://github.com/iriumlabs/irium/blob/main/docs/LISTING-APPLICATION.md

---

**We Need Community Seed Nodes**

The Irium network currently bootstraps from 2 seed nodes operated by Irium Labs. This is a centralisation risk. We are expanding the official signed seedlist to at least 6 community-operated nodes.

A seed node is a standard iriumd instance with its P2P port (38291) open to the internet. No special software, no mining required.

**Minimum requirements:**
- 1 CPU core, 1 GB RAM, 20 GB disk, 10 Mbps upload
- Static publicly reachable IP
- Port 38291 open TCP
- 95%+ monthly uptime

**How to run:**
```
git clone https://github.com/iriumlabs/irium.git
cd irium
cargo build --release --bin iriumd
```

Full seed node guide: https://github.com/iriumlabs/irium/blob/main/docs/SEED-NODE.md

**How the seedlist works:**

`bootstrap/seedlist.txt` is signed with an SSH Ed25519 key. Each node verifies the signature on startup. Anyone can independently verify the signature:

```
ssh-keygen -Y verify \
  -f bootstrap/trust/allowed_signers \
  -I bootstrap-signer \
  -n file \
  -s bootstrap/seedlist.txt.sig \
  < bootstrap/seedlist.txt
```

Only verified community nodes with confirmed uptime are added.

**To apply:**
- Reply to this thread with your IP and port
- Or open a GitHub Issue: https://github.com/iriumlabs/irium/issues
- Or message on Telegram: https://t.me/iriumlabs

---

**Links**
- GitHub: https://github.com/iriumlabs/irium
- Website: https://www.irium.org
- Network status: https://www.irium.org/status/
- Seed node guide: https://github.com/iriumlabs/irium/blob/main/docs/SEED-NODE.md
- Telegram: https://t.me/iriumlabs

---
*Ibrahim posts this manually. Do not post directly.*
