# Getting Paid Directly: One-Time Pool Setup for Irium Miners

> **Status:** the tooling below is built and tested against isolated test environments.
> **Full live end-to-end testing against a production pool is still pending** (the pool
> infrastructure is being stood up). This guide describes accurately *how it works*; it does
> not claim it has been exercised against the live pool yet. Command names and syntax are
> final.

## The short version

Irium's pool can pay your mining rewards **straight to your own wallet address, on the
blockchain**, instead of only tracking them off-chain. Turning this on is a **one-time step**
you do once from your wallet — then you go back to mining exactly as you do today.

**You do not have to do this.** If you skip it, nothing changes: you keep getting paid the
same fair way you're paid now, through the pool's existing tracking. This is purely an upgrade
for miners who want their rewards paid directly to their own address on-chain.

---

## Why is a one-time step even needed?

Irium uses a mining system called **PoAW-X**. Alongside the normal hashing your ASIC does, the
network requires a small cryptographic **"proof of eligibility"** (a VRF proof) to accompany
each block, proving *who* is allowed to produce it. **ASIC miners physically cannot produce
that proof** — they're purpose-built to hash, and nothing else.

So the pool performs that proving step **on your behalf**. But for the blockchain to then pay
a reward **directly to your address**, it needs your permission — a one-time note, signed by
your wallet, that says:

> "I authorise this pool to do the eligibility proving for me, and to pay my share to **my**
> address."

That signed note is called a **delegation**. You create it once. After that, the pool can pay
you directly on-chain, block after block, with no further action from you. It's like setting up
direct deposit: sign one form once, and your pay lands in your account automatically.

---

## What changes after you sign up — and what stays the same

**What changes (the upside):**
- Your **PRIMARY mining reward is paid directly to your own wallet address, on-chain**, in the
  blocks you help produce — yours immediately, verifiable on the block explorer.

**What stays exactly the same:**
- You **still just point your ASIC at the pool and mine normally.** No new mining software, no
  miner config changes, no change to how you connect.
- The pool still does all the PoAW-X proving for you.
- Your hardware, hashrate, and electricity — all unchanged.

**If you do NOT sign up:**
- **Nothing breaks and nothing is lost.** You keep being paid the same way you are today — the
  pool tracks your fair share by the work your miner submits and pays you through its existing
  process. You are not penalised or excluded; you mine exactly as before.

---

## How to sign up

Two ways — pick whichever you're comfortable with. Both do the same thing.

### Method A — Command line (`irium-wallet`)

**Sign up (one command):**

```
irium-wallet delegate-pool <your-wallet-address> \
    --pool <pool-delegation-url> \
    --worker <your-worker-name> \
    --expiry-height <height>
```

- It fetches the pool's identity (the pool's keys, including the custodial proposer key),
  signs a delegation with **your wallet key** (which never leaves your machine), and submits it.
- On success it prints a confirmation **and your `deleg_nonce`** — **save that value**; you
  need it if you ever want to revoke (see below).

**Offline variant** (air-gapped wallet; the operator supplies the pool's public keys and
submits the result for you):

```
irium-wallet delegate-pool <your-wallet-address> --emit-only \
    --pool-pubkey <66-hex> --proposer-pubkey <66-hex> --network-id <id> \
    --worker <name> --expiry-height <height>
```

This prints a JSON payload (public data only — never your private key) to hand to the operator.

**Check your delegation status** (are you delegated, to which worker, expiry, nonce):
the app surfaces this; the pool exposes it at `GET /poawx/delegation-status?miner_pkh=<pkh>`.

**Check your proposer status** (only relevant if you mine solo, not via the pool):
`GET /poawx/proposer-status?pkh=<pkh>` reports whether your key is registered and eligible.

### Method B — Irium Core app

> The app controls exist and are wired to the real commands, but the **visual design is still a
> functional stub** — polish is pending. The flow works; it just isn't styled yet.

1. Open Irium Core and **unlock your wallet** (the same unlock you already use).
2. Enter your **wallet address** and the **pool delegation URL**, then click
   **"Enable direct pool rewards"**.
3. You'll see a confirmation including your `deleg_nonce` (save it).
4. **"Check delegation status"** shows whether you're delegated; **"Check proposer status"**
   shows solo-proposer registration. Done — go mine as normal.

---

## Undoing it (revocation)

You can cancel a delegation. **Important:** revocation is currently **on-chain only** — it is
**not instant** like signup. You generate a signed revocation and **hand it to the pool
operator**, who embeds it on-chain; it takes effect once included in a block.

**CLI:**
```
irium-wallet revoke-delegation --addr <your-wallet-address> \
    --deleg-nonce <the-nonce-from-signup> --network-id <id>
```
This prints a signed revocation hex — give it to the operator. In the app, the **"Generate
revocation"** button does the same (generate-and-hand-off). After it's on-chain, the network
stops paying you delegated rewards and you fall back to the pool's off-chain fair tracking.

---

## Frequently asked questions

**Do I have to do this?**
No. It's completely optional. Skip it and you're paid exactly as you are today.

**What happens if I don't?**
Nothing changes. The pool keeps tracking your fair share by the work your miner submits and
pays you through its existing process. Nothing is lost, nothing breaks.

**Is this safe? What does the signature actually authorise?**
The one-time signature authorises the pool to do the PoAW-X eligibility proving on your behalf
and to direct your PRIMARY reward to the address you chose. It does **not** give the pool
access to your wallet, your coins, or your private keys, and it **cannot** spend or move your
funds — it only names *where* the network pays your mining reward. Your signing key never
leaves your wallet; only public data and a signature are sent.

**Can I undo it?**
Yes — with a revocation (see above). Note it is on-chain only right now, so it takes effect
when the operator includes it in a block, not instantly.

**Do I need to keep the app or CLI running?**
No. Signup is a one-time action. Afterward you just mine normally; nothing needs to stay open.

---

## Known limitation (for reviewers)

The signup, status, revoke, and proposer-status paths have been built and tested against
**isolated test environments** (isolated node + pool harnesses, real HTTP round-trips, real
signed delegations/revocations). **The full live path — the Irium Core app talking to a real
production pool, with visual polish — has not yet been exercised end-to-end**, because the
production pool infrastructure (custodial proposer key registration, the live delegation
endpoint) is still being stood up. This guide describes the intended, built behaviour; the
final live verification will happen when that infrastructure is ready.
