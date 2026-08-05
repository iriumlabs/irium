# Join Irium mining

Everything below was verified against mainnet on 2026-08-05 at block ~66,540.

> **Ignore `MINING-QUICKSTART.txt` and the `mine-*.sh` / `mine-*.bat` scripts in the release
> archive.** They point at `stratum+tcp://pool.irium.org:3335`, which is shut down and refuses
> connections, and none of them pass `--poawx`, so they cannot produce a valid block. Use the
> commands on this page instead. Those files are being corrected in a later release.

## What mining Irium actually is

Irium does **not** award blocks to whoever hashes fastest. Since block 61,414 the producer of each
block is chosen by a **verifiable random draw (VRF sortition)** over registered mining keys.
Hashrate is not an input to that draw.

Real hashing still happens — a selected producer must still grind a nonce until the block header
meets a fixed 20-bit floor (~1 million SHA-256d attempts, well under a second on any CPU) — but a
faster machine simply finishes that same fixed work sooner. **It wins no extra blocks.**

Practically: **an ordinary CPU is enough. Buying more hardware does not improve your odds.**

## 1. Download

<https://github.com/iriumlabs/irium/releases/tag/v1.9.192>

Pick your platform, then verify the download against the published `checksums.txt`:

```bash
sha256sum -c checksums.txt --ignore-missing
```

The archive contains `iriumd` (the node), `irium-wallet`, `irium-miner`, and `irium-miner-gpu`.

## 2. Create a wallet and get your payout address

```bash
./irium-wallet create-wallet --bip32
./irium-wallet export-mnemonic --out mnemonic.txt
./irium-wallet list-addresses
```

⚠️ `create-wallet` does **not** print the mnemonic — it only stores it. You must run
`export-mnemonic` explicitly, as above. That file is the only way to recover the wallet: move it
somewhere safe and delete it from this machine. Your address starts with `P` or `Q`.

## 3. Choose an RPC token, then start the node

The node protects its RPC with a token, and **the miner cannot work without it** — this is not
optional. Pick one value and use the *same* value for both the node and the miner.

```bash
export IRIUM_RPC_TOKEN="$(openssl rand -hex 24)"
echo "$IRIUM_RPC_TOKEN" > rpc_token.txt      # you need this again in step 5
./iriumd
```

If you start `iriumd` without it you will see:

```
[!] No IRIUM_RPC_TOKEN configured — token-guarded endpoints will be REFUSED (401).
```

and the miner will then loop forever on
`template fetch failed: HTTP 401 Unauthorized (check IRIUM_RPC_TOKEN)`.

Leave the node running. It serves RPC on `http://127.0.0.1:38300`. Wait until its reported height
stops climbing and matches a public explorer before mining — a miner cannot build on a chain it has
not caught up to.

## 4. Create a proposer secret

This is the key the chain draws on. It is **separate** from your wallet key.

```bash
openssl rand -hex 32 > poawx_secret.hex
chmod 600 poawx_secret.hex
```

Back it up and keep it private. Anyone holding it can mine as you.

## 5. Start mining

```bash
export IRIUM_NODE_RPC=http://127.0.0.1:38300
export IRIUM_RPC_TOKEN="$(cat rpc_token.txt)"    # SAME value the node is running with
export IRIUM_MINER_ADDRESS="<your P... or Q... address>"
export IRIUM_POAWX_MINER_SECRET_HEX="$(cat poawx_secret.hex)"

./irium-miner --poawx --threads 1
```

If you run the miner in a **different terminal** from the node, remember it does not inherit the
node's environment — you must export `IRIUM_RPC_TOKEN` again there.

`--poawx` is **mandatory**. Without it the miner runs the legacy proof-of-work path, which consensus
has rejected since block 61,414 — it will appear to run and will never produce a block. The miner
says so itself if you omit it:

```
error: PoAW-X is active at this height (…); plain-PoW blocks are rejected by consensus.
       Set IRIUM_POAWX_MINER_SECRET_HEX and use --poawx
```

Piping the miner into `head`, `grep` or `tee` will make it look frozen — its output is block
buffered. Let it write to the terminal, or redirect to a file and `tail -f` that.

## 6. What you should see, and when

The miner registers your key on-chain automatically, then prints one line per slot:

```
[poawx] submitted proposer registration (anchor=…)
[poawx] not proposer this slot height=… (priority=… eligible=… max_round=…); waiting
[poawx] proposer SELECTED height=… round=… priority=… eligible=…
[poawx] submitted all-gates block height=…
```

`not proposer this slot` is **normal and expected** — it is the draw not selecting you this round,
printed roughly every 3 seconds.

### Time to first eligibility — be patient

Your key is not eligible the moment it registers. Eligibility is computed from the registry
**frozen 16 blocks back** (`DEFAULT_PROPOSER_FREEZE_DEPTH = 16`), so your registration must be at
least 16 blocks deep before you can be drawn.

At the 120-second block target that is **roughly 30–35 minutes** from your first successful
registration before you can win anything. Seeing only `not proposer this slot` during that window
means it is working correctly.

Registrations also age out: the anchor is valid for 64 blocks (`PROPOSER_REG_ANCHOR_WINDOW`), and
the miner re-registers periodically on its own. Leave it running.

## 7. How often should I win?

Honestly: it depends entirely on how many keys are actively mining, not on your hardware.

Selection runs in rounds. With `n` eligible keys, round 0 admits 1/n of the draw space, round 1
admits 4/n, and round 2 admits everyone — so a block is produced roughly every 120–240 seconds. If
few keys are actually running, whoever is running wins most blocks; as more real miners join, wins
spread out. This is the design, not a fault.

Blocks are never faster than 120 seconds apart — that floor is enforced by every node and a block
that breaks it is rejected outright.

## 8. Getting paid

Since block 66,400 the **full block subsidy (50 IRM) is paid by the chain directly to the single
selected producer's address**, in that block's coinbase. There is no pool, no operator, and nothing
custodial in between. Coinbase outputs mature after 100 blocks.

## Known gaps, stated plainly

- **GPU mining** (`irium-miner-gpu --poawx`) exists and the code path is complete, but it has not
  been verified end-to-end on real GPU hardware. Use the CPU path above — it is the one proven on
  mainnet.
- The **Irium Core desktop app** can run a node and a miner, but the CLI path above is the one
  verified working. If you use the app, it exposes the same RPC on port 38300.
- The **stratum pool is retired permanently.** Pooling cannot improve odds when selection is a
  random draw over keys, so there is nothing for a pool to aggregate.
