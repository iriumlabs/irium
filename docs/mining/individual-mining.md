# Individual Mining Setup

Each miner should have their own wallet file and payout address so rewards are not shared.

## Setup Individual Miner

1. **Create a dedicated wallet file:**
   ```bash
   export IRIUM_WALLET_FILE=~/.irium-miners/my-miner-1/wallet.json
   ./target/release/irium-wallet init
   ./target/release/irium-wallet list-addresses
   ```

2. **Start mining to your address:**
   ```bash
   export IRIUM_MINER_ADDRESS=<YOUR_IRIUM_ADDRESS>
   ./target/release/irium-miner --threads 4
   ```

## Verify Your Mining Address

```bash
./target/release/irium-wallet list-addresses
```

## Optional: systemd

You can run a miner per host using `/etc/irium/miner.env` with a unique `IRIUM_MINER_ADDRESS`.
