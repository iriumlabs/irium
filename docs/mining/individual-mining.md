# Individual Mining Setup

## Problem with Current Setup

The current mining setup uses a shared wallet file (`~/.irium/irium-wallet.json`) which means:
- All miners use the same address: `Q2hJVzmxuSdx136AFoaxDQkFPk8yLWVU6E`
- All mining rewards go to one address
- This is not fair for individual miners

## Solution: Individual Miner Wallets

Each miner should have their own wallet file to receive their own mining rewards.

### Setup Individual Miner

1. **Create a new miner wallet:**
   ```bash
   ./scripts/setup-miner.sh my-miner-1
   ```

2. **Start mining with your wallet:**
   ```bash
   python3 scripts/irium-miner-individual.py --wallet ~/.irium-miners/my-miner-1/irium-wallet.json
   ```

### Alternative: Use Miner ID

```bash
python3 scripts/irium-miner-individual.py --miner-id my-miner-1
```

### Verify Your Mining Address

Check that you're mining to your own address:
```bash
cat ~/.irium-miners/my-miner-1/irium-wallet.json
```

## Migration from Shared Wallet

If you're currently using the shared wallet:

1. **Stop current mining:**
   ```bash
   pkill -f irium-simple-miner.py
   ```

2. **Create your individual wallet:**
   ```bash
   ./scripts/setup-miner.sh my-miner-$(whoami)
   ```

3. **Start mining with your wallet:**
   ```bash
   python3 scripts/irium-miner-individual.py --miner-id my-miner-$(whoami)
   ```

## Security Benefits

- ✅ Each miner gets their own rewards
- ✅ No shared wallet files
- ✅ Individual miner identification
- ✅ Fair distribution of mining rewards
- ✅ Better decentralization

## Troubleshooting

**Wallet file not found:**
- Make sure you ran `./scripts/setup-miner.sh` first
- Check the wallet file path

**Permission denied:**
- Make sure the script is executable: `chmod +x scripts/setup-miner.sh`

**Mining to wrong address:**
- Verify your wallet file contains your address
- Check the miner logs for the mining address
