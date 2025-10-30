#!/bin/bash
# Irium Miner Setup Script
# This script sets up individual mining wallets for each miner

echo "⛏️  Setting up Irium Miner..."

# Create miner-specific directory
MINER_ID=${1:-"miner-$(date +%s)"}
MINER_DIR="$HOME/.irium-miners/$MINER_ID"

echo "Creating miner directory: $MINER_DIR"
mkdir -p "$MINER_DIR"

# Generate new wallet for this miner
echo "Generating new wallet for miner: $MINER_ID"
python3 -c "
import sys
import os
import json
sys.path.insert(0, '/home/irium/irium-test')
from irium.wallet import Wallet, KeyPair

# Create new wallet
wallet = Wallet()

# Generate new key pair
key = KeyPair.generate()
wif = key.to_wif()
address = key.address()

# Import key to wallet
wallet.import_wif(wif)

# Save wallet to miner-specific file
wallet_data = {
    'keys': {address: wif},
    'addresses': [address],
    'miner_id': '$MINER_ID',
    'created': '$(date -Iseconds)'
}

wallet_file = '$MINER_DIR/irium-wallet.json'
with open(wallet_file, 'w') as f:
    json.dump(wallet_data, f, indent=2)

print(f'✅ New miner wallet created:')
print(f'   Address: {address}')
print(f'   Wallet file: {wallet_file}')
print(f'   Miner ID: $MINER_ID')
"

# Create miner configuration
cat > "$MINER_DIR/miner.conf" << EOC
# Irium Miner Configuration
MINER_ID=$MINER_ID
WALLET_FILE=$MINER_DIR/irium-wallet.json
P2P_PORT=38292
NODE_PORT=38291
BOOTSTRAP_NODES=178.78.34.62:38291,106.219.157.252:38291
EOC

echo ""
echo "✅ Miner setup complete!"
echo "   Miner ID: $MINER_ID"
echo "   Wallet: $MINER_DIR/irium-wallet.json"
echo "   Config: $MINER_DIR/miner.conf"
echo ""
echo "To start mining with this wallet:"
echo "   python3 scripts/irium-miner-individual.py --wallet $MINER_DIR/irium-wallet.json"
