#!/bin/bash
# Fix Mining Setup Script
# This script helps migrate from shared wallet to individual wallets

echo "🔧 Fixing Irium Mining Setup..."
echo ""

# Check if miners are running
echo "🔍 Checking for running miners..."
RUNNING_MINERS=$(ps aux | grep "irium.*miner" | grep -v grep | wc -l)
echo "Found $RUNNING_MINERS running miners"

if [ $RUNNING_MINERS -gt 0 ]; then
    echo "⚠️  Stopping current miners..."
    pkill -f irium-simple-miner.py
    sleep 2
fi

# Create individual miner directories
echo ""
echo "🔧 Setting up individual miners..."

# Get list of running miners from process list
MINER_PIDS=$(ps aux | grep "irium.*miner" | grep -v grep | awk '{print $2}')

if [ -n "$MINER_PIDS" ]; then
    echo "Found miner processes, creating individual wallets..."
    
    COUNTER=1
    for pid in $MINER_PIDS; do
        MINER_ID="miner-$COUNTER-$(date +%s)"
        echo "Setting up miner: $MINER_ID"
        
        # Create miner directory
        MINER_DIR="$HOME/.irium-miners/$MINER_ID"
        mkdir -p "$MINER_DIR"
        
        # Generate wallet
        python3 -c "
import sys
import os
import json
sys.path.insert(0, '/home/irium/irium-test')
from irium.wallet import Wallet, KeyPair

wallet = Wallet()
key = KeyPair.generate()
wif = key.to_wif()
address = key.address()
wallet.import_wif(wif)

wallet_data = {
    'keys': {address: wif},
    'addresses': [address],
    'miner_id': '$MINER_ID',
    'created': '$(date -Iseconds)'
}

with open('$MINER_DIR/irium-wallet.json', 'w') as f:
    json.dump(wallet_data, f, indent=2)

print(f'✅ Miner $MINER_ID: {address}')
"
        
        COUNTER=$((COUNTER + 1))
    done
else
    echo "No running miners found, creating default individual wallet..."
    ./scripts/setup-miner.sh "default-miner"
fi

echo ""
echo "✅ Migration complete!"
echo ""
echo "To start mining with individual wallets:"
echo "1. python3 scripts/irium-miner-individual.py --miner-id miner-1-*"
echo "2. python3 scripts/irium-miner-individual.py --miner-id miner-2-*"
echo ""
echo "Each miner will now mine to their own address!"
