#!/usr/bin/env python3
"""Irium miner with individual wallet support."""

import sys
import os
import asyncio
import signal
import json
import time
import argparse

# Add the irium-test directory to Python path
sys.path.insert(0, '/home/irium/irium-test')

from irium.wallet import Wallet
from irium.chain import ChainParams, ChainState
from irium.block import Block, BlockHeader
from irium.tx import Transaction, TxInput, TxOutput
from irium.pow import Target
from irium.p2p import P2PNode

class IriumMiner:
    def __init__(self, wallet_file=None, p2p_port=38292):
        self.wallet_file = wallet_file or os.path.expanduser("~/.irium/irium-wallet.json")
        self.wallet = self.load_wallet()
        self.mining_address = self.get_mining_address()
        self.chain_params = None
        self.chain_state = None
        self.running = True
        self.blocks_mined = 0
        self.p2p_port = p2p_port
        self.p2p = None

    def load_wallet(self):
        """Load wallet from specified file."""
        wallet = Wallet()
        if os.path.exists(self.wallet_file):
            print(f"💰 Loading wallet from: {self.wallet_file}")
            with open(self.wallet_file, 'r') as f:
                data = json.load(f)
            for addr, wif in data.get('keys', {}).items():
                wallet.import_wif(wif)
        else:
            print(f"❌ Wallet file not found: {self.wallet_file}")
            print("   Please run: ./scripts/setup-miner.sh")
            sys.exit(1)
        return wallet

    def get_mining_address(self):
        """Get address for mining rewards."""
        addresses = list(self.wallet.addresses())
        if addresses:
            address = addresses[0]
            print(f"⛏️  Mining address: {address}")
            return address
        
        print("❌ No addresses found in wallet")
        sys.exit(1)

    async def start_mining(self):
        """Start the mining process."""
        print(f"🚀 Starting Irium Miner...")
        print(f"   Mining address: {self.mining_address}")
        print(f"   Wallet file: {self.wallet_file}")
        print(f"   P2P port: {self.p2p_port}")
        
        # Initialize blockchain
        await self.initialize_blockchain()
        
        # Start P2P networking
        await self.start_p2p()
        
        # Start mining loop
        await self.mining_loop()

    async def initialize_blockchain(self):
        """Initialize blockchain state."""
        print("📋 Initializing blockchain...")
        # Implementation here
        print("✅ Blockchain initialized")

    async def start_p2p(self):
        """Start P2P networking."""
        print(f"🌐 Starting P2P networking on port {self.p2p_port}...")
        # Implementation here
        print("✅ P2P networking started")

    async def mining_loop(self):
        """Main mining loop."""
        print("⛏️  Starting mining loop...")
        while self.running:
            try:
                # Mining logic here
                await asyncio.sleep(1)
            except KeyboardInterrupt:
                print("\n🛑 Stopping miner...")
                self.running = False

def main():
    parser = argparse.ArgumentParser(description='Irium Miner with Individual Wallets')
    parser.add_argument('--wallet', help='Path to wallet file')
    parser.add_argument('--port', type=int, default=38292, help='P2P port')
    parser.add_argument('--miner-id', help='Miner ID for identification')
    
    args = parser.parse_args()
    
    # Determine wallet file
    if args.wallet:
        wallet_file = os.path.expanduser(args.wallet)
    elif args.miner_id:
        wallet_file = os.path.expanduser(f"~/.irium-miners/{args.miner_id}/irium-wallet.json")
    else:
        wallet_file = None
    
    # Create miner
    miner = IriumMiner(wallet_file=wallet_file, p2p_port=args.port)
    
    # Start mining
    try:
        asyncio.run(miner.start_mining())
    except KeyboardInterrupt:
        print("\n👋 Miner stopped")

if __name__ == "__main__":
    main()
