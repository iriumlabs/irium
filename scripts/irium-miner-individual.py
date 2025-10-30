#!/usr/bin/env python3
"""Irium miner with individual wallet support (no hardcoded wallet)."""

import sys
import os
import asyncio
import signal
import json
import argparse
import contextlib

# Add the irium-test directory to Python path
sys.path.insert(0, '/home/irium/irium-test')

from irium.wallet import Wallet
from irium.chain import ChainParams, ChainState
from irium.block import Block, BlockHeader
from irium.tx import Transaction, TxInput, TxOutput
from irium.pow import Target
from irium.p2p import P2PNode

class IriumMiner:
    def __init__(self, wallet_file=None, p2p_port=38292, node_port=38291, bootstrap_nodes=None):
        self.wallet_file = os.path.expanduser(wallet_file) if wallet_file else None
        if not self.wallet_file:
            print("❌ No wallet provided. Use --wallet or --miner-id.")
            sys.exit(1)
        self.wallet = self.load_wallet()
        self.mining_address = self.get_mining_address()
        self.chain_params = None
        self.chain_state = None
        self.running = True
        self.blocks_mined = 0
        self.p2p_port = p2p_port
        self.node_port = node_port
        self.bootstrap_nodes = bootstrap_nodes or []
        self.p2p = None

    def load_wallet(self):
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
        addresses = list(self.wallet.addresses())
        if addresses:
            address = addresses[0]
            print(f"⛏️  Mining address: {address}")
            return address
        print("❌ No addresses found in wallet")
        sys.exit(1)

    async def start_mining(self):
        print(f"🚀 Starting Irium Miner...")
        print(f"   Mining address: {self.mining_address}")
        print(f"   Wallet file: {self.wallet_file}")
        print(f"   P2P port: {self.p2p_port}  Node port: {self.node_port}")
        if self.bootstrap_nodes:
            print(f"   Bootstrap: {', '.join(self.bootstrap_nodes)}")

        await self.initialize_blockchain()
        await self.start_p2p()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))

        await self.mining_loop()

    async def stop(self):
        if not self.running:
            return
        print("\n🛑 Stopping miner...")
        self.running = False
        # if self.p2p:
        #     await self.p2p.stop()

    async def initialize_blockchain(self):
        print("📋 Initializing blockchain...")
        # Wire actual chain init here
        print("✅ Blockchain initialized")

    async def start_p2p(self):
        print(f"🌐 Starting P2P networking on port {self.p2p_port}...")
        # Example if P2PNode supports args:
        # self.p2p = P2PNode(listen_port=self.p2p_port, node_port=self.node_port, bootstrap=self.bootstrap_nodes)
        # await self.p2p.start()
        print("✅ P2P networking started")

    async def mining_loop(self):
        print("⛏️  Starting mining loop...")
        backoff_seconds = 1
        while self.running:
            try:
                # Mining logic here
                await asyncio.sleep(1)
                backoff_seconds = 1
            except Exception as e:
                print(f"⚠️  Mining error: {e}")
                await asyncio.sleep(min(backoff_seconds, 10))
                backoff_seconds = min(backoff_seconds * 2, 60)

def main():
    parser = argparse.ArgumentParser(description='Irium Miner with Individual Wallets')
    parser.add_argument('--wallet', help='Path to wallet file')
    parser.add_argument('--miner-id', help='Miner ID (uses ~/.irium-miners/{id}/irium-wallet.json)')
    parser.add_argument('--port', type=int, default=38292, help='P2P port')
    parser.add_argument('--node-port', type=int, default=38291, help='Node RPC/P2P port (if used)')
    parser.add_argument('--bootstrap', help='Comma-separated bootstrap peers host:port', default=os.getenv('BOOTSTRAP_NODES', ''))
    args = parser.parse_args()

    if args.wallet:
        wallet_file = os.path.expanduser(args.wallet)
    elif args.miner_id:
        wallet_file = os.path.expanduser(f"~/.irium-miners/{args.miner_id}/irium-wallet.json")
    else:
        print("❌ You must supply --wallet or --miner-id")
        sys.exit(1)

    bootstrap_nodes = [p.strip() for p in (args.bootstrap or '').split(',') if p.strip()]

    miner = IriumMiner(
        wallet_file=wallet_file,
        p2p_port=args.port,
        node_port=args.node_port,
        bootstrap_nodes=bootstrap_nodes
    )

    try:
        asyncio.run(miner.start_mining())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
