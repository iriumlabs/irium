#!/usr/bin/env python3
"""
Build a 3-UTXO CLTV genesis spec from a WIF without exposing it.

Usage:
  FOUNDER_WIF=K... python3 scripts/build_genesis_from_wif.py --output configs/genesis.json

Notes:
- The WIF is only read from the FOUNDER_WIF environment variable.
- The resulting file contains only public data (address/script hashes), never the WIF.
- Locks three UTXOs at +1y, +2y, +3y block heights (approx. 52,560 blocks/year).
"""
from __future__ import annotations

import argparse
import os
import hashlib
from dataclasses import dataclass
from typing import List

from irium.constants import BLOCK_TARGET_INTERVAL
from irium.tx import cltv_script
from irium.wallet import KeyPair

@dataclass
class VestingTranche:
    years: int
    amount_sats: int

TRANCHES: List[VestingTranche] = [
    VestingTranche(years=1, amount_sats=0),
    VestingTranche(years=2, amount_sats=0),
    VestingTranche(years=3, amount_sats=0),
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    # The genesis timestamp is independent of CLTV heights; we only compute heights
    args = parser.parse_args()

    wif = os.environ.get("FOUNDER_WIF")
    if not wif:
        raise SystemExit("FOUNDER_WIF environment variable must be set; refusing to read keys from argv")
    key = KeyPair.from_wif(wif)

    # Compute equal split with remainder adjustment to preserve exact total
    total_vesting = 3_500_000 * 10**8
    equal = total_vesting // 3
    remainder = total_vesting - equal * 3
    for i, t in enumerate(TRANCHES):
        TRANCHES[i] = VestingTranche(years=t.years, amount_sats=equal + (remainder if i == len(TRANCHES) - 1 else 0))

    # Build CLTV scripts using founder's public key hash
    pubkey = key.public_key()
    sha = hashlib.sha256(pubkey).digest()
    ripe = hashlib.new("ripemd160", sha).digest()

    blocks_per_year = (365 * 24 * 60 * 60) // BLOCK_TARGET_INTERVAL
    scripts: List[str] = []
    for tranche in TRANCHES:
        lock_height = tranche.years * blocks_per_year
        script = cltv_script(lock_height, ripe)
        scripts.append(script.hex())

    total = sum(t.amount_sats for t in TRANCHES)
    if total != 3_500_000 * 10**8:
        # Keep generation honest: ensure exact total supply allocated per requirement
        raise SystemExit("Vesting tranches do not sum to 3,500,000 IRM in satoshis")

    data = {
        "network": "mainnet",
        "timestamp": 0,
        "bits": "1d00ffff",
        "nonce": 2083236893,
        "allocations": [
            {"label": f"founder_vesting_{t.years}y", "amount_sats": t.amount_sats, "script_pubkey": script}
            for t, script in zip(TRANCHES, scripts)
        ],
    }

    with open(args.output, "w") as f:
        import json
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    main()
