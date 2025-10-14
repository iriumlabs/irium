"""Network-wide constants for Irium mainnet."""

from __future__ import annotations

import dataclasses
from typing import Final


@dataclasses.dataclass(frozen=True)
class SubsidySchedule:
    """Describes the block subsidy emission curve.

    Supports Bitcoin-style halvings. Reward for height=0 is always 0.
    """

    initial_reward: int
    coinbase_maturity: int
    halving_interval: int

    def block_reward(self, height: int) -> int:
        """Return the block subsidy for a specific block height.

        - Returns 0 for genesis (height=0)
        - Applies integer halvings every ``halving_interval`` blocks thereafter
        """
        if height < 0:
            raise ValueError("Block height cannot be negative")
        if self.initial_reward <= 0:
            return 0
        if height == 0:
            return 0

        if self.halving_interval <= 0:
            # No halvings; constant reward after genesis
            return self.initial_reward

        halvings = (height - 1) // self.halving_interval
        if halvings >= 64:
            # Prevent shifting beyond width (reward effectively zero)
            return 0
        return self.initial_reward >> halvings


MAX_MONEY: Final[int] = 100_000_000 * 10**8  # satoshis equivalent (cap)
BLOCK_TARGET_INTERVAL: Final[int] = 600  # seconds
DIFFICULTY_RETARGET_INTERVAL: Final[int] = 2016  # blocks
POW_ALGORITHM: Final[str] = "sha256d"
GENESIS_TIMELOCKS: Final[tuple[int, ...]] = (
    1 * 365 * 24 * 60 * 60,
    2 * 365 * 24 * 60 * 60,
    3 * 365 * 24 * 60 * 60,
)
GENESIS_BLOCK_HEIGHT: Final[int] = 0
GENESIS_TOTAL_VESTING: Final[int] = 3_500_000 * 10**8
GENESIS_PUBLIC_SUPPLY: Final[int] = 96_500_000 * 10**8
PUBKEY_ADDRESS_PREFIX: Final[int] = 0x39  # Base58 prefix for Irium P2PKH addresses
SUBSIDY_SCHEDULE: Final[SubsidySchedule] = SubsidySchedule(
    initial_reward=50 * 10**8,
    coinbase_maturity=100,
    halving_interval=210_000,
)
