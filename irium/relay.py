"""Relay reward commitment parser utilities.

Parses commitment OP_RETURN outputs with prefix b"relay:" to expose memo text
and collects P2PKH relay payouts intended for peers.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from .tx import Transaction, TxOutput

RELAY_PREFIX = b"relay:"


@dataclass(frozen=True)
class RelayCommitmentParsed:
    memo: Optional[str]
    total_peer_payout: int
    outputs: List[TxOutput]


def parse_commitments(tx: Transaction) -> RelayCommitmentParsed:
    memo: Optional[str] = None
    total = 0
    payouts: List[TxOutput] = []
    for out in tx.outputs:
        spk = out.script_pubkey
        # Standard P2PKH starts with OP_DUP OP_HASH160 0x14 ... OP_EQUALVERIFY OP_CHECKSIG
        is_p2pkh = len(spk) >= 25 and spk[:3] == b"\x76\xa9\x14" and spk[-2:] == b"\x88\xac"
        if is_p2pkh:
            total += out.value
            payouts.append(out)
            continue
        # OP_RETURN commitments: 0x6a PUSHDATA
        if len(spk) >= 2 and spk[0] == 0x6A:
            push_len = spk[1]
            if 2 + push_len != len(spk):
                continue
            payload = spk[2:]
            if payload.startswith(RELAY_PREFIX):
                try:
                    memo = payload[len(RELAY_PREFIX):].decode("utf8") or None
                except UnicodeDecodeError:
                    memo = None
    return RelayCommitmentParsed(memo=memo, total_peer_payout=total, outputs=payouts)
