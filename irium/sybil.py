"""Sybil-resistant handshake token stubs.

Defines interfaces for ephemeral key handshakes and uptime proofs. This is a stub
for integration with the future libp2p layer.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional

from .pow import sha256d


@dataclass(frozen=True)
class HandshakeToken:
    version: int
    issued_at: int
    difficulty_bits: int
    nonce: int
    signature: bytes


def generate_uptime_token(secret: bytes, *, difficulty_bits: int = 18) -> HandshakeToken:
    issued = int(time.time())
    nonce = 0
    target = 1 << (256 - difficulty_bits)
    while True:
        payload = issued.to_bytes(8, "big") + nonce.to_bytes(8, "big") + secret
        h = sha256d(payload)
        if int.from_bytes(h, "big") < target:
            return HandshakeToken(version=1, issued_at=issued, difficulty_bits=difficulty_bits, nonce=nonce, signature=h)
        nonce = (nonce + 1) & 0xFFFFFFFF


def verify_uptime_token(secret: bytes, token: HandshakeToken) -> bool:
    payload = token.issued_at.to_bytes(8, "big") + token.nonce.to_bytes(8, "big") + secret
    h = sha256d(payload)
    if h != token.signature:
        return False
    target = 1 << (256 - token.difficulty_bits)
    return int.from_bytes(h, "big") < target
