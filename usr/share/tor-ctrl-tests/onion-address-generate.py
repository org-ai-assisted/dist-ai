#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Print a fresh, syntactically valid v3 onion address.

A v3 address is base32(pubkey || checksum || version) where the pubkey is 32
bytes of ed25519, the checksum is the first 2 bytes of
sha3-256(".onion checksum" || pubkey || version), and version is 0x03.

The key is a REAL ed25519 public key rather than random bytes: tor validates the
point and answers '512 Invalid v3 address' for anything else. Generated per call
rather than hardcoded, so a test using it never names a real onion service.
"""

import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ONION_VERSION = b'\x03'
CHECKSUM_PREFIX = b'.onion checksum'
CHECKSUM_LENGTH = 2


def onion_address() -> str:
    """Return a v3 onion address, without the '.onion' suffix."""
    pubkey = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    checksum = hashlib.sha3_256(
        CHECKSUM_PREFIX + pubkey + ONION_VERSION
    ).digest()[:CHECKSUM_LENGTH]
    return base64.b32encode(pubkey + checksum + ONION_VERSION).decode().lower()


if __name__ == '__main__':
    print(onion_address())
