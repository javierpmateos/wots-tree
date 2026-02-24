"""WOTS-Tree: Stateful hash-based signatures for Bitcoin."""

from .wots_tree import (
    PARAMS,
    WOTSTreeParams,
    keygen,
    sign,
    verify,
    witness_size,
    setup_hashes,
    verification_hashes,
)

__version__ = "6.4.0"
__all__ = [
    "PARAMS",
    "WOTSTreeParams",
    "keygen",
    "sign",
    "verify",
    "witness_size",
    "setup_hashes",
    "verification_hashes",
]
