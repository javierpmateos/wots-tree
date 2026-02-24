"""
WOTS-Tree v6.4 — Reference Implementation
==========================================

Stateful hash-based signature scheme for Bitcoin combining WOTS+
one-time signatures with a binary Merkle tree.

Parameters (hardened default):
    n  = 16 bytes (128-bit truncated SHA-256 for chains)
    w  = 256
    ℓ₁ = 16, ℓ₂ = 2, ℓ = 18
    H_chain = SHA-256 truncated to n bytes
    H_tree  = SHA-256 full (32 bytes)

Security:
    Classical: 115.8 bits per-position (SPR)
    Quantum:   57.9 bits (Grover on SPR)
    Merkle:    ~124 bits (CR on H_tree)

Reference: WOTS-Tree v6.4 paper, Sections 3–6.
"""

import hashlib
import hmac
import math
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ===========================================================================
# Parameters
# ===========================================================================

@dataclass(frozen=True)
class WOTSTreeParams:
    """Immutable parameter set."""
    n: int = 16           # Hash output length in bytes (H_chain)
    w: int = 256          # Winternitz parameter
    tree_hash_len: int = 32  # H_tree output length (full SHA-256)

    @property
    def ell_1(self) -> int:
        return math.ceil(8 * self.n / math.log2(self.w))

    @property
    def ell_2(self) -> int:
        cs_max = self.ell_1 * (self.w - 1)
        return math.floor(math.log2(cs_max) / math.log2(self.w)) + 1

    @property
    def ell(self) -> int:
        return self.ell_1 + self.ell_2

    @property
    def max_checksum(self) -> int:
        return self.ell_1 * (self.w - 1)


PARAMS = WOTSTreeParams()


# ===========================================================================
# Hash functions — Dual hash design
# ===========================================================================

def h_chain(data: bytes, params: WOTSTreeParams = PARAMS) -> bytes:
    """SHA-256 truncated to n bytes. Used for WOTS+ chain evaluations."""
    return hashlib.sha256(data).digest()[:params.n]


def h_tree(data: bytes) -> bytes:
    """Full SHA-256 (32 bytes). Used for Merkle tree compression."""
    return hashlib.sha256(data).digest()


# ===========================================================================
# Key derivation (HMAC-based, Section 4.1)
# ===========================================================================

def derive_chain_seed(master_seed: bytes, deriv_idx: int) -> bytes:
    """Derive per-address chain_seed from master_seed and derivation index.
    
    chain_seed = HMAC(master_seed, "WOTS-TREE" || toByte(deriv_idx, 4))
    """
    msg = b"WOTS-TREE" + struct.pack(">I", deriv_idx)
    return hmac.new(master_seed, msg, hashlib.sha256).digest()


def derive_secret_key(
    chain_seed: bytes,
    leaf_idx: int,
    chain_idx: int,
    K: int,
    params: WOTSTreeParams = PARAMS
) -> bytes:
    """Derive secret key for leaf j, chain i. Returns n bytes."""
    idx_len = math.ceil(math.log2(max(K, 2)) / 8)
    msg = (
        leaf_idx.to_bytes(idx_len, "big")
        + struct.pack("B", chain_idx)
    )
    return hmac.new(chain_seed, msg, hashlib.sha256).digest()[:params.n]


# ===========================================================================
# WOTS+ chain evaluation (Section 3.1)
# ===========================================================================

def wots_chain(
    x: bytes,
    start: int,
    steps: int,
    public_seed: bytes,
    addr: bytes,
    params: WOTSTreeParams = PARAMS
) -> bytes:
    """Evaluate WOTS+ hash chain from position start for `steps` steps.
    
    Uses tweakable hash: H_chain(P || addr || step || x)
    where P = public_seed, addr = (leaf, chain), step = current position.
    """
    val = x
    for s in range(start, start + steps):
        tweak = public_seed + addr + struct.pack(">H", s)
        val = h_chain(tweak + val, params)
    return val


def msg_to_digits(msg_hash: bytes, params: WOTSTreeParams = PARAMS) -> List[int]:
    """Convert message hash to base-w digits with checksum (Section 3.1).
    
    Returns ℓ digits: ℓ₁ message digits + ℓ₂ checksum digits.
    """
    # Message digits (base-256 with w=256: each byte is one digit)
    digits = list(msg_hash[:params.ell_1])

    # Checksum
    checksum = sum(params.w - 1 - d for d in digits)

    # Encode checksum in base-w (big-endian)
    cs_digits = []
    for _ in range(params.ell_2):
        cs_digits.append(checksum % params.w)
        checksum //= params.w
    cs_digits.reverse()

    return digits + cs_digits


# ===========================================================================
# WOTS+ KeyGen / Sign / Verify (Section 4)
# ===========================================================================

@dataclass
class WOTSKeyPair:
    """WOTS+ key pair at a single leaf position."""
    leaf_idx: int
    secret_keys: List[bytes]       # ℓ secret keys, each n bytes
    public_keys: List[bytes]       # ℓ public keys (end of chains)
    leaf_hash: bytes               # H_chain(pk_0 || ... || pk_{ℓ-1})
    public_seed: bytes
    params: WOTSTreeParams = field(default_factory=lambda: PARAMS)


def wots_keygen(
    chain_seed: bytes,
    leaf_idx: int,
    K: int,
    params: WOTSTreeParams = PARAMS
) -> WOTSKeyPair:
    """Generate WOTS+ key pair for leaf position j."""
    # Public seed = H_tree(chain_seed) — deterministic, public
    public_seed = h_tree(chain_seed)[:params.n]

    secret_keys = []
    public_keys = []

    for i in range(params.ell):
        sk_i = derive_secret_key(chain_seed, leaf_idx, i, K, params)
        secret_keys.append(sk_i)

        # Public key = chain to end (w-1 steps from position 0)
        addr = struct.pack(">IB", leaf_idx, i)
        pk_i = wots_chain(sk_i, 0, params.w - 1, public_seed, addr, params)
        public_keys.append(pk_i)

    # Leaf hash = H_tree(pk_0 || pk_1 || ... || pk_{ℓ-1}) — 32 bytes
    # Paper Section 3.2: H_tree used for "leaf public key hashing"
    leaf_hash = h_tree(b"".join(public_keys))

    return WOTSKeyPair(
        leaf_idx=leaf_idx,
        secret_keys=secret_keys,
        public_keys=public_keys,
        leaf_hash=leaf_hash,
        public_seed=public_seed,
        params=params,
    )


def wots_sign(
    msg_hash: bytes,
    keypair: WOTSKeyPair,
) -> List[bytes]:
    """Sign a message hash with WOTS+. Returns ℓ signature elements."""
    params = keypair.params
    digits = msg_to_digits(msg_hash, params)
    signature = []

    for i in range(params.ell):
        addr = struct.pack(">IB", keypair.leaf_idx, i)
        sig_i = wots_chain(
            keypair.secret_keys[i], 0, digits[i],
            keypair.public_seed, addr, params
        )
        signature.append(sig_i)

    return signature


def wots_verify(
    msg_hash: bytes,
    signature: List[bytes],
    leaf_idx: int,
    public_seed: bytes,
    params: WOTSTreeParams = PARAMS
) -> bytes:
    """Verify a WOTS+ signature. Returns computed leaf hash.
    
    The caller must check that the returned leaf hash matches
    the expected leaf in the Merkle tree.
    """
    digits = msg_to_digits(msg_hash, params)
    public_keys = []

    for i in range(params.ell):
        remaining = params.w - 1 - digits[i]
        addr = struct.pack(">IB", leaf_idx, i)
        pk_i = wots_chain(signature[i], digits[i], remaining, public_seed, addr, params)
        public_keys.append(pk_i)

    return h_tree(b"".join(public_keys))


# ===========================================================================
# Merkle tree (Section 3.2) — uses H_tree (full SHA-256)
# ===========================================================================

@dataclass
class MerkleTree:
    """Binary Merkle tree over WOTS+ leaf hashes."""
    K: int
    depth: int
    root: bytes
    nodes: List[bytes]  # Flat array: nodes[1] = root
    leaf_hashes: List[bytes]


def build_merkle_tree(leaf_hashes: List[bytes]) -> MerkleTree:
    """Build a complete binary Merkle tree from leaf hashes.
    
    Leaf hashes are n bytes (from H_chain). Internal nodes use H_tree (32 bytes).
    """
    K = len(leaf_hashes)
    depth = math.ceil(math.log2(K)) if K > 1 else 0

    # Pad to power of 2 if needed
    padded_K = 1 << depth if depth > 0 else 1
    padded_leaves = list(leaf_hashes) + [b"\x00" * len(leaf_hashes[0])] * (padded_K - K)

    # Flat array: index 1 = root, leaves at [padded_K .. 2*padded_K-1]
    nodes = [b""] * (2 * padded_K)
    for i, lh in enumerate(padded_leaves):
        nodes[padded_K + i] = lh

    # Build bottom-up using H_tree
    for i in range(padded_K - 1, 0, -1):
        nodes[i] = h_tree(nodes[2 * i] + nodes[2 * i + 1])

    return MerkleTree(
        K=K,
        depth=depth,
        root=nodes[1] if padded_K > 0 else leaf_hashes[0],
        nodes=nodes,
        leaf_hashes=leaf_hashes,
    )


def get_auth_path(tree: MerkleTree, leaf_idx: int) -> List[bytes]:
    """Get authentication path (sibling hashes) for a leaf.
    
    Returns `depth` hashes, each 32 bytes (H_tree output).
    """
    padded_K = 1 << tree.depth
    idx = padded_K + leaf_idx
    path = []

    for _ in range(tree.depth):
        sibling = idx ^ 1
        path.append(tree.nodes[sibling])
        idx >>= 1

    return path


def verify_auth_path(
    leaf_hash: bytes,
    leaf_idx: int,
    auth_path: List[bytes],
    root: bytes,
    depth: int,
) -> bool:
    """Verify a Merkle authentication path against the root."""
    current = leaf_hash
    idx = (1 << depth) + leaf_idx

    for sibling in auth_path:
        if idx % 2 == 0:
            current = h_tree(current + sibling)
        else:
            current = h_tree(sibling + current)
        idx >>= 1

    return current == root


# ===========================================================================
# WOTS-Tree: Full scheme (Section 4)
# ===========================================================================

@dataclass
class WOTSTreeAddress:
    """A WOTS-Tree address (key pair + Merkle tree)."""
    chain_seed: bytes
    K: int
    depth: int
    tree: MerkleTree
    root: bytes                # = H_tree(merkle_root) — the address
    public_seed: bytes
    params: WOTSTreeParams
    _next_idx: int = 0         # State: next unused index


@dataclass
class WOTSTreeWitness:
    """Complete WOTS-Tree witness (Section 4.3)."""
    wots_signature: List[bytes]   # ℓ × n bytes
    spend_idx: int
    auth_path: List[bytes]        # depth × 32 bytes
    # BIP-341 control block handled at serialization layer

    def serialize(self, K: int, params: WOTSTreeParams = PARAMS) -> bytes:
        """Serialize witness to bytes (without BIP-341 control block)."""
        idx_len = math.ceil(math.log2(max(K, 2)) / 8)
        sig_bytes = b"".join(self.wots_signature)
        idx_bytes = self.spend_idx.to_bytes(idx_len, "big")
        path_bytes = b"".join(self.auth_path)
        return sig_bytes + idx_bytes + path_bytes

    def total_size(self, K: int, params: WOTSTreeParams = PARAMS, cb_size: int = 65) -> int:
        """Total L1 witness size including BIP-341 control block."""
        return len(self.serialize(K, params)) + cb_size


def keygen(
    master_seed: bytes,
    deriv_idx: int = 0,
    K: int = 1024,
    params: WOTSTreeParams = PARAMS,
) -> WOTSTreeAddress:
    """Generate a WOTS-Tree address with K leaves."""
    chain_seed = derive_chain_seed(master_seed, deriv_idx)
    depth = math.ceil(math.log2(max(K, 2)))
    public_seed = h_tree(chain_seed)[:params.n]

    # Generate all leaf hashes
    leaf_hashes = []
    for j in range(K):
        kp = wots_keygen(chain_seed, j, K, params)
        leaf_hashes.append(kp.leaf_hash)

    # Build Merkle tree
    tree = build_merkle_tree(leaf_hashes)

    # Address = H_tree(root)
    address = h_tree(tree.root)

    return WOTSTreeAddress(
        chain_seed=chain_seed,
        K=K,
        depth=depth,
        tree=tree,
        root=address,
        public_seed=public_seed,
        params=params,
    )


def sign(
    addr: WOTSTreeAddress,
    msg_hash: bytes,
    spend_idx: Optional[int] = None,
) -> WOTSTreeWitness:
    """Sign a message hash using the next available (or specified) leaf.
    
    WARNING: Each leaf index MUST be used at most once.
    Reusing a leaf index compromises the secret key.
    """
    if spend_idx is None:
        spend_idx = addr._next_idx
        addr._next_idx += 1

    if spend_idx >= addr.K:
        raise ValueError(f"Leaf index {spend_idx} exceeds K={addr.K}")

    # Regenerate key pair for this leaf
    kp = wots_keygen(addr.chain_seed, spend_idx, addr.K, addr.params)

    # WOTS+ sign
    wots_sig = wots_sign(msg_hash, kp)

    # Get auth path
    auth_path = get_auth_path(addr.tree, spend_idx)

    return WOTSTreeWitness(
        wots_signature=wots_sig,
        spend_idx=spend_idx,
        auth_path=auth_path,
    )


def verify(
    witness: WOTSTreeWitness,
    msg_hash: bytes,
    merkle_root: bytes,
    K: int,
    public_seed: bytes,
    params: WOTSTreeParams = PARAMS,
) -> bool:
    """Verify a WOTS-Tree witness against a Merkle root.
    
    Returns True if the witness is valid.
    """
    depth = math.ceil(math.log2(max(K, 2)))

    # Step 1: WOTS+ verify → recover leaf hash
    leaf_hash = wots_verify(
        msg_hash, witness.wots_signature,
        witness.spend_idx, public_seed, params
    )

    # Step 2: Verify Merkle auth path
    return verify_auth_path(
        leaf_hash, witness.spend_idx,
        witness.auth_path, merkle_root, depth
    )


# ===========================================================================
# Utility functions
# ===========================================================================

def witness_size(K: int, params: WOTSTreeParams = PARAMS, mode: str = "hardened") -> int:
    """Calculate witness size in bytes for given K and mode."""
    if K == 1:
        return params.ell * params.n + 65  # WOTS sig + CB, no idx or auth path
    depth = math.ceil(math.log2(K))
    idx_len = math.ceil(math.log2(K) / 8)
    wots_sig = params.ell * params.n
    node_size = params.tree_hash_len if mode == "hardened" else params.n
    auth_path = depth * node_size
    cb = 65  # BIP-341 control block (1 + 32 + 32)
    return wots_sig + idx_len + auth_path + cb


def setup_hashes(K: int, params: WOTSTreeParams = PARAMS) -> int:
    """Total hash evaluations for setup (keygen + tree build)."""
    per_leaf = params.ell + params.ell * (params.w - 1) + 1  # derivation + chains + leaf compress
    return K * per_leaf + (K - 1)  # leaves + internal nodes


def verification_hashes(params: WOTSTreeParams = PARAMS, K: int = 1024) -> int:
    """Maximum verification hash count."""
    depth = math.ceil(math.log2(K)) if K > 1 else 0
    return params.ell * (params.w - 1) + 1 + depth
