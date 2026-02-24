# WOTS-Tree

**Stateful hash-based signatures for Bitcoin's post-quantum transition.**

WOTS-Tree combines WOTS+ one-time signatures with a bounded Merkle tree, deployed as dual leaves within BIP-341 Taproot. It provides an emergency pure-hash fallback layer requiring only the security of SHA-256.

## Key Properties

| Parameter | Value |
|---|---|
| Witness (K=1, fast-path) | **353 bytes** |
| Witness (K=1024, hardened) | **675 bytes** |
| Witness (K=2²¹, Lightning) | **1,028 bytes** |
| Verification | **4,601 hashes** (0.009 ms @ SHA-NI) |
| Classical security | **115.8 bits** per-position |
| Quantum security | **57.9 bits** (Grover) |
| Merkle binding | **~124 bits** (hardened mode) |

Default witnesses are **4–7× smaller** than hypertree variants (SLH-DSA, SPHINCS+C) at the 128-bit security level.

## Design

```
H_chain = SHA-256 truncated to 128 bits    (WOTS+ chain evaluations)
H_tree  = SHA-256 full 256 bits            (Merkle tree compression)
```

Parameters: `n=16, w=256, ℓ=18 (ℓ₁=16, ℓ₂=2)`

The dual hash design places the collision resistance bottleneck on the Merkle tree (~124 bits with full SHA-256) rather than on the WOTS+ chains, where only second-preimage resistance is required.

## Repository Structure

```
├── paper/
│   ├── wots_tree.tex          # Full paper (LaTeX source)
│   ├── references.bib         # Bibliography
│   └── WOTS_Tree_v6.4.pdf     # Compiled PDF
├── src/
│   ├── __init__.py
│   └── wots_tree.py           # Reference implementation
├── tests/
│   └── test_wots_tree.py      # 42 tests (vectors, sizes, security)
├── tools/
│   ├── gen_vectors.py          # Test vector generator
│   └── run_benchmarks.py       # Performance benchmarks
└── .github/workflows/
    └── ci.yml                  # Continuous integration
```

## Quick Start

```bash
# Run tests
python3 -m unittest tests.test_wots_tree -v

# Generate test vectors
python3 tools/gen_vectors.py

# Run benchmarks
python3 tools/run_benchmarks.py
```

### Minimal Example

```python
from src.wots_tree import keygen, sign, verify, h_chain

# Generate address with K=1024 leaves
master_seed = bytes(32)  # Use secure random in production
addr = keygen(master_seed, deriv_idx=0, K=1024)

# Sign (each index must be used at most once)
msg_hash = h_chain(b"transaction sighash placeholder!")
witness = sign(addr, msg_hash, spend_idx=0)

# Verify
valid = verify(
    witness, msg_hash,
    addr.tree.root, addr.K, addr.public_seed
)
assert valid

print(f"Witness: {witness.total_size(1024)} bytes")  # 675
```

## Test Vectors (Appendix B)

```
Parameters: n=16, w=256, ℓ=18, K=1024, depth=10

Key Generation (master_seed = 0x00^32, deriv_idx = 0):
  chain_seed: ec90155ffe6f55cb87470ac8cf2c566e
              df78c68a4e5cd1552087dd238efcf032
  sk_{0,0}:   428b70877eb337c8cc1d094da5ee6b85
```

## Security

WOTS-Tree is a **parameterization and deployment framework** for XMSS (RFC 8391), not a novel cryptographic primitive. Security relies on:

- **SPR** of SHA-256 (truncated to 128 bits) for WOTS+ chains
- **CR** of SHA-256 (full 256 bits) for Merkle tree binding
- **PRF** security of HMAC-SHA256 for key derivation

See the paper (Section 5) for formal reductions and concrete bounds.

## ⚠️ Important

- **Stateful scheme**: Each leaf index MUST be used at most once. Reusing an index compromises the secret key for that position.
- **Reference implementation**: This Python code is for testing and education. Production deployments require constant-time implementations in C/Rust.
- **Not standalone**: WOTS-Tree is designed as a fallback layer within a multi-signature Taproot architecture (Schnorr + ML-DSA + WOTS-Tree).

## Paper

The full technical paper is available in `paper/` and on [IACR ePrint](https://eprint.iacr.org/) (forthcoming).

**Citation:**
```bibtex
@misc{mateos2026wotstree,
  author = {Javier Mateos},
  title  = {{WOTS-Tree}: Compact Stateful Hash-Based Signatures for Bitcoin},
  year   = {2026},
  note   = {Version 6.4}
}
```

## License

MIT — see [LICENSE](LICENSE).
