#!/usr/bin/env python3
"""
Generate test vectors for WOTS-Tree v6.4

Produces vectors matching Appendix B of the paper.
Usage: python3 tools/gen_vectors.py [--json]
"""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.wots_tree import (
    PARAMS, derive_chain_seed, derive_secret_key, h_chain, h_tree,
    keygen, sign, setup_hashes, verification_hashes, witness_size,
)


def generate_vectors(K: int = 1024) -> dict:
    """Generate test vectors for a given K."""
    master_seed = b"\x00" * 32
    deriv_idx = 0

    chain_seed = derive_chain_seed(master_seed, deriv_idx)
    sk_0_0 = derive_secret_key(chain_seed, 0, 0, K)

    addr = keygen(master_seed, deriv_idx=deriv_idx, K=K)

    # Sign at index 0
    msg = h_chain(b"test message for WOTS-Tree v6.4!")
    witness = sign(addr, msg, spend_idx=0)

    return {
        "parameters": {
            "n": PARAMS.n,
            "w": PARAMS.w,
            "ell": PARAMS.ell,
            "ell_1": PARAMS.ell_1,
            "ell_2": PARAMS.ell_2,
            "K": K,
            "depth": addr.depth,
            "tree_hash_len": PARAMS.tree_hash_len,
        },
        "key_generation": {
            "master_seed": master_seed.hex(),
            "deriv_idx": deriv_idx,
            "chain_seed": chain_seed.hex(),
            "sk_0_0": sk_0_0.hex(),
            "merkle_root": addr.tree.root.hex(),
            "address": addr.root.hex(),
        },
        "witness_sizes": {
            "hardened": witness_size(K, mode="hardened"),
            "compact": witness_size(K, mode="compact"),
        },
        "setup": {
            "total_hashes": setup_hashes(K),
            "time_500mhs_ms": round(setup_hashes(K) / 500_000_000 * 1000, 2),
        },
        "verification": {
            "max_hashes": verification_hashes(K=K),
        },
        "sample_witness": {
            "spend_idx": 0,
            "wots_sig_hex": b"".join(witness.wots_signature).hex(),
            "auth_path_hex": b"".join(witness.auth_path).hex(),
            "serialized_hex": witness.serialize(K).hex(),
            "serialized_len": len(witness.serialize(K)),
            "total_with_cb": witness.total_size(K),
        },
    }


def main():
    use_json = "--json" in sys.argv

    for K in [1024, 65536]:
        vectors = generate_vectors(K)

        if use_json:
            print(json.dumps(vectors, indent=2))
        else:
            print(f"{'='*60}")
            print(f"  WOTS-Tree v6.4 Test Vectors — K = {K:,}")
            print(f"{'='*60}")
            print()
            p = vectors["parameters"]
            print(f"  n={p['n']}, w={p['w']}, ℓ={p['ell']} "
                  f"(ℓ₁={p['ell_1']}, ℓ₂={p['ell_2']})")
            print(f"  K={p['K']}, depth={p['depth']}")
            print()

            kg = vectors["key_generation"]
            print(f"  master_seed:  {kg['master_seed'][:32]}...")
            print(f"  chain_seed:   {kg['chain_seed'][:32]}...")
            print(f"  sk_{{0,0}}:     {kg['sk_0_0']}")
            print(f"  merkle_root:  {kg['merkle_root'][:32]}...")
            print(f"  address:      {kg['address'][:32]}...")
            print()

            ws = vectors["witness_sizes"]
            print(f"  Witness (hardened): {ws['hardened']} bytes")
            print(f"  Witness (compact):  {ws['compact']} bytes")
            print()

            s = vectors["setup"]
            print(f"  Setup hashes: {s['total_hashes']:,}")
            print(f"  Setup time:   {s['time_500mhs_ms']} ms @ 500 MH/s")
            print()

            v = vectors["verification"]
            print(f"  Max verify:   {v['max_hashes']} hashes")
            print()

    # Summary table
    print(f"{'='*60}")
    print("  Summary — Witness sizes (bytes)")
    print(f"{'='*60}")
    print(f"  {'K':>10s}  {'Hardened':>10s}  {'Compact':>10s}")
    print(f"  {'-'*10}  {'-'*10}  {'-'*10}")
    for K in [1, 1024, 65536, 2**21]:
        h = witness_size(K, mode="hardened")
        c = witness_size(K, mode="compact")
        print(f"  {K:>10,d}  {h:>10d}  {c:>10d}")


if __name__ == "__main__":
    main()
