#!/usr/bin/env python3
"""
WOTS-Tree v6.4 — Performance benchmarks

Measures keygen, sign, and verify times for various K values.
Usage: python3 tools/run_benchmarks.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.wots_tree import (
    PARAMS, h_chain, keygen, sign, verify,
    setup_hashes, verification_hashes, witness_size,
)


def benchmark_keygen(K: int, master_seed: bytes, repeats: int = 1) -> float:
    """Benchmark keygen for given K. Returns average time in seconds."""
    times = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        keygen(master_seed, deriv_idx=0, K=K)
        t1 = time.perf_counter()
        times.append(t1 - t0)
    return sum(times) / len(times)


def benchmark_sign(addr, msg_hash: bytes, repeats: int = 10) -> float:
    """Benchmark signing. Returns average time in seconds."""
    times = []
    for i in range(repeats):
        t0 = time.perf_counter()
        sign(addr, msg_hash, spend_idx=i % addr.K)
        t1 = time.perf_counter()
        times.append(t1 - t0)
    return sum(times) / len(times)


def benchmark_verify(addr, msg_hash: bytes, repeats: int = 10) -> float:
    """Benchmark verification. Returns average time in seconds."""
    w = sign(addr, msg_hash, spend_idx=0)
    times = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        verify(w, msg_hash, addr.tree.root, addr.K, addr.public_seed)
        t1 = time.perf_counter()
        times.append(t1 - t0)
    return sum(times) / len(times)


def main():
    master_seed = b"\x00" * 32
    msg_hash = h_chain(b"benchmark message for WOTS-Tree!")

    print("WOTS-Tree v6.4 — Performance Benchmarks")
    print("=" * 65)
    print(f"  Python reference implementation (NOT optimized)")
    print(f"  n={PARAMS.n}, w={PARAMS.w}, ℓ={PARAMS.ell}")
    print()

    # Theoretical performance at 500 MH/s SHA-NI
    print("  Theoretical (500 MH/s SHA-NI hardware):")
    print(f"  {'K':>10s}  {'Setup':>12s}  {'Sign':>10s}  {'Verify':>10s}  {'Witness':>8s}")
    print(f"  {'-'*10}  {'-'*12}  {'-'*10}  {'-'*10}  {'-'*8}")
    for K in [1, 1024, 65536, 2**21]:
        sh = setup_hashes(K)
        setup_t = sh / 500_000_000
        sign_t = 4608 / 500_000_000  # ℓ(w-1) + ℓ hashes
        verify_t = verification_hashes(K=K) / 500_000_000
        ws = witness_size(K)
        if setup_t < 1:
            setup_str = f"{setup_t*1000:.1f} ms"
        else:
            setup_str = f"{setup_t:.1f} s"
        print(f"  {K:>10,d}  {setup_str:>12s}  {sign_t*1000:.3f} ms"
              f"  {verify_t*1000:.3f} ms  {ws:>6d} B")

    print()
    print("  Python benchmarks (reference only — expect ~1000x slower):")
    print(f"  {'K':>10s}  {'Keygen':>12s}  {'Sign':>10s}  {'Verify':>10s}")
    print(f"  {'-'*10}  {'-'*12}  {'-'*10}  {'-'*10}")

    for K in [4, 16, 64]:
        addr = keygen(master_seed, K=K)
        kg_t = benchmark_keygen(K, master_seed, repeats=3)
        s_t = benchmark_sign(addr, msg_hash, repeats=5)
        v_t = benchmark_verify(addr, msg_hash, repeats=5)
        print(f"  {K:>10,d}  {kg_t*1000:>10.1f}ms  {s_t*1000:>8.1f}ms  {v_t*1000:>8.1f}ms")

    print()
    print("  Note: Python is ~1000x slower than optimized C/Rust with SHA-NI.")
    print("  The theoretical numbers above reflect production performance.")


if __name__ == "__main__":
    main()
