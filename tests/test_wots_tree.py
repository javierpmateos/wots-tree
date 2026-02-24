"""
Test suite for WOTS-Tree v6.4

Tests organized by paper section:
  - Test vectors (Appendix B)
  - Witness sizes (Table 1)
  - Setup hash counts (Appendix A)
  - Sign/verify correctness (Section 4)
  - Security edge cases (Section 5)
"""

import hashlib
import math
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.wots_tree import (
    PARAMS,
    WOTSTreeParams,
    build_merkle_tree,
    derive_chain_seed,
    derive_secret_key,
    get_auth_path,
    h_chain,
    h_tree,
    keygen,
    msg_to_digits,
    setup_hashes,
    sign,
    verify,
    verify_auth_path,
    verification_hashes,
    witness_size,
    wots_keygen,
    wots_sign,
    wots_verify,
)


# ===========================================================================
# Section 1: Paper test vectors (Appendix B)
# ===========================================================================

class TestVectors(unittest.TestCase):
    """Verify against test vectors from the paper (Appendix B)."""

    def setUp(self):
        self.master_seed = b"\x00" * 32
        self.deriv_idx = 0

    def test_chain_seed_derivation(self):
        """chain_seed = HMAC(master_seed, 'WOTS-TREE' || uint32(0))"""
        cs = derive_chain_seed(self.master_seed, self.deriv_idx)
        expected = bytes.fromhex(
            "ec90155ffe6f55cb87470ac8cf2c566e"
            "df78c68a4e5cd1552087dd238efcf032"
        )
        self.assertEqual(cs, expected)

    def test_sk_0_0_derivation(self):
        """sk_{0,0} = HMAC(chain_seed, toByte(0,2) || toByte(0,1))[0:16]"""
        cs = derive_chain_seed(self.master_seed, self.deriv_idx)
        sk = derive_secret_key(cs, 0, 0, 1024)
        expected = bytes.fromhex("428b70877eb337c8cc1d094da5ee6b85")
        self.assertEqual(sk, expected)
        self.assertEqual(len(sk), PARAMS.n)

    def test_chain_seed_length(self):
        """chain_seed must be full 256 bits (32 bytes)."""
        cs = derive_chain_seed(self.master_seed, self.deriv_idx)
        self.assertEqual(len(cs), 32)


# ===========================================================================
# Section 2: Parameter validation (Section 3)
# ===========================================================================

class TestParams(unittest.TestCase):
    """Verify parameter calculations from the paper."""

    def test_default_params(self):
        self.assertEqual(PARAMS.n, 16)
        self.assertEqual(PARAMS.w, 256)
        self.assertEqual(PARAMS.ell_1, 16)
        self.assertEqual(PARAMS.ell_2, 2)
        self.assertEqual(PARAMS.ell, 18)
        self.assertEqual(PARAMS.tree_hash_len, 32)

    def test_tightness_loss(self):
        """ℓ(w-1) = 4590, log₂(4590) ≈ 12.16 (Section 5.3)."""
        tightness = PARAMS.ell * (PARAMS.w - 1)
        self.assertEqual(tightness, 4590)
        loss = math.log2(tightness)
        self.assertAlmostEqual(loss, 12.164, places=2)

    def test_security_bits(self):
        """115.8-bit classical, 57.9-bit quantum (Section 5.4)."""
        loss = math.log2(PARAMS.ell * (PARAMS.w - 1))
        classical = 8 * PARAMS.n - loss
        quantum = classical / 2
        self.assertAlmostEqual(classical, 115.84, places=1)
        self.assertAlmostEqual(quantum, 57.92, places=1)


# ===========================================================================
# Section 3: Witness sizes (Table 1)
# ===========================================================================

class TestWitnessSizes(unittest.TestCase):
    """Verify witness sizes match Table 1 in the paper."""

    def test_k1_hardened(self):
        self.assertEqual(witness_size(1, mode="hardened"), 353)

    def test_k1024_hardened(self):
        self.assertEqual(witness_size(1024, mode="hardened"), 675)

    def test_k65536_hardened(self):
        self.assertEqual(witness_size(65536, mode="hardened"), 867)

    def test_k2m_hardened(self):
        self.assertEqual(witness_size(2**21, mode="hardened"), 1028)

    def test_k1024_compact(self):
        self.assertEqual(witness_size(1024, mode="compact"), 515)

    def test_k65536_compact(self):
        self.assertEqual(witness_size(65536, mode="compact"), 611)

    def test_k2m_compact(self):
        self.assertEqual(witness_size(2**21, mode="compact"), 692)


# ===========================================================================
# Section 4: Setup hash counts (Appendix A)
# ===========================================================================

class TestSetupHashes(unittest.TestCase):
    """Verify setup hash counts match Appendix A."""

    def test_per_leaf_cost(self):
        """ℓ + ℓ(w-1) + 1 = 4609 per leaf."""
        per_leaf = PARAMS.ell + PARAMS.ell * (PARAMS.w - 1) + 1
        self.assertEqual(per_leaf, 4609)

    def test_k1024_total(self):
        self.assertEqual(setup_hashes(1024), 4_720_639)

    def test_k65536_total(self):
        total = setup_hashes(65536)
        # 65536 × 4609 + 65535 = 302,120,959
        self.assertEqual(total, 302_120_959)

    def test_k2m_total(self):
        self.assertEqual(setup_hashes(2**21), 9_667_870_719)

    def test_k1024_time(self):
        """9.44 ms at 500 MH/s."""
        time_s = setup_hashes(1024) / 500_000_000
        self.assertAlmostEqual(time_s * 1000, 9.44, places=1)

    def test_k2m_time(self):
        """19.34 s at 500 MH/s."""
        time_s = setup_hashes(2**21) / 500_000_000
        self.assertAlmostEqual(time_s, 19.34, places=1)


# ===========================================================================
# Section 5: Verification hash counts (Section 6)
# ===========================================================================

class TestVerificationHashes(unittest.TestCase):
    """Verify max verification hash count."""

    def test_max_verify_k1(self):
        # ℓ(w-1) + 1 + 0 = 4591
        self.assertEqual(verification_hashes(K=1), 4591)

    def test_max_verify_k1024(self):
        # ℓ(w-1) + 1 + 10 = 4601
        self.assertEqual(verification_hashes(K=1024), 4601)

    def test_max_verify_k2m(self):
        # ℓ(w-1) + 1 + 21 = 4612
        self.assertEqual(verification_hashes(K=2**21), 4612)


# ===========================================================================
# Section 6: Sign/verify correctness (Section 4)
# ===========================================================================

class TestSignVerify(unittest.TestCase):
    """End-to-end sign and verify tests."""

    def setUp(self):
        self.master_seed = b"\x00" * 32
        self.addr = keygen(self.master_seed, deriv_idx=0, K=16)
        self.msg = h_chain(b"test message for WOTS-Tree v6.4!")

    def test_sign_verify_idx0(self):
        w = sign(self.addr, self.msg, spend_idx=0)
        self.assertTrue(
            verify(w, self.msg, self.addr.tree.root, 16, self.addr.public_seed)
        )

    def test_sign_verify_last_idx(self):
        w = sign(self.addr, self.msg, spend_idx=15)
        self.assertTrue(
            verify(w, self.msg, self.addr.tree.root, 16, self.addr.public_seed)
        )

    def test_sign_verify_multiple_indices(self):
        """Each leaf produces a valid, independent signature."""
        for idx in [0, 5, 10, 15]:
            w = sign(self.addr, self.msg, spend_idx=idx)
            self.assertTrue(
                verify(w, self.msg, self.addr.tree.root, 16, self.addr.public_seed)
            )

    def test_different_messages(self):
        """Different messages at different indices all verify."""
        for idx in range(4):
            msg = h_chain(f"message number {idx}".encode().ljust(32, b"\x00"))
            w = sign(self.addr, msg, spend_idx=idx)
            self.assertTrue(
                verify(w, msg, self.addr.tree.root, 16, self.addr.public_seed)
            )

    def test_wrong_message_fails(self):
        w = sign(self.addr, self.msg, spend_idx=0)
        bad_msg = h_chain(b"wrong message padded to 32 bytes")
        self.assertFalse(
            verify(w, bad_msg, self.addr.tree.root, 16, self.addr.public_seed)
        )

    def test_wrong_root_fails(self):
        w = sign(self.addr, self.msg, spend_idx=0)
        bad_root = b"\xff" * 32
        self.assertFalse(
            verify(w, self.msg, bad_root, 16, self.addr.public_seed)
        )

    def test_actual_witness_size(self):
        """Serialized witness matches expected size."""
        w = sign(self.addr, self.msg, spend_idx=0)
        expected = witness_size(16, mode="hardened")
        self.assertEqual(w.total_size(16), expected)


# ===========================================================================
# Section 7: Security edge cases (Section 5)
# ===========================================================================

class TestSecurityEdgeCases(unittest.TestCase):
    """Security-relevant edge cases."""

    def test_index_overflow_raises(self):
        addr = keygen(b"\x00" * 32, K=4)
        msg = h_chain(b"test" * 8)
        with self.assertRaises(ValueError):
            sign(addr, msg, spend_idx=4)

    def test_chain_independence(self):
        """Different leaf positions derive independent keys (Section 5.5)."""
        cs = derive_chain_seed(b"\x00" * 32, 0)
        keys = [derive_secret_key(cs, j, 0, 1024) for j in range(10)]
        # All keys must be distinct
        self.assertEqual(len(set(keys)), 10)

    def test_chain_index_independence(self):
        """Different chain indices derive independent keys."""
        cs = derive_chain_seed(b"\x00" * 32, 0)
        keys = [derive_secret_key(cs, 0, i, 1024) for i in range(18)]
        self.assertEqual(len(set(keys)), 18)

    def test_different_deriv_idx(self):
        """Different deriv_idx produce different chain_seeds."""
        seeds = [derive_chain_seed(b"\x00" * 32, i) for i in range(10)]
        self.assertEqual(len(set(seeds)), 10)

    def test_msg_digest_with_checksum(self):
        """Checksum digits are valid base-256 digits."""
        msg = bytes(range(16))  # 16-byte message hash
        digits = msg_to_digits(msg)
        self.assertEqual(len(digits), 18)
        for d in digits:
            self.assertGreaterEqual(d, 0)
            self.assertLessEqual(d, 255)

    def test_checksum_prevents_trivial_forgery(self):
        """Increasing a message digit increases checksum → can't forge."""
        msg1 = b"\x00" * 16
        msg2 = b"\x01" + b"\x00" * 15
        d1 = msg_to_digits(msg1)
        d2 = msg_to_digits(msg2)
        # msg2 has higher digit[0], so checksum should be lower
        cs1 = d1[16] * 256 + d1[17]
        cs2 = d2[16] * 256 + d2[17]
        self.assertGreater(cs1, cs2)


# ===========================================================================
# Section 8: Merkle tree (Section 3.2)
# ===========================================================================

class TestMerkleTree(unittest.TestCase):
    """Merkle tree construction and verification."""

    def test_build_and_verify_small(self):
        leaves = [h_tree(bytes([i]) * 32) for i in range(4)]
        tree = build_merkle_tree(leaves)
        self.assertEqual(tree.depth, 2)

        for idx in range(4):
            path = get_auth_path(tree, idx)
            self.assertTrue(
                verify_auth_path(leaves[idx], idx, path, tree.root, 2)
            )

    def test_auth_path_sizes_hardened(self):
        """Auth path elements are 32 bytes (H_tree output)."""
        addr = keygen(b"\x00" * 32, K=16)
        path = get_auth_path(addr.tree, 0)
        self.assertEqual(len(path), 4)  # depth = log2(16) = 4
        for sibling in path:
            self.assertEqual(len(sibling), 32)

    def test_wrong_auth_path_fails(self):
        leaves = [h_tree(bytes([i]) * 32) for i in range(4)]
        tree = build_merkle_tree(leaves)
        path = get_auth_path(tree, 0)
        # Corrupt one sibling
        bad_path = [b"\xff" * 32] + path[1:]
        self.assertFalse(
            verify_auth_path(leaves[0], 0, bad_path, tree.root, 2)
        )


# ===========================================================================
# Section 9: Hash function properties
# ===========================================================================

class TestHashFunctions(unittest.TestCase):
    """Dual hash design properties."""

    def test_h_chain_truncation(self):
        """H_chain produces n=16 bytes."""
        out = h_chain(b"test")
        self.assertEqual(len(out), 16)

    def test_h_tree_full(self):
        """H_tree produces 32 bytes."""
        out = h_tree(b"test")
        self.assertEqual(len(out), 32)

    def test_h_chain_is_sha256_prefix(self):
        """H_chain(x) = SHA256(x)[0:16]."""
        data = b"reference test data"
        expected = hashlib.sha256(data).digest()[:16]
        self.assertEqual(h_chain(data), expected)

    def test_h_tree_is_sha256(self):
        """H_tree(x) = SHA256(x)."""
        data = b"reference test data"
        expected = hashlib.sha256(data).digest()
        self.assertEqual(h_tree(data), expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
