import hashlib
import struct
import unittest

from lab1_client import has_leading_zero_bits, is_valid_pow, pow_digest, pow_prefix


class ProofOfWorkTests(unittest.TestCase):
    def test_hash_input_uses_newlines_and_big_endian_u64_nonce(self) -> None:
        email = "cyakisir@tudelft.nl"
        github_url = "https://github.com/cenkeryak/blockchain-engineering-assignment1"
        nonce = 42

        expected_input = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n" + struct.pack(">Q", nonce)

        self.assertEqual(pow_prefix(email, github_url) + struct.pack(">Q", nonce), expected_input)
        self.assertEqual(pow_digest(email, github_url, nonce), hashlib.sha256(expected_input).digest())

    def test_leading_zero_bit_check(self) -> None:
        self.assertTrue(has_leading_zero_bits(bytes.fromhex("0000000f" + "ff" * 28), 28))
        self.assertFalse(has_leading_zero_bits(bytes.fromhex("00000010" + "00" * 28), 28))
        self.assertTrue(has_leading_zero_bits(bytes.fromhex("00000010" + "00" * 28), 27))

    def test_known_low_difficulty_nonce(self) -> None:
        email = "cyakisir@tudelft.nl"
        github_url = "https://github.com/cenkeryak/blockchain-engineering-assignment1"

        nonce = 0
        while not is_valid_pow(email, github_url, nonce, difficulty=12):
            nonce += 1

        self.assertTrue(is_valid_pow(email, github_url, nonce, difficulty=12))


if __name__ == "__main__":
    unittest.main()
