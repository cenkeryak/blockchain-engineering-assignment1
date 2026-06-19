import hashlib
import pytest

from src.core import (
    ZERO32,
    BlockHeader,
    count_leading_zero_bits,
    make_genesis,
    mine_block,
    satisfies_pow,
    tx_hash,
    txs_hash,
    u32_be,
    u64_be,
    validate_block,
    validate_chain,
)


def test_u64_big_endian():
    assert u64_be(1) == b"\x00\x00\x00\x00\x00\x00\x00\x01"


def test_u32_big_endian():
    assert u32_be(1) == b"\x00\x00\x00\x01"


def test_header_is_84_bytes():
    header = BlockHeader(
        prev_hash=b"a" * 32,
        txs_hash=b"b" * 32,
        timestamp=1,
        difficulty=2,
        nonce=3,
    )

    raw = header.to_bytes()

    assert len(raw) == 84
    assert raw == b"a" * 32 + b"b" * 32 + u64_be(1) + u32_be(2) + u64_be(3)


def test_block_hash_is_sha256_of_header():
    header = BlockHeader(
        prev_hash=b"a" * 32,
        txs_hash=b"b" * 32,
        timestamp=1,
        difficulty=2,
        nonce=3,
    )

    assert header.hash() == hashlib.sha256(header.to_bytes()).digest()


def test_empty_txs_hash_is_sha256_empty_bytes():
    assert txs_hash([]) == hashlib.sha256(b"").digest()


def test_txs_hash_is_flat_concat_not_merkle():
    h1 = b"a" * 32
    h2 = b"b" * 32

    assert txs_hash([h1, h2]) == hashlib.sha256(h1 + h2).digest()


def test_transaction_hash_format():
    sender_key = b"sender"
    data = b"hello"
    timestamp = 123
    signature = b"sig"

    expected = hashlib.sha256(
        sender_key + data + u64_be(timestamp) + signature
    ).digest()

    assert tx_hash(sender_key, data, timestamp, signature) == expected


def test_leading_zero_bits():
    assert count_leading_zero_bits(b"\x00") == 8
    assert count_leading_zero_bits(b"\x00\x0f") == 12
    assert count_leading_zero_bits(b"\x80") == 0
    assert count_leading_zero_bits(b"\x40") == 1
    assert count_leading_zero_bits(b"\x20") == 2


def test_mine_block_satisfies_pow():
    block = mine_block(
        height=1,
        prev_hash=b"x" * 32,
        tx_hashes_=[],
        difficulty=8,
        timestamp=100,
    )

    assert satisfies_pow(block.block_hash, 8)
    assert block.header.prev_hash == b"x" * 32
    assert block.header.txs_hash == txs_hash([])


def test_genesis_is_deterministic():
    g1 = make_genesis(difficulty=8)
    g2 = make_genesis(difficulty=8)

    assert g1.block_hash == g2.block_hash
    assert g1.height == 0
    assert g1.header.prev_hash == ZERO32
    assert g1.header.timestamp == 0


def test_valid_chain():
    genesis = make_genesis(difficulty=8)

    tx1 = b"a" * 32
    b1 = mine_block(
        height=1,
        prev_hash=genesis.block_hash,
        tx_hashes_=[tx1],
        difficulty=8,
        timestamp=101,
    )

    b2 = mine_block(
        height=2,
        prev_hash=b1.block_hash,
        tx_hashes_=[],
        difficulty=8,
        timestamp=102,
    )

    validate_chain([genesis, b1, b2])


def test_reject_wrong_prev_hash():
    genesis = make_genesis(difficulty=8)

    bad = mine_block(
        height=1,
        prev_hash=b"z" * 32,
        tx_hashes_=[],
        difficulty=8,
        timestamp=101,
    )

    with pytest.raises(ValueError, match="Invalid prev_hash"):
        validate_block(bad, genesis)


def test_reject_wrong_body_commitment():
    genesis = make_genesis(difficulty=8)

    block = mine_block(
        height=1,
        prev_hash=genesis.block_hash,
        tx_hashes_=[b"a" * 32],
        difficulty=8,
        timestamp=101,
    )

    tampered = type(block)(
        height=block.height,
        header=block.header,
        tx_hashes=[b"b" * 32],
    )

    with pytest.raises(ValueError, match="Invalid txs_hash"):
        validate_block(tampered, genesis)