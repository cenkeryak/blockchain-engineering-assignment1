from __future__ import annotations

from dataclasses import dataclass
import hashlib
import time


ZERO32 = b"\x00" * 32


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def u64_be(n: int) -> bytes:
    return n.to_bytes(8, "big", signed=False)


def u32_be(n: int) -> bytes:
    return n.to_bytes(4, "big", signed=False)


def count_leading_zero_bits(data: bytes) -> int:
    count = 0
    for byte in data:
        if byte == 0:
            count += 8
        else:
            count += 8 - byte.bit_length()
            break
    return count


def satisfies_pow(block_hash: bytes, difficulty: int) -> bool:
    return count_leading_zero_bits(block_hash) >= difficulty


def tx_hash(sender_key: bytes, data: bytes, timestamp: int, signature: bytes) -> bytes:
    return sha256(sender_key + data + u64_be(timestamp) + signature)


def txs_hash(tx_hashes: list[bytes]) -> bytes:
    for h in tx_hashes:
        if len(h) != 32:
            raise ValueError("Every tx hash must be 32 bytes")
    return sha256(b"".join(tx_hashes))


@dataclass(frozen=True)
class BlockHeader:
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int

    def to_bytes(self) -> bytes:
        if len(self.prev_hash) != 32:
            raise ValueError("prev_hash must be 32 bytes")
        if len(self.txs_hash) != 32:
            raise ValueError("txs_hash must be 32 bytes")

        return (
            self.prev_hash
            + self.txs_hash
            + u64_be(self.timestamp)
            + u32_be(self.difficulty)
            + u64_be(self.nonce)
        )

    def hash(self) -> bytes:
        return sha256(self.to_bytes())


@dataclass(frozen=True)
class Block:
    height: int
    header: BlockHeader
    tx_hashes: list[bytes]

    @property
    def block_hash(self) -> bytes:
        return self.header.hash()

    @property
    def tx_hashes_blob(self) -> bytes:
        return b"".join(self.tx_hashes)


def mine_block(
    height: int,
    prev_hash: bytes,
    tx_hashes_: list[bytes],
    difficulty: int,
    timestamp: int | None = None,
    start_nonce: int = 0,
) -> Block:
    if timestamp is None:
        timestamp = int(time.time())

    body_hash = txs_hash(tx_hashes_)

    nonce = start_nonce
    while True:
        header = BlockHeader(
            prev_hash=prev_hash,
            txs_hash=body_hash,
            timestamp=timestamp,
            difficulty=difficulty,
            nonce=nonce,
        )

        if satisfies_pow(header.hash(), difficulty):
            return Block(height=height, header=header, tx_hashes=tx_hashes_)

        nonce += 1


def make_genesis(difficulty: int = 8) -> Block:
    return mine_block(
        height=0,
        prev_hash=ZERO32,
        tx_hashes_=[],
        difficulty=difficulty,
        timestamp=0,
    )


def validate_block(block: Block, prev_block: Block | None) -> None:
    if block.header.txs_hash != txs_hash(block.tx_hashes):
        raise ValueError("Invalid txs_hash")

    if not satisfies_pow(block.block_hash, block.header.difficulty):
        raise ValueError("Invalid PoW")

    if prev_block is None:
        if block.height != 0:
            raise ValueError("Genesis must have height 0")
        if block.header.prev_hash != ZERO32:
            raise ValueError("Genesis prev_hash must be zero")
    else:
        if block.height != prev_block.height + 1:
            raise ValueError("Invalid height")
        if block.header.prev_hash != prev_block.block_hash:
            raise ValueError("Invalid prev_hash")


def validate_chain(chain: list[Block]) -> None:
    if not chain:
        raise ValueError("Empty chain")

    validate_block(chain[0], None)

    for prev, curr in zip(chain, chain[1:]):
        validate_block(curr, prev)