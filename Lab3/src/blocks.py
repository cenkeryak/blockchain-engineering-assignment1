"""Block and transaction primitives for the Lab 3 PoW blockchain."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from ipv8.keyvault.crypto import default_eccrypto

HASH_SIZE = 32
# The header field is uint64 big-endian, but IPv8's "q" wire type is a signed
# int64 — keep nonces below 2^63 so both encodings agree.
NONCE_MASK = (1 << 63) - 1

# Difficulty (leading zero bits) every node mines at. With 3 miners this gives
# a new block every few seconds, fast enough to bury the test transaction.
DIFFICULTY = 25

RETRY_INITIAL_DELAY = 2.0
RETRY_MAX_DELAY = 30.0
MAX_RETRIES = 5


def pack_header(prev_hash: bytes, txs_hash: bytes, timestamp: int, difficulty: int, nonce: int) -> bytes:
    """84-byte header: prev_hash | txs_hash | timestamp(8be) | difficulty(4be) | nonce(8be)."""
    return (
        prev_hash
        + txs_hash
        + timestamp.to_bytes(8, "big")
        + difficulty.to_bytes(4, "big")
        + nonce.to_bytes(8, "big")
    )


def leading_zero_bits(digest: bytes) -> int:
    return len(digest) * 8 - int.from_bytes(digest, "big").bit_length()


def meets_difficulty(block_hash: bytes, difficulty: int) -> bool:
    return leading_zero_bits(block_hash) >= difficulty


def txs_commitment(tx_hashes: list[bytes]) -> bytes:
    """Body commitment. Empty block -> SHA256(b"")."""
    return sha256(b"".join(tx_hashes)).digest()


@dataclass
class Transaction:
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes

    @property
    def tx_hash(self) -> bytes:
        return sha256(
            self.sender_key + self.data + self.timestamp.to_bytes(8, "big") + self.signature
        ).digest()

    def verify(self) -> bool:
        try:
            key = default_eccrypto.key_from_public_bin(self.sender_key)
        except Exception:
            return False
        message = self.sender_key + self.data + self.timestamp.to_bytes(8, "big")
        return default_eccrypto.is_valid_signature(key, message, self.signature)


@dataclass
class Block:
    height: int
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    block_hash: bytes
    tx_hashes: list[bytes]
    

    def is_internally_valid(self) -> bool:
        """PoW holds, block_hash matches the header, and the body commitment matches."""
        if len(self.prev_hash) != HASH_SIZE or len(self.txs_hash) != HASH_SIZE:
            return False
        if self.height > 0 and self.difficulty < 1:
            return False
        header = pack_header(self.prev_hash, self.txs_hash, self.timestamp, self.difficulty, self.nonce)
        return (
            sha256(header).digest() == self.block_hash
            and meets_difficulty(self.block_hash, self.difficulty)
            and txs_commitment(self.tx_hashes) == self.txs_hash
        )


def make_block(height: int, prev_hash: bytes, tx_hashes: list[bytes],
               timestamp: int, difficulty: int, nonce: int) -> Block:
    txs_hash = txs_commitment(tx_hashes)
    header = pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce)
    return Block(height, prev_hash, txs_hash, timestamp, difficulty, nonce,
                 sha256(header).digest(), tx_hashes)


def genesis_block() -> Block:
    """Fixed group-wide genesis; every node boots with this exact block 0."""
    return make_block(0, b"\x00" * HASH_SIZE, [], 0, 0, 0)

class Blockchain:
    def __init__(self):
        self.chain: list[Block] = [genesis_block()]
        self.block_pool: dict[bytes, Block] = {}
        self.mempool: dict[bytes, Transaction] = {}
        self.chain_tx_hashes: set[bytes] = set()
       

    @property
    def height(self) -> int:
        return len(self.chain) - 1

    @property
    def tip(self) -> Block:
        return self.chain[-1]

    def accept_transaction(self, tx: Transaction) -> bool:
        if tx.tx_hash in self.chain_tx_hashes:
            return False

        if tx.tx_hash in self.mempool:
            return False

        self.mempool[tx.tx_hash] = tx
        return True

    def pending_tx_hashes(self) -> list[bytes]:
        return [txh for txh in self.mempool if txh not in self.chain_tx_hashes]

    def validate_block_transactions(self, block: Block) -> tuple[bool, list[bytes]]:
        # Only the position-independent checks live here: no duplicate hashes
        # inside the block, and every referenced tx is known and validly signed.
        # We deliberately do NOT reject a tx just because it is already in our
        # active chain — a competing fork may re-include it because the blocks
        # holding it are about to be rolled back. That double-spend decision is
        # context-dependent and is made against the post-fork chain in try_adopt.
        if len(block.tx_hashes) != len(set(block.tx_hashes)):
            return False, []

        missing_txs = []

        for tx_hash in block.tx_hashes:
            tx = self.mempool.get(tx_hash)

            if tx is None:
                missing_txs.append(tx_hash)
                continue

            if not tx.verify():
                return False, []

        return True, missing_txs


    def add_block(self, block: Block) -> tuple[bool, int | None, list[bytes]]:
        if block.block_hash in self.block_pool:
            return False, None, []

        if not block.is_internally_valid():
            return False, None, []

        txs_valid, missing_txs = self.validate_block_transactions(block)

        if not txs_valid:
            return False, None, []

        self.block_pool[block.block_hash] = block

        if missing_txs:
            return False, None, missing_txs
        
        missing_block = self.try_adopt()
        return True, missing_block, []

    def branch_double_spend(self, fork_point: int, branch_blocks: list[Block]) -> bool:
        """Would this branch put the same transaction in the chain twice?

        We measure against the chain the branch would actually create: the prefix
        we keep (chain[:fork_point + 1]) plus the branch blocks themselves. The
        blocks above the fork point are rolled back, so any tx they hold is freed
        and a fork is free to re-include it without it counting as a double-spend.
        """
        seen = {txh for b in self.chain[:fork_point + 1] for txh in b.tx_hashes}
        for block in branch_blocks:
            for tx_hash in block.tx_hashes:
                if tx_hash in seen:
                    return True
                seen.add(tx_hash)
        return False

    def try_adopt(self) -> int | None:
        missing_height = None
        for block in sorted(self.block_pool.values(), key=lambda b: (-b.height, b.block_hash)):
            if block.height <= self.height and self.chain[block.height].block_hash == block.block_hash:
                continue
            
            txs_valid, missing_txs = self.validate_block_transactions(block)

            if not txs_valid or missing_txs:
                continue

            branch, fork_point, missing = self.trace_branch(block)

            if fork_point is None:
                if missing is not None:
                    missing_height = missing
                continue

            branch_blocks = list(reversed(branch))

            # Reject a branch only if it genuinely double-spends within the chain
            # it would create — not just because the tx still sits in the chain we
            # are about to abandon. Without this, two miners that each mine the
            # same transaction at the same height stay stuck on their own block:
            # neither can ever adopt the other's competing branch.
            if self.branch_double_spend(fork_point, branch_blocks):
                continue

            tip = self.tip
            longer = block.height > tip.height
            tie_win = block.height == tip.height and block.block_hash < tip.block_hash

            if longer or tie_win:
                self.chain = self.chain[:fork_point + 1] + branch_blocks
                self.chain_tx_hashes = {txh for b in self.chain for txh in b.tx_hashes}
                break

        cutoff = self.height - 10
        for block_hash in [h for h, b in self.block_pool.items() if b.height < cutoff]:
            del self.block_pool[block_hash]
        
        return missing_height

    def trace_branch(self, block: Block):
        branch = []
        cur = block

        while True:
            branch.append(cur)
            parent_height = cur.height - 1

            if parent_height < len(self.chain) and self.chain[parent_height].block_hash == cur.prev_hash:
                return branch, parent_height, None

            parent = self.block_pool.get(cur.prev_hash)

            if parent is None or parent.height != parent_height:
                return branch, None, parent_height if parent_height >= 1 else None

            cur = parent