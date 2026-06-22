"""Block and transaction primitives for the Lab 3 PoW blockchain.

This file carries the combined bonus implementation:

* Bonus 4 (fork convergence after a partition): work-based fork choice,
  bounded reorg depth, and an atomic branch switch that returns orphaned
  transactions to the mempool. See ``try_adopt`` / ``switch_chain``.
* Bonus 5 (adaptive difficulty): a deterministic retargeting controller and a
  median-time-past timestamp rule. See ``expected_difficulty`` /
  ``median_time_past``.

The two fit together: adaptive difficulty makes per-block difficulty vary, and
work-based fork choice is exactly what is needed to compare variable-difficulty
branches correctly.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from hashlib import sha256

from ipv8.keyvault.crypto import default_eccrypto

HASH_SIZE = 32
# The header field is uint64 big-endian, but IPv8's "q" wire type is a signed
# int64 — keep nonces below 2^63 so both encodings agree.
NONCE_MASK = (1 << 63) - 1

# Bootstrap difficulty (leading zero bits): used for the first DIFFICULTY_WINDOW
# blocks, before there is enough history to retarget. After that the adaptive
# controller (Bonus 5) takes over.
DIFFICULTY = 25

RETRY_INITIAL_DELAY = 2.0
RETRY_MAX_DELAY = 30.0
MAX_RETRIES = 5

# --- Bonus 4: fork convergence after a partition ---------------------------
#
# A branch is never chosen on length alone. Length is trivial to fake: a peer
# can splice many low-difficulty blocks together for almost no cost and hand you
# a chain that is "longer" but carries no real work. We choose the branch with
# the most accumulated proof-of-work, and (with Bonus 5) we also require every
# block to use the difficulty the retarget schedule mandates — so a fake branch
# would have to do the same real work as the honest one to compete.

# A reorg is the act of rolling back our own confirmed blocks to follow a
# competing branch. We cap how far back that can reach. A partition that heals
# legitimately needs only as deep a reorg as the partition was long; an attacker
# trying to rewrite ancient history needs an unbounded one. Bounding the depth
# keeps a single bad peer from rewriting the whole ledger and keeps the rebuild
# cheap. Sized for several minutes of partition at our block rate.
MAX_REORG_DEPTH = 256

# --- Bonus 5: adaptive difficulty ------------------------------------------
#
# We want a steady block interval through a tenfold swing in hashpower, settling
# without oscillation, and unmovable by one miner lying about timestamps.
# ``expected_difficulty`` estimates the network hashrate from recent blocks and
# aims straight at the equilibrium difficulty; taking the MEDIAN of the per-block
# estimates makes it deaf to a single liar, and clamping each solve time bounds
# how far one timestamp can reach. ``median_time_past`` rejects backdating, and
# ``MAX_FUTURE_TIME`` rejects blocks that are far ahead of the receiver's clock.
TARGET_BLOCK_TIME = 10.0   # seconds we want between blocks
DIFFICULTY_WINDOW = 11     # blocks of history the retarget looks at
SOLVE_CLAMP_LOW = 1.0      # a counted solve time is never below this...
SOLVE_CLAMP_HIGH = 6 * TARGET_BLOCK_TIME  # ...nor above this (caps a liar's reach)
MEDIAN_TIME_BLOCKS = 11    # window for the median-time-past timestamp rule
MIN_DIFFICULTY = 4         # floor: never mine/accept below this
MAX_DIFFICULTY = 48        # ceiling on difficulty
MAX_FUTURE_TIME = 120      # reject peer block times more than this many seconds ahead


def block_work(difficulty: int) -> int:
    """Expected hashes to mine a block at this difficulty == 2**difficulty.

    Summed over a chain this gives total accumulated work, the quantity two
    competing branches are actually compared on.
    """
    return 1 << max(difficulty, 0)


def chain_work(blocks: list["Block"]) -> int:
    return sum(block_work(b.difficulty) for b in blocks)


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def expected_difficulty(chain: list["Block"]) -> int:
    """Difficulty the next block (the one extending `chain`) must use.

    Deterministic and identical on every node, so the whole group mines at the
    same adaptive difficulty without exchanging a single extra message. We
    recover a hashrate estimate from each recent block (a block of difficulty D
    solved in `st` seconds implies 2**D / st hashes/s), take the median over a
    window (robust to one liar), and pick the difficulty whose expected solve
    time equals the target. Aiming at the equilibrium rather than nudging a
    controller means no overshoot and no ringing.
    """
    real = [b for b in chain if b.height >= 1]  # genesis has a placeholder ts
    if len(real) <= DIFFICULTY_WINDOW:
        return DIFFICULTY  # bootstrap: not enough history to retarget yet

    window = real[-(DIFFICULTY_WINDOW + 1):]
    hashrate_samples = []
    for prev, cur in zip(window, window[1:]):
        solve = cur.timestamp - prev.timestamp
        solve = min(max(float(solve), SOLVE_CLAMP_LOW), SOLVE_CLAMP_HIGH)
        hashrate_samples.append(block_work(cur.difficulty) / solve)

    hashrate = _median(hashrate_samples)
    difficulty = round(math.log2(hashrate * TARGET_BLOCK_TIME))
    return max(MIN_DIFFICULTY, min(MAX_DIFFICULTY, int(difficulty)))


def median_time_past(chain: list["Block"]) -> int:
    """Median of the most recent real-block timestamps.

    A new block must be strictly newer than this, which neutralises a miner that
    backdates its clock: the median of the window is robust to a single outlier.
    """
    stamps = [b.timestamp for b in chain if b.height >= 1][-MEDIAN_TIME_BLOCKS:]
    if not stamps:
        return 0
    return sorted(stamps)[len(stamps) // 2]


def timestamp_is_valid(chain: list["Block"], timestamp: int, now: int | None = None) -> bool:
    """A block timestamp must move forward and not be far ahead of local time."""
    if timestamp <= median_time_past(chain):
        return False
    if now is None:
        now = int(time.time())
    return timestamp <= now + MAX_FUTURE_TIME


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
    transactions: list[Transaction]
    

    def is_internally_valid(self) -> bool:
        """PoW holds, block_hash matches the header, and the body commitment matches."""
        if len(self.prev_hash) != HASH_SIZE or len(self.txs_hash) != HASH_SIZE:
            return False
        # Reject blocks that do not clear the difficulty floor (height 0 is the
        # fixed group genesis and is exempt). This is the first line of defence
        # against a "longer but fake" branch built from cheap, low-work blocks.
        if self.height > 0 and self.difficulty < MIN_DIFFICULTY:
            return False
        header = pack_header(self.prev_hash, self.txs_hash, self.timestamp, self.difficulty, self.nonce)
        return (
            sha256(header).digest() == self.block_hash
            and meets_difficulty(self.block_hash, self.difficulty)
            and txs_commitment(self.tx_hashes) == self.txs_hash
        )


def make_block(height: int, prev_hash: bytes, transactions: list[Transaction],
               timestamp: int, difficulty: int, nonce: int) -> Block:
    tx_hashes = [tx.tx_hash for tx in transactions]
    txs_hash = txs_commitment(tx_hashes)
    header = pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce)
    return Block(height, prev_hash, txs_hash, timestamp, difficulty, nonce,
                 sha256(header).digest(), tx_hashes, list(transactions))


def genesis_block() -> Block:
    """Fixed group-wide genesis; every node boots with this exact block 0."""
    return make_block(0, b"\x00" * HASH_SIZE, [], 0, 0, 0)


class Blockchain:
    def __init__(self):
        self.chain: list[Block] = [genesis_block()]
        self.block_pool: dict[bytes, Block] = {}
        # Pending pool: transactions not yet on the active chain. A tx referenced
        # by an unconfirmed block in the block pool stays here until that branch
        # wins (or the tx is orphaned back here after a reorg).
        self.mempool: dict[bytes, Transaction] = {}
        self.chain_tx_hashes: set[bytes] = set()
        # Bonus 4 telemetry: how many reorgs we have performed, the depth of the
        # last one, and how many transactions the last reorg returned to the
        # mempool. Useful for the convergence demo/tests and for proving that no
        # transaction is lost when we switch branches.
        self.reorg_count: int = 0
        self.last_reorg_depth: int = 0
        self.last_orphaned_txs: list[bytes] = []


    @property
    def height(self) -> int:
        return len(self.chain) - 1

    @property
    def tip(self) -> Block:
        return self.chain[-1]

    @property
    def total_work(self) -> int:
        """Accumulated proof-of-work of the active chain (the fork-choice metric)."""
        return chain_work(self.chain)

    def next_difficulty(self) -> int:
        """Difficulty the next mined block must declare (the adaptive target)."""
        return expected_difficulty(self.chain)

    def valid_difficulty_and_time(self, kept_prefix: list[Block], branch_blocks: list[Block]) -> bool:
        """Every block in the branch must use the mandated difficulty and a sane timestamp.

        This turns the adaptive controller into a *consensus rule*: a miner cannot
        declare an easier difficulty than the schedule allows (which would also be
        the cheap way to fake a "longer" branch), backdate a block to skew the
        retarget, or future-date it far beyond the receiver's clock. The schedule
        and median-time-past checks depend only on prior blocks, so they are
        deterministic across nodes; the future-time window is a local admission
        guard with slack for ordinary clock skew.
        """
        prefix = list(kept_prefix)
        for block in branch_blocks:
            if block.difficulty != expected_difficulty(prefix):
                return False
            if not timestamp_is_valid(prefix, block.timestamp):
                return False
            prefix.append(block)
        return True

    def accept_transaction(self, tx: Transaction) -> bool:
        """Index a tx for lookup and attach it to waiting blocks.

        Returns True only when the tx is newly added to the mempool. A tx that
        is already pending, or already confirmed on the active chain, is still
        attached to any block-pool entry that references it.
        """
        if tx.tx_hash in self.chain_tx_hashes:
            self._attach_transaction_to_waiting_blocks(tx)
            return False

        is_new = tx.tx_hash not in self.mempool
        if is_new:
            self.mempool[tx.tx_hash] = tx

        self._attach_transaction_to_waiting_blocks(tx)
        return is_new

    def pending_tx_hashes(self) -> list[bytes]:
        return [txh for txh in self.mempool if txh not in self.chain_tx_hashes]

    def get_transaction(self, tx_hash: bytes) -> Transaction | None:
        """Look up a transaction from the mempool or the active chain."""
        tx = self.mempool.get(tx_hash)
        if tx is not None:
            return tx
        for block in self.chain:
            for candidate in block.transactions:
                if candidate.tx_hash == tx_hash:
                    return candidate
        return None

    def _attach_transaction_to_waiting_blocks(self, tx: Transaction) -> None:
        """Attach a newly learned tx to blocks in the pool that still need it."""
        for block in self.block_pool.values():
            if tx.tx_hash not in block.tx_hashes:
                continue
            if any(existing.tx_hash == tx.tx_hash for existing in block.transactions):
                continue
            block.transactions.append(tx)

    def _drop_confirmed_from_mempool(self, tx_hashes: list[bytes] | set[bytes]) -> None:
        """Remove transactions from the pending pool once they are on the active chain."""
        for tx_hash in tx_hashes:
            self.mempool.pop(tx_hash, None)

    def validate_block_transactions(self, block: Block) -> tuple[bool, list[bytes]]:
        # Position-independent checks: no duplicate hashes inside the block, every
        # embedded tx is listed in the header commitment, and every listed hash that
        # we have a body for is validly signed. We deliberately do NOT reject a tx
        # just because it is already in our active chain — a competing fork may
        # re-include it because the blocks holding it are about to be rolled back.
        # That double-spend decision is context-dependent and is made in try_adopt.
        if len(block.tx_hashes) != len(set(block.tx_hashes)):
            return False, []

        if len(block.transactions) != len({tx.tx_hash for tx in block.transactions}):
            return False, []

        committed = set(block.tx_hashes)
        for tx in block.transactions:
            if tx.tx_hash not in committed:
                return False, []

        embedded = {tx.tx_hash: tx for tx in block.transactions}
        missing_txs = []

        for tx_hash in block.tx_hashes:
            tx = embedded.get(tx_hash)
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

        for tx in block.transactions:
            self.accept_transaction(tx)

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

    def branch_transactions_available(self, branch_blocks: list[Block]) -> bool:
        """Every block we would adopt must reference known, valid transactions."""
        for block in branch_blocks:
            txs_valid, missing_txs = self.validate_block_transactions(block)
            if not txs_valid or missing_txs:
                return False
        return True

    def try_adopt(self) -> int | None:
        """Pick the heaviest valid branch reachable from the block pool.

        Combined-bonus fork choice:

        * Every block in a candidate branch must obey the adaptive difficulty
          schedule and the median-time-past timestamp rule (Bonus 5), so a branch
          of cheap off-schedule blocks or one built on backdated timestamps is
          rejected before it is ever considered.
        * Branches are compared on accumulated proof-of-work, not on length, so a
          longer chain made of cheaper blocks cannot displace a heavier honest one
          (Bonus 4).
        * A reorg deeper than ``MAX_REORG_DEPTH`` is refused outright, bounding
          how much history any single peer can make us rewrite (Bonus 4).
        * The switch is one atomic rebind of ``self.chain``; transactions stranded
          on the abandoned blocks are returned to the mempool in the same step, so
          no transaction is ever lost across a fork (Bonus 4).
        """
        missing_height = None
        current_work = self.total_work
        best_candidate: tuple[list[Block], list[Block]] | None = None
        best_work = current_work
        best_tip_hash = self.tip.block_hash

        for block in sorted(self.block_pool.values(), key=lambda b: (-b.height, b.block_hash)):
            if block.height <= self.height and self.chain[block.height].block_hash == block.block_hash:
                continue

            txs_valid, missing_txs = self.validate_block_transactions(block)

            if not txs_valid or missing_txs:
                continue

            branch, fork_point, missing = self.trace_branch(block)

            if fork_point is None:
                if missing is not None:
                    if missing_height is None:
                        missing_height = missing
                continue

            branch_blocks = list(reversed(branch))
            kept_prefix = self.chain[:fork_point + 1]

            # A tip can arrive before its parent, and a parent can arrive before
            # all of its transaction bodies. Validate the whole branch here so a
            # clean tip cannot accidentally pull in an earlier block whose tx data
            # is still missing.
            if not self.branch_transactions_available(branch_blocks):
                continue

            # Bonus 5: a branch is only legal if every block uses the difficulty
            # the retarget mandates for its position and carries a timestamp past
            # the median time. This stops cheap off-schedule blocks and backdating.
            if not self.valid_difficulty_and_time(kept_prefix, branch_blocks):
                continue

            # Bound the reorg: never roll back more than MAX_REORG_DEPTH of our
            # own confirmed blocks. A legitimately healed partition stays well
            # within this; a peer trying to rewrite ancient history does not.
            reorg_depth = self.height - fork_point
            if reorg_depth > MAX_REORG_DEPTH:
                continue

            # Reject a branch only if it genuinely double-spends within the chain
            # it would create — not just because the tx still sits in the chain we
            # are about to abandon. Without this, two miners that each mine the
            # same transaction at the same height stay stuck on their own block:
            # neither can ever adopt the other's competing branch.
            if self.branch_double_spend(fork_point, branch_blocks):
                continue

            prospective_work = chain_work(kept_prefix) + chain_work(branch_blocks)

            # Examine every reachable candidate before switching. With adaptive
            # difficulty, a shorter branch can carry more work than a taller one,
            # so height-sorted iteration is only a fetch/validation convenience,
            # not the fork-choice rule.
            if prospective_work < best_work:
                continue
            if prospective_work == best_work and block.block_hash >= best_tip_hash:
                continue

            best_candidate = (kept_prefix, branch_blocks)
            best_work = prospective_work
            best_tip_hash = block.block_hash

        if best_candidate is not None:
            kept_prefix, branch_blocks = best_candidate
            self.switch_chain(kept_prefix, branch_blocks)

        # Keep the pool deep enough to assemble a full MAX_REORG_DEPTH reorg, but
        # drop anything older so memory stays bounded.
        cutoff = self.height - MAX_REORG_DEPTH
        for block_hash in [h for h, b in self.block_pool.items() if b.height < cutoff]:
            del self.block_pool[block_hash]

        return missing_height

    def switch_chain(self, kept_prefix: list[Block], branch_blocks: list[Block]) -> None:
        """Atomically replace the active chain and return orphaned txs to the mempool.

        The whole switch is a single rebind of ``self.chain`` followed by a
        rebuild of the confirmed-tx index, so an observer never sees a partial
        chain. Any transaction that was confirmed on a block we are discarding
        but is absent from the branch we adopt is put back into the mempool, so
        it can be mined again and is never silently dropped.
        """
        old_blocks_above_fork = self.chain[len(kept_prefix):]

        new_chain = kept_prefix + branch_blocks
        new_tx_hashes = {txh for b in new_chain for txh in b.tx_hashes}

        # Atomic publish of the new tip + its confirmed-tx set.
        self.chain = new_chain
        self.chain_tx_hashes = new_tx_hashes

        orphaned = []
        for stale_block in old_blocks_above_fork:
            for tx in stale_block.transactions:
                if tx.tx_hash in new_tx_hashes:
                    continue  # the branch already re-included it
                # Restore the tx body from the orphaned block back to pending.
                self.mempool[tx.tx_hash] = tx
                orphaned.append(tx.tx_hash)

        self._drop_confirmed_from_mempool(new_tx_hashes)

        if old_blocks_above_fork:  # a genuine rollback, not a plain extension
            self.reorg_count += 1
            self.last_reorg_depth = len(old_blocks_above_fork)
            self.last_orphaned_txs = orphaned

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
