"""Blockchain community: chain state, mining, block gossip, and server query handlers.

All 3 nodes mine concurrently. Consensus is accumulated proof-of-work, with a
smaller-tip-hash tie-break on equal work so the group converges deterministically.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import time
from hashlib import sha256

from collections import defaultdict
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.peer import Peer

from src.blocks import (
    HASH_SIZE,
    MAX_REORG_DEPTH,
    NONCE_MASK,
    Block,
    Transaction,
    Blockchain,
    make_block,
    meets_difficulty,
    median_time_past,
    pack_header,
    txs_commitment,
)
from src.payloads import (
    BlockResponse,
    ChainHeightResponse,
    GetBlock,
    GetChainHeight,
    NewBlockGossip,
    SubmitTransaction,
    SubmitTransactionResponse,
    TransactionGossip,
    GetTransaction,
)

RETRY_INITIAL_DELAY = 2.0
RETRY_MAX_DELAY = 30.0
MAX_RETRIES = 5
NONCE_BATCH = 20_000      # hashes per event-loop yield while mining
SYNC_INTERVAL = 5.0       # seconds between tip polls to teammates
PARTITION_RELOAD_INTERVAL = 1.0  # how often we re-read the partition control file
FORCE_PROVIDE_ALL = os.environ.get("COMPACT_PROVIDE_ALL") == "1"


class BlockchainSettings(CommunitySettings):
    member_keys: list = None  # the 3 members' public keys (bytes)
    server_key: bytes = b""


class BlockchainCommunity(Community):
    community_id = b""  # set in main.py before IPv8 starts
    settings_class = BlockchainSettings

    def __init__(self, settings: BlockchainSettings) -> None:
        super().__init__(settings)
        self.member_keys: list[bytes] = settings.member_keys
        self.server_key: bytes = settings.server_key

        self.blockchain = Blockchain()
        # item -> (last_requested_time, retry_count)
        self.missing_block_requests: dict[int, tuple[float, int]] = {}
        self.missing_tx_requests: dict[bytes, tuple[float, int]] = {}

        self.peer_known_txs: dict[Peer, set[bytes]] = defaultdict(set)

        # --- Bonus 4: partition simulation ---------------------------------
        # Teammate keys we are currently cut off from. A peer in this set is
        # treated as if it were not a group member at all: we drop its packets
        # and never send to it. This lets us split the 3 nodes into two groups
        # that cannot reach each other and then heal the split, without touching
        # the real UDP transport.
        self.partitioned_keys: set[bytes] = set()
        self.reorg_count_seen = 0  # for logging reorgs as they happen
        self._init_partition_from_env()

        self.add_message_handler(SubmitTransaction, self.on_submit_transaction)
        self.add_message_handler(GetChainHeight, self.on_get_chain_height)
        self.add_message_handler(GetBlock, self.on_get_block)
        self.add_message_handler(BlockResponse, self.on_block_response)
        self.add_message_handler(ChainHeightResponse, self.on_chain_height_response)
        self.add_message_handler(NewBlockGossip, self.on_new_block)
        self.add_message_handler(TransactionGossip, self.on_transaction_gossip)
        self.add_message_handler(GetTransaction, self.on_get_transaction)

        self.register_task("mine", self.mine_forever)
        self.register_task("sync", self.sync_with_teammates, interval=SYNC_INTERVAL)

        # Optional: a control file (path in $PARTITION_CONTROL_FILE) listing the
        # member hex keys this node is currently cut off from. Re-reading it lets
        # an operator partition and heal a live 3-node deployment by editing one
        # file — split the group, let both halves mine, then clear the file and
        # watch them converge.
        self.partition_control_file = os.environ.get("PARTITION_CONTROL_FILE")
        if self.partition_control_file:
            self.register_task("partition_control", self.reload_partition_control,
                               interval=PARTITION_RELOAD_INTERVAL)

    # --- Bonus 4: partition control -----------------------------------------

    def _init_partition_from_env(self) -> None:
        raw = os.environ.get("PARTITION_FROM")
        if not raw:
            return
        try:
            self.partitioned_keys = {bytes.fromhex(k) for k in json.loads(raw)}
            print(f"[partition] starting partitioned from {len(self.partitioned_keys)} peer(s)")
        except (ValueError, TypeError) as exc:
            print(f"[partition] ignoring malformed PARTITION_FROM: {exc}")

    def set_partition(self, keys: set[bytes]) -> None:
        """Cut this node off from the given teammate public keys."""
        self.partitioned_keys = set(keys)

    def heal_partition(self) -> None:
        """Reconnect to every teammate. Convergence is driven by the next sync."""
        if self.partitioned_keys:
            print("[partition] healed; reconnecting to teammates")
        self.partitioned_keys = set()
        # Don't wait for the next periodic poll — start converging immediately.
        self.sync_with_teammates()

    def reload_partition_control(self) -> None:
        try:
            with open(self.partition_control_file, "r", encoding="utf-8") as fh:
                text = fh.read().strip()
        except FileNotFoundError:
            text = ""
        keys = {bytes.fromhex(k) for k in json.loads(text)} if text else set()
        if keys != self.partitioned_keys:
            healing = bool(self.partitioned_keys) and not keys
            self.partitioned_keys = keys
            print(f"[partition] control file -> cut off from {len(keys)} peer(s)")
            if healing:
                self.sync_with_teammates()

    # --- peer filtering -----------------------------------------------------

    def is_member(self, peer: Peer) -> bool:
        # A partitioned teammate is invisible: we neither accept its packets nor
        # gossip to it, exactly as if the link were down.
        if peer.public_key.key_to_bin() in self.partitioned_keys:
            return False
        return peer.public_key.key_to_bin() in self.member_keys

    def is_trusted(self, peer: Peer) -> bool:
        return self.is_member(peer) or peer.public_key.key_to_bin() == self.server_key

    def member_peers(self) -> list[Peer]:
        return [p for p in self.get_peers() if self.is_member(p)]

    # --- server query handlers ----------------------------------------------
    
    @lazy_wrapper(SubmitTransaction)
    def on_submit_transaction(self, peer: Peer, payload: SubmitTransaction) -> None:
        if not self.is_trusted(peer):
            return
        tx = Transaction(payload.sender_key, payload.data, payload.timestamp, payload.signature)
        if tx.verify():
            is_new = self.blockchain.accept_transaction(tx)
            missing = self.blockchain.try_adopt()
            if missing is not None:
                self.remember_missing_block(missing, peer)
            if is_new:
                self.gossip_transaction_to_members(tx)
            self.ez_send(peer, SubmitTransactionResponse(True, tx.tx_hash, "accepted"))
            print(f"[tx] accepted {tx.tx_hash.hex()[:16]} from server")
        else:
            self.ez_send(peer, SubmitTransactionResponse(False, tx.tx_hash, "invalid signature"))
            print("[tx] rejected transaction with invalid signature")

    @lazy_wrapper(GetChainHeight)
    def on_get_chain_height(self, peer: Peer, payload: GetChainHeight) -> None:
        if not self.is_trusted(peer):
            return
        self.ez_send(peer, ChainHeightResponse(payload.request_id, len(self.blockchain.chain) - 1,
                                               self.blockchain.chain[-1].block_hash))

    @lazy_wrapper(GetBlock)
    def on_get_block(self, peer: Peer, payload: GetBlock) -> None:
        if not self.is_trusted(peer) or not 0 <= payload.height < len(self.blockchain.chain):
            return
        block = self.blockchain.chain[payload.height]
        self.ez_send(peer, BlockResponse(
            block.height, block.prev_hash, block.txs_hash,
            block.timestamp, block.difficulty, block.nonce,
            block.block_hash, b"".join(block.tx_hashes),
        ))
        
    
    def retry_delay(self, retries: int) -> float:
        return min(RETRY_INITIAL_DELAY * (2 ** (retries - 1)), RETRY_MAX_DELAY)

    # --- intra-group messages -------------------------------------------------

    @lazy_wrapper(TransactionGossip)
    def on_transaction_gossip(self, peer: Peer, payload: TransactionGossip) -> None:
        if not self.is_member(peer):
            return
        tx = Transaction(payload.sender_key, payload.data, payload.timestamp, payload.signature)

        if not tx.verify():
            return

        self.peer_known_txs[peer].add(tx.tx_hash)
        
        if self.blockchain.accept_transaction(tx):
            missing = self.blockchain.try_adopt()
            if missing is not None:
                self.remember_missing_block(missing, peer)

            self.gossip_transaction_to_members(tx, exclude=peer)

    @lazy_wrapper(NewBlockGossip)
    def on_new_block(self, peer: Peer, payload: NewBlockGossip) -> None:
        if not self.is_member(peer):
            return

        for tx_payload in payload.provided_txs:
            tx = Transaction(
                tx_payload.sender_key,
                tx_payload.data,
                tx_payload.timestamp,
                tx_payload.signature,
            )

            if tx.verify():
                self.blockchain.accept_transaction(tx)
                self.peer_known_txs[peer].add(tx.tx_hash)

        provided = [
            Transaction(p.sender_key, p.data, p.timestamp, p.signature)
            for p in payload.provided_txs
        ]
        self.handle_block(
            peer,
            payload.height,
            payload.prev_hash,
            payload.txs_hash,
            payload.timestamp,
            payload.difficulty,
            payload.nonce,
            payload.tx_hashes,
            provided,
        )

    @lazy_wrapper(BlockResponse)
    def on_block_response(self, peer: Peer, payload: BlockResponse) -> None:
        if not self.is_member(peer):
            return
        self.handle_block(
            peer, payload.height, payload.prev_hash, payload.txs_hash,
            payload.timestamp, payload.difficulty, payload.nonce,
            payload.tx_hashes,
        )

    def sync_with_teammates(self) -> None:
        for member in self.member_peers():
            self.ez_send(member, GetChainHeight(random.getrandbits(63)))
        
        self.retry_missing_blocks()
        self.retry_missing_transactions()

    @lazy_wrapper(ChainHeightResponse)
    def on_chain_height_response(self, peer: Peer, payload: ChainHeightResponse) -> None:
        """Periodic tip poll: spot a competing branch and fetch its tip.

        After a partition heals, the two halves advertise different tips. We pull
        a teammate's unseen tip whenever it could still force a legal reorg:
        taller/equal tips, plus shorter tips whose fork point may lie inside the
        reorg window. Variable difficulty means a shorter branch can carry more
        work, so height alone is not a safe discovery filter. Fetching the tip
        kicks off a parent-by-parent walk back to the fork point, so only the
        blocks that actually differ are pulled.
        """
        if not self.is_member(peer):
            return
        if payload.height < 1:
            return
        if payload.tip_hash in self.blockchain.block_pool:
            return
        lowest_reorg_tip = max(1, self.blockchain.height - MAX_REORG_DEPTH)
        if payload.height >= lowest_reorg_tip:
            self.request_block(payload.height, peer)

    @lazy_wrapper(GetTransaction)
    def on_get_transaction(self, peer: Peer, payload: GetTransaction) -> None:
        if not self.is_member(peer):
            return

        tx = self.blockchain.get_transaction(payload.tx_hash)
        if tx is None:
            return
        
        self.ez_send(
            peer,
            TransactionGossip(tx.sender_key, tx.data, tx.timestamp, tx.signature),
        )
        # we are assuming received and processed
        self.peer_known_txs[peer].add(tx.tx_hash)

    def retry_missing_transactions(self) -> None:
        now = time.time()

        for tx_hash, (last_requested, retries) in list(self.missing_tx_requests.items()):
            if tx_hash in self.blockchain.mempool or tx_hash in self.blockchain.chain_tx_hashes:
                del self.missing_tx_requests[tx_hash]
                continue

            if retries >= MAX_RETRIES:
                del self.missing_tx_requests[tx_hash]
                continue

            if now - last_requested >= self.retry_delay(retries):
                self.request_transactions([tx_hash])
                self.missing_tx_requests[tx_hash] = (now, retries + 1)

    def retry_missing_blocks(self) -> None:
        now = time.time()

        for height, (last_requested, retries) in list(self.missing_block_requests.items()):

            # A lower-height request may be the parent of a shorter-but-heavier
            # fork. Drop it only once it is too old to matter under the reorg cap.
            if height < max(1, self.blockchain.height - MAX_REORG_DEPTH):
                del self.missing_block_requests[height]
                continue

            # Give up eventually
            if retries >= MAX_RETRIES:
                print(f"[sync] giving up on block {height}")
                del self.missing_block_requests[height]
                continue

            # Not time yet
            if now - last_requested < self.retry_delay(retries):
                continue

            print(f"[sync] retrying block {height} (attempt {retries + 1})")

            self.request_block(height)

            self.missing_block_requests[height] = (
                now,
                retries + 1,
            )

    # --- chain state ----------------------------------------------------------

    def handle_block(self, peer: Peer, height: int, prev_hash: bytes, txs_hash: bytes,
                     timestamp: int, difficulty: int, nonce: int, tx_hashes_blob: bytes,
                     transactions: list[Transaction] | None = None) -> None:
        if height < 1 or len(tx_hashes_blob) % HASH_SIZE != 0:
            return
        tx_hashes = [tx_hashes_blob[i:i + HASH_SIZE] for i in range(0, len(tx_hashes_blob), HASH_SIZE)]
        # Recompute the hash from the header; never trust a received block_hash.
        block_hash = sha256(pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce)).digest()

        for tx in transactions or []:
            if tx.verify():
                self.blockchain.accept_transaction(tx)

        block_transactions = []
        for tx_hash in tx_hashes:
            tx = self.blockchain.get_transaction(tx_hash)
            if tx is not None:
                block_transactions.append(tx)

        block = Block(
            height, prev_hash, txs_hash, timestamp, difficulty, nonce,
            block_hash, tx_hashes, block_transactions,
        )

        accepted, missing, missing_txs = self.blockchain.add_block(block)

        if missing is not None:
            self.remember_missing_block(missing, peer)

        if missing_txs:
            self.remember_missing_transactions(missing_txs, peer)
            return

        if accepted:
            self.missing_block_requests.pop(block.height, None)
            print(f"[block] accepted {block.block_hash.hex()[:16]}")
            self.note_reorg()

    def note_reorg(self) -> None:
        """Log a branch switch once, the moment the chain actually reorganises."""
        if self.blockchain.reorg_count <= self.reorg_count_seen:
            return
        self.reorg_count_seen = self.blockchain.reorg_count
        depth = self.blockchain.last_reorg_depth
        orphaned = self.blockchain.last_orphaned_txs
        print(f"[reorg] switched branch: rolled back {depth} block(s), "
              f"returned {len(orphaned)} tx(s) to mempool, new tip "
              f"{self.blockchain.tip.block_hash.hex()[:16]} at height {self.blockchain.height}")

    def remember_missing_block(self, height: int, peer: Peer | None = None) -> None:
        if height in self.missing_block_requests:
            return

        self.missing_block_requests[height] = (
            time.time(),  # first request time
            1,            # retry count
        )

        self.request_block(height, peer)

    def remember_missing_transactions(
        self,
        tx_hashes: list[bytes],
        peer: Peer | None = None,
    ) -> None:
        now = time.time()
        new_missing = []

        for tx_hash in tx_hashes:
            if tx_hash in self.missing_tx_requests:
                continue

            self.missing_tx_requests[tx_hash] = (now, 1)
            new_missing.append(tx_hash)

        if new_missing:
            self.request_transactions(new_missing, peer)

    def request_block(self, height: int, peer: Peer | None = None) -> None:
        targets = [peer] if peer is not None and self.is_member(peer) else self.member_peers()
        for target in targets:
            self.ez_send(target, GetBlock(height))

    def request_transactions(self, tx_hashes: list[bytes], peer: Peer | None = None) -> None:
        targets = [peer] if peer is not None and self.is_member(peer) else self.member_peers()

        for tx_hash in tx_hashes:
            for target in targets:
                self.ez_send(target, GetTransaction(tx_hash))
        
    def gossip_to_members(self, payload, exclude: Peer | None = None) -> None:
        for member in self.member_peers():
            if exclude is not None and member == exclude:
                continue
            self.ez_send(member, payload)
    
    def gossip_transaction_to_members(self, tx: Transaction, exclude: Peer | None = None) -> None:
        payload = TransactionGossip(tx.sender_key, tx.data, tx.timestamp, tx.signature)

        for member in self.member_peers():
            if exclude is not None and member == exclude:
                continue

            self.ez_send(member, payload)

            # We just sent this tx to that peer, so we assume they know it now.
            self.peer_known_txs[member].add(tx.tx_hash)
    
    def gossip_compact_block_to_members(self, block: Block) -> None:
        for peer in self.member_peers():
            known = self.peer_known_txs.get(peer, set())

            provided_txs = []
            for tx_hash in block.tx_hashes:
                if not FORCE_PROVIDE_ALL and tx_hash in known:
                    continue

                tx = self.blockchain.get_transaction(tx_hash)
                if tx is None:
                    continue

                provided_txs.append(
                    TransactionGossip(
                        tx.sender_key,
                        tx.data,
                        tx.timestamp,
                        tx.signature,
                    )
                )

            gossip = NewBlockGossip(
                block.height,
                block.prev_hash,
                block.txs_hash,
                block.timestamp,
                block.difficulty,
                block.nonce,
                b"".join(block.tx_hashes),
                provided_txs,
            )
            
            print(
                f"[compact-send] peer={peer.public_key.key_to_bin().hex()[:8]} "
                f"hashes={len(block.tx_hashes)} "
                f"provided={len(provided_txs)}"
            )

            self.ez_send(peer, gossip)

            # After sending, we believe peer can reconstruct/know these txs.
            self.peer_known_txs[peer].update(block.tx_hashes)
            

    # --- mining ---------------------------------------------------------------

    async def mine_forever(self) -> None:
        while True:
            await self.mine_one_block()
            await asyncio.sleep(0)

    async def mine_one_block(self) -> None:
        """Mine on the current tip; bail out when the tip or pending txs change."""
        tip = self.blockchain.chain[-1]
        height = len(self.blockchain.chain)
        pending = self.blockchain.pending_tx_hashes()
        pending_txs = [self.blockchain.mempool[h] for h in pending]
        txs_hash = txs_commitment(pending)
        # Bonus 5: difficulty is not fixed — it is whatever the retarget mandates
        # for this position, so the whole group mines at the same adaptive target.
        difficulty = self.blockchain.next_difficulty()
        # Timestamp must move strictly past the median time, so our own block is
        # never rejected by the timestamp rule even if our clock lags.
        timestamp = max(int(time.time()), median_time_past(self.blockchain.chain) + 1)
        prefix = tip.block_hash + txs_hash + timestamp.to_bytes(8, "big") + difficulty.to_bytes(4, "big")
        nonce = random.getrandbits(63)  # random start so the 3 miners search disjoint ranges

        while True:
            for _ in range(NONCE_BATCH):
                digest = sha256(prefix + nonce.to_bytes(8, "big")).digest()
                if meets_difficulty(digest, difficulty):
                    block = make_block(height, tip.block_hash, pending_txs, timestamp,
                                       difficulty, nonce)
                    self.adopt_own_block(block)
                    return
                nonce = (nonce + 1) & NONCE_MASK
            await asyncio.sleep(0)
            if self.blockchain.chain[-1] is not tip or self.blockchain.pending_tx_hashes() != pending:
                return  # restart on the new tip / with the new transactions

    def adopt_own_block(self, block: Block) -> None:
        accepted, missing, missing_txs = self.blockchain.add_block(block)

        if missing is not None:
            self.remember_missing_block(missing)

        if missing_txs:
            self.remember_missing_transactions(missing_txs)
            return

        if not accepted:
            return

        self.note_reorg()

        print(f"[mine] found block {block.height} {block.block_hash.hex()[:16]} "
            f"({len(block.tx_hashes)} txs)")

        self.gossip_compact_block_to_members(block)
