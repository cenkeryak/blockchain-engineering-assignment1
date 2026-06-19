"""Blockchain community: chain state, mining, block gossip, and server query handlers.

All 3 nodes mine concurrently. Consensus is longest chain; ties at equal height
are broken by the smaller block hash so the group converges deterministically.
"""

from __future__ import annotations

import asyncio
import random
import time
from hashlib import sha256

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.peer import Peer

from src.blocks import (
    DIFFICULTY,
    HASH_SIZE,
    NONCE_MASK,
    Block,
    Transaction,
    Blockchain,
    meets_difficulty,
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

    # --- peer filtering -----------------------------------------------------

    def is_member(self, peer: Peer) -> bool:
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
            if self.blockchain.accept_transaction(tx):
                # did this transaction change adoption status
                missing = self.blockchain.try_adopt()
                if missing is not None:
                    self.remember_missing_block(missing, peer)

                self.gossip_to_members(
                    TransactionGossip(tx.sender_key, tx.data, tx.timestamp, tx.signature)
                )
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
        self.ez_send(peer, BlockResponse(block.height, block.prev_hash, block.txs_hash,
                                         block.timestamp, block.difficulty, block.nonce,
                                         block.block_hash, b"".join(block.tx_hashes)))
        
    
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

        if self.blockchain.accept_transaction(tx):
            missing = self.blockchain.try_adopt()
            if missing is not None:
                self.remember_missing_block(missing, peer)

            self.gossip_to_members(
                TransactionGossip(tx.sender_key, tx.data, tx.timestamp, tx.signature),
                exclude=peer,
            )

    @lazy_wrapper(NewBlockGossip)
    def on_new_block(self, peer: Peer, payload: NewBlockGossip) -> None:
        if self.is_member(peer):
            self.handle_block(peer, payload.height, payload.prev_hash, payload.txs_hash,
                              payload.timestamp, payload.difficulty, payload.nonce,
                              payload.tx_hashes)

    @lazy_wrapper(BlockResponse)
    def on_block_response(self, peer: Peer, payload: BlockResponse) -> None:
        if self.is_member(peer):
            self.handle_block(peer, payload.height, payload.prev_hash, payload.txs_hash,
                              payload.timestamp, payload.difficulty, payload.nonce,
                              payload.tx_hashes)

    def sync_with_teammates(self) -> None:
        for member in self.member_peers():
            self.ez_send(member, GetChainHeight(random.getrandbits(63)))
        
        self.retry_missing_blocks()
        self.retry_missing_transactions()

    @lazy_wrapper(ChainHeightResponse)
    def on_chain_height_response(self, peer: Peer, payload: ChainHeightResponse) -> None:
        """Periodic tip poll: if a teammate is ahead of us, fetch their tip block."""
        if not self.is_member(peer):
            return
        if payload.height >= len(self.blockchain.chain) - 1 and payload.tip_hash not in self.blockchain.block_pool:
            self.request_block(payload.height, peer)

    @lazy_wrapper(GetTransaction)
    def on_get_transaction(self, peer: Peer, payload: GetTransaction) -> None:
        if not self.is_member(peer):
            return

        tx = self.blockchain.mempool.get(payload.tx_hash)
        if tx is None:
            return
        
        self.ez_send(
            peer,
            TransactionGossip(tx.sender_key, tx.data, tx.timestamp, tx.signature),
        )

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

            # Already caught up
            if height <= self.blockchain.height:
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
                     timestamp: int, difficulty: int, nonce: int, tx_hashes_blob: bytes) -> None:
        if height < 1 or len(tx_hashes_blob) % HASH_SIZE != 0:
            return
        tx_hashes = [tx_hashes_blob[i:i + HASH_SIZE] for i in range(0, len(tx_hashes_blob), HASH_SIZE)]
        # Recompute the hash from the header; never trust a received block_hash.
        block_hash = sha256(pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce)).digest()
        block = Block(height, prev_hash, txs_hash, timestamp, difficulty, nonce, block_hash, tx_hashes)

        accepted, missing, missing_txs = self.blockchain.add_block(block)

        if missing is not None:
            self.remember_missing_block(missing, peer)

        if missing_txs:
            self.remember_missing_transactions(missing_txs, peer)
            return

        if accepted:
            self.missing_block_requests.pop(block.height, None)
            print(f"[block] accepted {block.block_hash.hex()[:16]}")

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
            

    # --- mining ---------------------------------------------------------------

    async def mine_forever(self) -> None:
        while True:
            await self.mine_one_block()
            await asyncio.sleep(0)

    async def mine_one_block(self) -> None:
        """Mine on the current tip; bail out when the tip or the mempool changes."""
        tip = self.blockchain.chain[-1]
        height = len(self.blockchain.chain)
        pending = self.blockchain.pending_tx_hashes()
        txs_hash = txs_commitment(pending)
        timestamp = int(time.time())
        prefix = tip.block_hash + txs_hash + timestamp.to_bytes(8, "big") + DIFFICULTY.to_bytes(4, "big")
        nonce = random.getrandbits(63)  # random start so the 3 miners search disjoint ranges

        while True:
            for _ in range(NONCE_BATCH):
                digest = sha256(prefix + nonce.to_bytes(8, "big")).digest()
                if meets_difficulty(digest, DIFFICULTY):
                    block = Block(height, tip.block_hash, txs_hash, timestamp,
                                  DIFFICULTY, nonce, digest, pending)
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

        print(f"[mine] found block {block.height} {block.block_hash.hex()[:16]} "
            f"({len(block.tx_hashes)} txs)")

        gossip = NewBlockGossip(
            block.height,
            block.prev_hash,
            block.txs_hash,
            block.timestamp,
            block.difficulty,
            block.nonce,
            b"".join(block.tx_hashes),
        )

        self.gossip_to_members(gossip)
