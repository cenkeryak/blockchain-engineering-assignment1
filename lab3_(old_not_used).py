"""Lab 3 IPv8 Proof-of-Work blockchain node.

This file intentionally keeps the assignment mechanics visible instead of
hiding them behind many abstractions. The comments explain the wire protocol,
local blockchain rules, peer filtering, and mining decisions so the file can be
read as both an implementation and a study guide for the assignment.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import signal
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv
from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.peer import Peer
from ipv8_service import IPv8


# ---------------------------------------------------------------------------
# Lab 3 constants published in the assignment.
# ---------------------------------------------------------------------------

REGISTRATION_COMMUNITY_ID_HEX = "4c616233426c6f636b636861696e323032365057"
SERVER_PUBLIC_KEY_HEX = (
    "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0"
    "d76873e7d7f7838f3715e025af08f791324495e083331ce6"
)

REGISTRATION_COMMUNITY_ID = bytes.fromhex(REGISTRATION_COMMUNITY_ID_HEX)
SERVER_PUBLIC_KEY = bytes.fromhex(SERVER_PUBLIC_KEY_HEX)


# ---------------------------------------------------------------------------
# Local defaults. Keep the difficulty low enough that three laptop nodes can
# mine several confirmation blocks quickly, while still doing real PoW.
# ---------------------------------------------------------------------------

GROUP_SIZE = 3
HASH_SIZE = 32
DEFAULT_DIFFICULTY = 12
DEFAULT_CONFIRMATIONS = 3
DEFAULT_REGISTER_RETRY_SECONDS = 10.0
DEFAULT_SUMMARY_SECONDS = 2.0
DEFAULT_TICK_SECONDS = 0.1
DEFAULT_NONCE_BATCH = 5_000
KEY_ALIAS = "lab3 identity"

MAX_U32 = (1 << 32) - 1
MAX_U64 = (1 << 64) - 1
MAX_I64 = (1 << 63) - 1

GENESIS_PREV_HASH = b"\x00" * HASH_SIZE
GENESIS_TIMESTAMP = 0
GENESIS_DIFFICULTY = 0
GENESIS_NONCE = 0


# ---------------------------------------------------------------------------
# Registration-community payloads.
# These message ids are defined by the assignment for the fixed registration
# community, not for our custom blockchain community.
# ---------------------------------------------------------------------------


@dataclass
class RegisterBlockchainPayload(DataClassPayload[1]):
    """Message id 1 on the registration community: announce our chain."""

    group_id: str
    community_id: bytes


@dataclass
class RegisterBlockchainResponsePayload(DataClassPayload[2]):
    """Message id 2 on the registration community: server registration result."""

    success: bool
    message: str


# ---------------------------------------------------------------------------
# Blockchain-community payloads sent by the server.
# The message ids 1-6 are fixed by the assignment.
# ---------------------------------------------------------------------------


@dataclass
class SubmitTransactionPayload(DataClassPayload[1]):
    """Message id 1 on the blockchain community: server submits a transaction."""

    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes


@dataclass
class SubmitTransactionResponsePayload(DataClassPayload[2]):
    """Message id 2 on the blockchain community: transaction acceptance result."""

    success: bool
    tx_hash: bytes
    message: str


@dataclass
class GetChainHeightPayload(DataClassPayload[3]):
    """Message id 3 on the blockchain community: server asks for our tip."""

    request_id: int


@dataclass
class ChainHeightResponsePayload(DataClassPayload[4]):
    """Message id 4 on the blockchain community: current height and tip hash."""

    request_id: int
    height: int
    tip_hash: bytes


@dataclass
class GetBlockPayload(DataClassPayload[5]):
    """Message id 5 on the blockchain community: server asks for one block."""

    height: int


@dataclass
class BlockResponsePayload(DataClassPayload[6]):
    """Message id 6 on the blockchain community: block header plus tx hashes."""

    height: int
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    block_hash: bytes
    tx_hashes: bytes


# ---------------------------------------------------------------------------
# Blockchain-community payloads used only between the three teammates.
# These start at id 7 so they do not collide with the server protocol.
# ---------------------------------------------------------------------------


@dataclass
class TransactionGossipPayload(DataClassPayload[7]):
    """Internal message id 7: teammate-to-teammate transaction sharing."""

    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes


@dataclass
class BlockGossipPayload(DataClassPayload[8]):
    """Internal message id 8: teammate-to-teammate block sharing."""

    height: int
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    block_hash: bytes
    tx_hashes: bytes


@dataclass
class ChainSummaryPayload(DataClassPayload[9]):
    """Internal message id 9: lightweight tip announcement for catch-up."""

    height: int
    tip_hash: bytes


@dataclass
class BlockRequestPayload(DataClassPayload[10]):
    """Internal message id 10: request a missing canonical block by height."""

    height: int


# ---------------------------------------------------------------------------
# Small immutable data objects for local chain state.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransactionRecord:
    """Local transaction object with both original bytes and calculated hash."""

    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes
    tx_hash: bytes

    def to_gossip_payload(self) -> TransactionGossipPayload:
        """Convert a stored transaction into the payload sent to teammates."""
        return TransactionGossipPayload(self.sender_key, self.data, self.timestamp, self.signature)


@dataclass(frozen=True)
class TransactionAcceptResult:
    """Structured result from validating and inserting a transaction."""

    success: bool
    tx_hash: bytes
    message: str
    is_new: bool
    record: TransactionRecord | None


@dataclass(frozen=True)
class Block:
    """Local immutable block representation used by mining and validation."""

    height: int
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    block_hash: bytes
    tx_hashes: tuple[bytes, ...]

    def tx_hashes_blob(self) -> bytes:
        """Return transaction hashes in the exact concatenated wire format."""
        return b"".join(self.tx_hashes)

    def to_response_payload(self) -> BlockResponsePayload:
        """Build the server-facing block response payload for this block."""
        return BlockResponsePayload(
            self.height,
            self.prev_hash,
            self.txs_hash,
            self.timestamp,
            self.difficulty,
            self.nonce,
            self.block_hash,
            self.tx_hashes_blob(),
        )

    def to_gossip_payload(self) -> BlockGossipPayload:
        """Build the teammate-facing block gossip payload for this block."""
        return BlockGossipPayload(
            self.height,
            self.prev_hash,
            self.txs_hash,
            self.timestamp,
            self.difficulty,
            self.nonce,
            self.block_hash,
            self.tx_hashes_blob(),
        )


# ---------------------------------------------------------------------------
# Encoding and hashing helpers. These are deliberately boring and explicit:
# most blockchain bugs in this assignment come from packing one integer in the
# wrong width or byte order.
# ---------------------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    """Return a SHA-256 digest as raw bytes, not as hexadecimal text."""
    return hashlib.sha256(data).digest()


def pack_u64(value: int, field_name: str) -> bytes:
    """Pack an integer as an unsigned 64-bit big-endian field."""
    if value < 0 or value > MAX_U64:
        raise ValueError(f"{field_name} must fit in uint64")
    return struct.pack(">Q", value)


def pack_u32(value: int, field_name: str) -> bytes:
    """Pack an integer as an unsigned 32-bit big-endian field."""
    if value < 0 or value > MAX_U32:
        raise ValueError(f"{field_name} must fit in uint32")
    return struct.pack(">I", value)


def transaction_signature_bytes(sender_key: bytes, data: bytes, timestamp: int) -> bytes:
    """Return the byte string the assignment says transaction signatures cover."""
    return sender_key + data + pack_u64(timestamp, "transaction timestamp")


def calculate_tx_hash(sender_key: bytes, data: bytes, timestamp: int, signature: bytes) -> bytes:
    """Calculate the assignment-defined transaction hash."""
    return sha256(transaction_signature_bytes(sender_key, data, timestamp) + signature)


def calculate_txs_hash(tx_hashes: tuple[bytes, ...]) -> bytes:
    """Calculate the flat block-body commitment over ordered transaction hashes."""
    return sha256(b"".join(tx_hashes))


def block_header_bytes(prev_hash: bytes, txs_hash: bytes, timestamp: int, difficulty: int, nonce: int) -> bytes:
    """Encode a block header in the exact 84-byte assignment format."""
    if len(prev_hash) != HASH_SIZE:
        raise ValueError("prev_hash must be exactly 32 bytes")
    if len(txs_hash) != HASH_SIZE:
        raise ValueError("txs_hash must be exactly 32 bytes")

    return (
        prev_hash
        + txs_hash
        + pack_u64(timestamp, "block timestamp")
        + pack_u32(difficulty, "block difficulty")
        + pack_u64(nonce, "block nonce")
    )


def calculate_block_hash(prev_hash: bytes, txs_hash: bytes, timestamp: int, difficulty: int, nonce: int) -> bytes:
    """Hash the block header exactly as the server will hash it."""
    return sha256(block_header_bytes(prev_hash, txs_hash, timestamp, difficulty, nonce))


def leading_zero_bits(digest: bytes) -> int:
    """Count leading zero bits in a digest for Proof-of-Work validation."""
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        return count + (8 - byte.bit_length())
    return count


def satisfies_pow(digest: bytes, difficulty: int) -> bool:
    """Return whether a digest satisfies a leading-zero-bit difficulty."""
    if difficulty < 0 or difficulty > len(digest) * 8:
        return False
    return leading_zero_bits(digest) >= difficulty


def split_tx_hashes(blob: bytes) -> tuple[bytes, ...]:
    """Split the wire-format transaction-hash blob into 32-byte chunks."""
    if len(blob) % HASH_SIZE != 0:
        raise ValueError("tx_hashes must be a concatenation of 32-byte hashes")
    return tuple(blob[offset : offset + HASH_SIZE] for offset in range(0, len(blob), HASH_SIZE))


def make_genesis_block() -> Block:
    """Construct the deterministic block 0 shared by every group member."""
    tx_hashes: tuple[bytes, ...] = ()
    txs_hash = calculate_txs_hash(tx_hashes)
    block_hash = calculate_block_hash(
        GENESIS_PREV_HASH,
        txs_hash,
        GENESIS_TIMESTAMP,
        GENESIS_DIFFICULTY,
        GENESIS_NONCE,
    )
    return Block(
        height=0,
        prev_hash=GENESIS_PREV_HASH,
        txs_hash=txs_hash,
        timestamp=GENESIS_TIMESTAMP,
        difficulty=GENESIS_DIFFICULTY,
        nonce=GENESIS_NONCE,
        block_hash=block_hash,
        tx_hashes=tx_hashes,
    )


def block_from_wire(
    height: int,
    prev_hash: bytes,
    txs_hash: bytes,
    timestamp: int,
    difficulty: int,
    nonce: int,
    block_hash: bytes,
    tx_hashes_blob: bytes,
) -> Block:
    """Convert a received block payload into the internal immutable Block type."""
    return Block(
        height=height,
        prev_hash=prev_hash,
        txs_hash=txs_hash,
        timestamp=timestamp,
        difficulty=difficulty,
        nonce=nonce,
        block_hash=block_hash,
        tx_hashes=split_tx_hashes(tx_hashes_blob),
    )


# ---------------------------------------------------------------------------
# CLI/env parsing helpers.
# ---------------------------------------------------------------------------


def parse_hex_bytes(value: str, field_name: str, expected_length: int | None = None) -> bytes:
    """Parse a hex string and optionally enforce an exact byte length."""
    cleaned = value.strip()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    try:
        parsed = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be hex") from exc

    if expected_length is not None and len(parsed) != expected_length:
        raise ValueError(f"{field_name} must be {expected_length} bytes / {expected_length * 2} hex characters")
    return parsed


def derive_blockchain_community_id(group_id: str) -> bytes:
    """Derive a stable 20-byte blockchain community id from the Lab 2 group id."""
    # IPv8 community ids are 20 bytes. Deriving from group_id gives all three
    # teammates the same default without hard-coding a personal id in the file.
    return hashlib.sha256(f"lab3-blockchain:{group_id}".encode("utf-8")).digest()[:20]


def public_key_from_private_key_file(key_file: Path) -> bytes:
    """Load an IPv8 private key file and return its matching public key bytes."""
    private_bin = key_file.read_bytes()
    if not default_eccrypto.is_valid_private_bin(private_bin):
        raise ValueError(f"{key_file} is not a valid IPv8 private key file")
    return default_eccrypto.key_from_private_bin(private_bin).pub().key_to_bin()


def load_member_public_keys(cli_values: list[str] | None) -> list[bytes]:
    """Load and validate the three group-member public keys."""
    raw_values = cli_values

    if not raw_values:
        env_value = os.getenv("PUBLIC_KEYS", "").strip()
        if env_value:
            try:
                loaded = json.loads(env_value)
                if isinstance(loaded, list):
                    raw_values = [str(item) for item in loaded]
                else:
                    raise ValueError
            except ValueError:
                raw_values = [part.strip() for part in env_value.split(",") if part.strip()]

    if not raw_values:
        raise ValueError("provide the three member public keys with --member-public-key or PUBLIC_KEYS")

    public_keys = [parse_hex_bytes(value, "member public key") for value in raw_values]
    if len(public_keys) != GROUP_SIZE:
        raise ValueError(f"exactly {GROUP_SIZE} member public keys are required")
    if len(set(public_keys)) != GROUP_SIZE:
        raise ValueError("member public keys must be unique")

    for public_key in public_keys:
        if not default_eccrypto.is_valid_public_bin(public_key):
            raise ValueError(f"invalid IPv8 public key: {public_key.hex()}")

    return public_keys


# ---------------------------------------------------------------------------
# Registration overlay: talks to the official Lab 3 server on the fixed
# registration community and tells it which blockchain community to inspect.
# ---------------------------------------------------------------------------


class Lab3RegistrationSettings(CommunitySettings):
    """Typed settings passed into the registration IPv8 overlay."""

    group_id: str
    blockchain_community_id: bytes
    server_public_key: bytes
    retry_seconds: float


class Lab3RegistrationCommunity(Community):
    """IPv8 overlay responsible only for registering the blockchain community."""

    community_id = REGISTRATION_COMMUNITY_ID
    settings_class = Lab3RegistrationSettings

    def __init__(self, settings: Lab3RegistrationSettings) -> None:
        """Store registration settings and install the server response handler."""
        super().__init__(settings)
        self.group_id = settings.group_id
        self.blockchain_community_id = settings.blockchain_community_id
        self.server_public_key = settings.server_public_key
        self.retry_seconds = settings.retry_seconds

        self.server_peer: Peer | None = None
        self.registered = False
        self.last_register_at = 0.0

        self.add_message_handler(RegisterBlockchainResponsePayload, self.on_register_response)

    def is_server(self, peer: Peer) -> bool:
        """Return True only for the official Lab 3 server public key."""
        return peer.public_key.key_to_bin() == self.server_public_key

    def find_server_peer(self) -> Peer | None:
        """Search IPv8 discovery results for the verified registration server."""
        # The assignment explicitly says to filter by the published server key.
        if self.server_peer is not None:
            return self.server_peer

        for peer in self.get_peers():
            if self.is_server(peer):
                self.server_peer = peer
                print(f"Registration server discovered at {peer.address}", flush=True)
                return peer
        return None

    def tick(self) -> None:
        """Periodically submit registration until the server accepts it."""
        if self.registered:
            return

        server_peer = self.find_server_peer()
        if server_peer is None:
            return

        now = time.monotonic()
        if now - self.last_register_at < self.retry_seconds:
            return

        print(
            "Registering blockchain community "
            f"{self.blockchain_community_id.hex()} for group {self.group_id!r}",
            flush=True,
        )
        self.ez_send(server_peer, RegisterBlockchainPayload(self.group_id, self.blockchain_community_id))
        self.last_register_at = now

    @lazy_wrapper(RegisterBlockchainResponsePayload)
    def on_register_response(self, peer: Peer, payload: RegisterBlockchainResponsePayload) -> None:
        """Handle the server's answer to our RegisterBlockchain message."""
        if not self.is_server(peer):
            return

        print(f"Registration response: success={payload.success} message={payload.message!r}", flush=True)
        if payload.success:
            self.registered = True
        else:
            # Let the periodic tick retry soon after a negative response.
            self.last_register_at = 0.0


# ---------------------------------------------------------------------------
# Blockchain overlay: accepts the server transaction, mines blocks, gossips
# data to teammates, and answers chain queries.
# ---------------------------------------------------------------------------


class Lab3BlockchainSettings(CommunitySettings):
    """Typed settings passed into the blockchain IPv8 overlay."""

    member_id: int
    member_public_keys: list[bytes]
    server_public_key: bytes
    difficulty: int
    required_confirmations: int
    summary_seconds: float
    nonce_batch: int
    mine_empty_blocks: bool


class Lab3BlockchainCommunity(Community):
    """IPv8 overlay that runs the 3-node Proof-of-Work blockchain."""

    # This is overwritten in start_node() before IPv8 constructs the overlay.
    community_id = b"\x00" * 20
    settings_class = Lab3BlockchainSettings

    def __init__(self, settings: Lab3BlockchainSettings) -> None:
        """Initialize local blockchain state and register all message handlers."""
        super().__init__(settings)

        self.member_id = settings.member_id
        self.member_public_keys = settings.member_public_keys
        self.server_public_key = settings.server_public_key
        self.difficulty = settings.difficulty
        self.required_confirmations = settings.required_confirmations
        self.summary_seconds = settings.summary_seconds
        self.nonce_batch = settings.nonce_batch
        self.mine_empty_blocks = settings.mine_empty_blocks

        self.member_ids_by_key = {public_key: idx for idx, public_key in enumerate(self.member_public_keys)}
        self.member_peers: dict[int, Peer] = {}
        self.server_peer: Peer | None = None

        genesis = make_genesis_block()
        self.blocks_by_hash: dict[bytes, Block] = {genesis.block_hash: genesis}
        self.canonical_hashes: list[bytes] = [genesis.block_hash]

        # We keep full transaction data only for transactions we receive or
        # learn through teammate gossip. Blocks themselves only need hashes.
        self.all_transactions: dict[bytes, TransactionRecord] = {}
        self.mempool: dict[bytes, TransactionRecord] = {}
        self.included_tx_heights: dict[bytes, int] = {}

        # Orphans are valid-looking blocks whose parent has not arrived yet.
        self.orphans_by_prev_hash: dict[bytes, list[Block]] = {}
        self.orphan_hashes: set[bytes] = set()

        self.last_summary_at = 0.0
        self.last_mempool_gossip_at = 0.0
        self.mining_task: asyncio.Task[None] | None = None
        self.mining_height: int | None = None
        self.mining_prev_hash: bytes | None = None
        self.mining_tx_hashes: tuple[bytes, ...] = ()

        self.add_message_handler(SubmitTransactionPayload, self.on_submit_transaction)
        self.add_message_handler(GetChainHeightPayload, self.on_get_chain_height)
        self.add_message_handler(GetBlockPayload, self.on_get_block)
        self.add_message_handler(TransactionGossipPayload, self.on_transaction_gossip)
        self.add_message_handler(BlockGossipPayload, self.on_block_gossip)
        self.add_message_handler(ChainSummaryPayload, self.on_chain_summary)
        self.add_message_handler(BlockRequestPayload, self.on_block_request)

    # ----- Peer identity helpers -------------------------------------------------

    def is_server(self, peer: Peer) -> bool:
        """Return True only for the official server inside our blockchain community."""
        return peer.public_key.key_to_bin() == self.server_public_key

    def teammate_id(self, peer: Peer) -> int | None:
        """Map a peer to its group-member index, or None if it is not a teammate."""
        public_key = peer.public_key.key_to_bin()
        teammate_id = self.member_ids_by_key.get(public_key)
        if teammate_id is None or teammate_id == self.member_id:
            return None
        return teammate_id

    def discover_known_peers(self) -> None:
        """Refresh cached server and teammate peers from IPv8 discovery."""
        for peer in self.get_peers():
            public_key = peer.public_key.key_to_bin()
            if public_key == self.server_public_key:
                self.server_peer = peer
                continue

            teammate_id = self.member_ids_by_key.get(public_key)
            if teammate_id is not None and teammate_id != self.member_id:
                if teammate_id not in self.member_peers:
                    print(f"Teammate {teammate_id} discovered at {peer.address}", flush=True)
                self.member_peers[teammate_id] = peer

    # ----- Current-chain helpers -------------------------------------------------

    def current_height(self) -> int:
        """Return the current canonical chain height, with genesis at height 0."""
        return len(self.canonical_hashes) - 1

    def tip_hash(self) -> bytes:
        """Return the block hash at the tip of the canonical chain."""
        return self.canonical_hashes[-1]

    def block_at_height(self, height: int) -> Block | None:
        """Return the canonical block at a height, or None if it is unknown."""
        if height < 0 or height >= len(self.canonical_hashes):
            return None
        return self.blocks_by_hash[self.canonical_hashes[height]]

    def leader_for_height(self, height: int) -> int:
        """Return the group member responsible for mining a given height."""
        # Height 1 is mined by member 0, height 2 by member 1, and so on.
        return (height - 1) % GROUP_SIZE

    def is_my_turn_to_mine(self, height: int) -> bool:
        """Return whether this node is the deterministic miner for a height."""
        return self.leader_for_height(height) == self.member_id

    # ----- Server query handlers -------------------------------------------------

    @lazy_wrapper(SubmitTransactionPayload)
    def on_submit_transaction(self, peer: Peer, payload: SubmitTransactionPayload) -> None:
        """Verify and accept a transaction submitted by the Lab 3 server."""
        if not self.is_server(peer):
            return

        result = self.accept_transaction(
            payload.sender_key,
            payload.data,
            payload.timestamp,
            payload.signature,
        )
        self.ez_send(peer, SubmitTransactionResponsePayload(result.success, result.tx_hash, result.message))

        if result.success and result.record is not None:
            print(f"Server transaction accepted: {result.tx_hash.hex()}", flush=True)
            if result.is_new:
                self.broadcast_transaction(result.record)
            self.cancel_empty_mining_for_new_transaction()

    @lazy_wrapper(GetChainHeightPayload)
    def on_get_chain_height(self, peer: Peer, payload: GetChainHeightPayload) -> None:
        """Respond to the server with current chain height and tip hash."""
        if not self.is_server(peer):
            return

        self.ez_send(peer, ChainHeightResponsePayload(payload.request_id, self.current_height(), self.tip_hash()))

    @lazy_wrapper(GetBlockPayload)
    def on_get_block(self, peer: Peer, payload: GetBlockPayload) -> None:
        """Respond to the server with the canonical block at a requested height."""
        if not self.is_server(peer):
            return

        block = self.block_at_height(payload.height)
        if block is None:
            print(f"Server requested unknown block height {payload.height}", flush=True)
            return

        self.ez_send(peer, block.to_response_payload())

    # ----- Teammate gossip handlers ---------------------------------------------

    @lazy_wrapper(TransactionGossipPayload)
    def on_transaction_gossip(self, peer: Peer, payload: TransactionGossipPayload) -> None:
        """Accept and forward a valid transaction learned from a teammate."""
        teammate_id = self.teammate_id(peer)
        if teammate_id is None:
            return

        result = self.accept_transaction(
            payload.sender_key,
            payload.data,
            payload.timestamp,
            payload.signature,
        )
        if result.success and result.record is not None and result.is_new:
            print(f"Transaction learned from teammate {teammate_id}: {result.tx_hash.hex()}", flush=True)
            self.broadcast_transaction(result.record, exclude_peer=peer)
            self.cancel_empty_mining_for_new_transaction()

    @lazy_wrapper(BlockGossipPayload)
    def on_block_gossip(self, peer: Peer, payload: BlockGossipPayload) -> None:
        """Validate and apply a block gossiped by a teammate."""
        teammate_id = self.teammate_id(peer)
        if teammate_id is None:
            return

        try:
            block = block_from_wire(
                payload.height,
                payload.prev_hash,
                payload.txs_hash,
                payload.timestamp,
                payload.difficulty,
                payload.nonce,
                payload.block_hash,
                payload.tx_hashes,
            )
        except ValueError as exc:
            print(f"Ignoring malformed block from teammate {teammate_id}: {exc}", flush=True)
            return

        accepted = self.accept_block(block, source=f"teammate {teammate_id}", source_peer=peer)
        if accepted:
            self.broadcast_block(block, exclude_peer=peer)

    @lazy_wrapper(ChainSummaryPayload)
    def on_chain_summary(self, peer: Peer, payload: ChainSummaryPayload) -> None:
        """Notice when a teammate is ahead and request our next missing block."""
        teammate_id = self.teammate_id(peer)
        if teammate_id is None:
            return

        if payload.height > self.current_height():
            # Ask for the next missing canonical height. Repeated summaries will
            # pull the rest if several UDP block messages were missed.
            self.ez_send(peer, BlockRequestPayload(self.current_height() + 1))

    @lazy_wrapper(BlockRequestPayload)
    def on_block_request(self, peer: Peer, payload: BlockRequestPayload) -> None:
        """Send a canonical block to a teammate that requested it."""
        teammate_id = self.teammate_id(peer)
        if teammate_id is None:
            return

        block = self.block_at_height(payload.height)
        if block is not None:
            self.ez_send(peer, block.to_gossip_payload())

    # ----- Transaction handling --------------------------------------------------

    def accept_transaction(self, sender_key: bytes, data: bytes, timestamp: int, signature: bytes) -> TransactionAcceptResult:
        """Verify a transaction signature and place the transaction in the mempool."""
        try:
            public_key = default_eccrypto.key_from_public_bin(sender_key)
            signed_bytes = transaction_signature_bytes(sender_key, data, timestamp)
        except Exception as exc:
            return TransactionAcceptResult(False, b"", f"invalid transaction fields: {exc}", False, None)

        if not default_eccrypto.is_valid_signature(public_key, signed_bytes, signature):
            return TransactionAcceptResult(False, b"", "invalid transaction signature", False, None)

        # The server later checks the transaction by hash, so every node must
        # calculate exactly the same tx_hash for the same transaction bytes.
        tx_hash = calculate_tx_hash(sender_key, data, timestamp, signature)
        record = TransactionRecord(sender_key, data, timestamp, signature, tx_hash)
        is_new = tx_hash not in self.all_transactions

        self.all_transactions.setdefault(tx_hash, record)
        if tx_hash not in self.included_tx_heights:
            self.mempool.setdefault(tx_hash, record)

        message = "accepted into mempool" if tx_hash in self.mempool else "already included in chain"
        return TransactionAcceptResult(True, tx_hash, message, is_new, record)

    def broadcast_transaction(self, record: TransactionRecord, exclude_peer: Peer | None = None) -> None:
        """Gossip a transaction to teammates, optionally skipping the sender."""
        exclude_key = exclude_peer.public_key.key_to_bin() if exclude_peer is not None else None
        for peer in self.member_peers.values():
            if peer.public_key.key_to_bin() != exclude_key:
                self.ez_send(peer, record.to_gossip_payload())

    # ----- Block validation and chain selection ---------------------------------

    def validate_block_shape(self, block: Block) -> tuple[bool, str]:
        """Check a block's local format, body commitment, hash, and Proof-of-Work."""
        if block.height < 0:
            return False, "negative height"
        if len(block.prev_hash) != HASH_SIZE:
            return False, "prev_hash is not 32 bytes"
        if len(block.txs_hash) != HASH_SIZE:
            return False, "txs_hash is not 32 bytes"
        if len(block.block_hash) != HASH_SIZE:
            return False, "block_hash is not 32 bytes"
        if block.timestamp < 0 or block.timestamp > MAX_U64:
            return False, "timestamp does not fit uint64"
        if block.difficulty < 0 or block.difficulty > HASH_SIZE * 8:
            return False, "difficulty is outside SHA-256's bit length"
        if block.nonce < 0 or block.nonce > MAX_U64:
            return False, "nonce does not fit uint64"
        if any(len(tx_hash) != HASH_SIZE for tx_hash in block.tx_hashes):
            return False, "one or more transaction hashes are not 32 bytes"

        # The body commitment is deliberately flat: no Merkle tree, just
        # SHA256(tx_hash_1 || tx_hash_2 || ...).
        expected_txs_hash = calculate_txs_hash(block.tx_hashes)
        if block.txs_hash != expected_txs_hash:
            return False, "txs_hash does not match tx_hashes"

        # The block hash is not trusted from the wire. We recompute the header
        # hash and compare it with the advertised block_hash.
        expected_block_hash = calculate_block_hash(
            block.prev_hash,
            block.txs_hash,
            block.timestamp,
            block.difficulty,
            block.nonce,
        )
        if block.block_hash != expected_block_hash:
            return False, "block_hash does not match the header"

        if not satisfies_pow(block.block_hash, block.difficulty):
            return False, "declared proof of work is not satisfied"

        return True, "valid"

    def accept_block(self, block: Block, *, source: str, source_peer: Peer | None = None) -> bool:
        """Validate a new block, store it, and switch chains if it becomes longest."""
        if block.block_hash in self.blocks_by_hash:
            return False

        valid, reason = self.validate_block_shape(block)
        if not valid:
            print(f"Ignoring invalid block from {source}: {reason}", flush=True)
            return False

        genesis = self.block_at_height(0)
        if block.height == 0:
            if genesis is not None and block.block_hash == genesis.block_hash:
                return False
            print("Ignoring alternate genesis block", flush=True)
            return False

        # A block cannot be connected until its parent is known. We keep it as
        # an orphan and ask the sender for the previous height.
        parent = self.blocks_by_hash.get(block.prev_hash)
        if parent is None:
            self.remember_orphan(block)
            if source_peer is not None and block.height > 0:
                self.ez_send(source_peer, BlockRequestPayload(block.height - 1))
            return False

        if block.height != parent.height + 1:
            print(f"Ignoring block with inconsistent height from {source}", flush=True)
            return False

        self.blocks_by_hash[block.block_hash] = block
        print(
            f"Accepted block {block.height} from {source}: "
            f"{block.block_hash.hex()} ({len(block.tx_hashes)} txs)",
            flush=True,
        )

        if block.height > self.current_height():
            self.switch_to_tip(block)

        self.process_orphans(block.block_hash)
        return True

    def remember_orphan(self, block: Block) -> None:
        """Store a block whose parent has not arrived yet."""
        if block.block_hash in self.orphan_hashes:
            return
        self.orphans_by_prev_hash.setdefault(block.prev_hash, []).append(block)
        self.orphan_hashes.add(block.block_hash)

    def process_orphans(self, parent_hash: bytes) -> None:
        """Retry orphan blocks that were waiting for a newly accepted parent."""
        waiting = self.orphans_by_prev_hash.pop(parent_hash, [])
        for orphan in waiting:
            self.orphan_hashes.discard(orphan.block_hash)
            self.accept_block(orphan, source="orphan queue")

    def switch_to_tip(self, new_tip: Block) -> None:
        """Rebuild the canonical chain so it ends at the given longest-chain tip."""
        new_chain: list[bytes] = []
        cursor = new_tip

        # Walk backwards from the new tip until genesis, then reverse the result
        # so canonical_hashes[height] still gives the block hash at that height.
        while True:
            new_chain.append(cursor.block_hash)
            if cursor.height == 0:
                break
            parent = self.blocks_by_hash.get(cursor.prev_hash)
            if parent is None:
                return
            cursor = parent

        new_chain.reverse()
        if len(new_chain) <= len(self.canonical_hashes):
            return

        # If the block we just mined was accepted, the current mining task is
        # already effectively complete. In that case avoid cancelling ourselves.
        should_cancel_mining = not (
            self.mining_height == new_tip.height
            and self.mining_prev_hash == new_tip.prev_hash
            and self.mining_tx_hashes == new_tip.tx_hashes
        )

        self.canonical_hashes = new_chain
        self.rebuild_transaction_indexes()
        if should_cancel_mining:
            self.cancel_mining("chain tip changed")

        print(
            f"Canonical chain height is now {self.current_height()} "
            f"with tip {self.tip_hash().hex()}",
            flush=True,
        )

    def rebuild_transaction_indexes(self) -> None:
        """Recompute included transactions and mempool after a chain switch."""
        self.included_tx_heights.clear()
        for height, block_hash in enumerate(self.canonical_hashes):
            block = self.blocks_by_hash[block_hash]
            for tx_hash in block.tx_hashes:
                self.included_tx_heights[tx_hash] = height

        self.mempool = {
            tx_hash: record
            for tx_hash, record in self.all_transactions.items()
            if tx_hash not in self.included_tx_heights
        }

    # ----- Mining ---------------------------------------------------------------

    def should_mine(self) -> bool:
        """Return whether this node currently has a reason to mine another block."""
        if self.mempool:
            return True
        if self.confirmation_blocks_needed() > 0:
            return True
        return self.mine_empty_blocks

    def confirmation_blocks_needed(self) -> int:
        """Return how many more blocks are needed to bury known transactions."""
        if not self.included_tx_heights:
            return 0

        current_height = self.current_height()
        missing = 0
        for included_height in self.included_tx_heights.values():
            blocks_on_top = current_height - included_height
            missing = max(missing, self.required_confirmations - blocks_on_top)
        return max(0, missing)

    def select_transactions_for_next_block(self) -> tuple[bytes, ...]:
        """Choose the transaction hashes to commit in the next mined block."""
        # Sorting makes the block body deterministic for a given mempool.
        return tuple(sorted(self.mempool.keys()))

    def cancel_empty_mining_for_new_transaction(self) -> None:
        """Restart empty-block mining if a real transaction arrives mid-search."""
        if self.mining_task is None or self.mining_task.done():
            return
        if not self.mining_tx_hashes and self.mempool:
            self.cancel_mining("new transaction arrived")

    def cancel_mining(self, reason: str) -> None:
        """Cancel the current asynchronous mining task and clear its metadata."""
        if self.mining_task is not None and not self.mining_task.done():
            print(f"Stopping current mining task: {reason}", flush=True)
            self.mining_task.cancel()
        self.mining_task = None
        self.mining_height = None
        self.mining_prev_hash = None
        self.mining_tx_hashes = ()

    def harvest_mining_task(self) -> None:
        """Collect exceptions from a finished mining task so they are not lost."""
        if self.mining_task is None or not self.mining_task.done():
            return

        task = self.mining_task
        self.mining_task = None
        self.mining_height = None
        self.mining_prev_hash = None
        self.mining_tx_hashes = ()

        try:
            task.result()
        except asyncio.CancelledError:
            return
        except Exception as exc:
            print(f"Mining task failed: {exc}", flush=True)

    def maybe_start_mining(self) -> None:
        """Start mining if there is work and this node is the height leader."""
        self.harvest_mining_task()

        if self.mining_task is not None or not self.should_mine():
            return

        # Only one deterministic leader mines each height. This keeps the group
        # from creating three competing blocks at the same height.
        next_height = self.current_height() + 1
        if not self.is_my_turn_to_mine(next_height):
            return

        prev_hash = self.tip_hash()
        tx_hashes = self.select_transactions_for_next_block()

        self.mining_height = next_height
        self.mining_prev_hash = prev_hash
        self.mining_tx_hashes = tx_hashes
        self.mining_task = asyncio.create_task(self.mine_block(next_height, prev_hash, tx_hashes))

    async def mine_block(self, height: int, prev_hash: bytes, tx_hashes: tuple[bytes, ...]) -> None:
        """Search for a nonce, publish the block, and yield periodically to IPv8."""
        txs_hash = calculate_txs_hash(tx_hashes)
        timestamp = int(time.time())
        nonce = 0
        task = asyncio.current_task()

        print(
            f"Mining block {height} as member {self.member_id} "
            f"with {len(tx_hashes)} transaction(s)",
            flush=True,
        )

        try:
            while True:
                # Stop immediately if another block moved the tip while this
                # task was searching. The next tick will decide whether to mine
                # a new height.
                if height != self.current_height() + 1 or prev_hash != self.tip_hash():
                    return

                for _ in range(self.nonce_batch):
                    block_hash = calculate_block_hash(prev_hash, txs_hash, timestamp, self.difficulty, nonce)
                    if satisfies_pow(block_hash, self.difficulty):
                        block = Block(
                            height=height,
                            prev_hash=prev_hash,
                            txs_hash=txs_hash,
                            timestamp=timestamp,
                            difficulty=self.difficulty,
                            nonce=nonce,
                            block_hash=block_hash,
                            tx_hashes=tx_hashes,
                        )
                        if self.accept_block(block, source="local miner"):
                            self.broadcast_block(block)
                        return

                    nonce += 1
                    if nonce > MAX_I64:
                        # DataClassPayload sends nonce as signed int64, so keep
                        # our mined nonce in the range the wire format can carry.
                        nonce = 0
                        timestamp = int(time.time())

                await asyncio.sleep(0)
        except asyncio.CancelledError:
            return
        finally:
            if self.mining_task is task:
                self.mining_task = None
                self.mining_height = None
                self.mining_prev_hash = None
                self.mining_tx_hashes = ()

    # ----- Block and chain-summary gossip ---------------------------------------

    def broadcast_block(self, block: Block, exclude_peer: Peer | None = None) -> None:
        """Gossip a mined or accepted block to teammates."""
        exclude_key = exclude_peer.public_key.key_to_bin() if exclude_peer is not None else None
        payload = block.to_gossip_payload()
        for peer in self.member_peers.values():
            if peer.public_key.key_to_bin() != exclude_key:
                self.ez_send(peer, payload)

    def maybe_broadcast_summary(self) -> None:
        """Periodically announce our current height and tip hash to teammates."""
        now = time.monotonic()
        if now - self.last_summary_at < self.summary_seconds:
            return

        payload = ChainSummaryPayload(self.current_height(), self.tip_hash())
        for peer in self.member_peers.values():
            self.ez_send(peer, payload)
        self.last_summary_at = now

    def maybe_regossip_mempool(self) -> None:
        """Periodically resend mempool transactions in case earlier gossip was missed."""
        if not self.mempool:
            return

        now = time.monotonic()
        if now - self.last_mempool_gossip_at < self.summary_seconds:
            return

        for record in self.mempool.values():
            self.broadcast_transaction(record)
        self.last_mempool_gossip_at = now

    # ----- Periodic driver -------------------------------------------------------

    def tick(self) -> None:
        """Run one lightweight maintenance step for peer discovery, gossip, and mining."""
        self.discover_known_peers()
        self.maybe_broadcast_summary()
        self.maybe_regossip_mempool()
        self.maybe_start_mining()


# ---------------------------------------------------------------------------
# IPv8 startup and CLI entrypoint.
# ---------------------------------------------------------------------------


async def start_node(args: argparse.Namespace) -> None:
    """Configure IPv8, start both Lab 3 overlays, and drive them forever."""
    member_public_keys = load_member_public_keys(args.member_public_key)
    self_public_key = public_key_from_private_key_file(args.key_file)

    if self_public_key not in member_public_keys:
        raise ValueError(
            "the supplied private key's public key is not in PUBLIC_KEYS/--member-public-key; "
            f"public key was {self_public_key.hex()}"
        )

    member_id = member_public_keys.index(self_public_key)
    group_id = args.group_id or os.getenv("LAB2_GROUP_ID") or os.getenv("GROUP_ID")
    if not group_id:
        raise ValueError("provide your Lab 2 group id with --group-id, LAB2_GROUP_ID, or GROUP_ID")

    # A fixed community id can be supplied explicitly. Otherwise all teammates
    # will derive the same default from the shared Lab 2 group id.
    if args.blockchain_community_id:
        blockchain_community_id = parse_hex_bytes(args.blockchain_community_id, "blockchain community id", 20)
    else:
        blockchain_community_id = derive_blockchain_community_id(group_id)

    if args.difficulty < 0 or args.difficulty > HASH_SIZE * 8:
        raise ValueError("difficulty must be between 0 and 256")
    if args.required_confirmations < 0:
        raise ValueError("required confirmations must be non-negative")
    if args.nonce_batch <= 0:
        raise ValueError("nonce batch must be positive")

    Lab3BlockchainCommunity.community_id = blockchain_community_id

    # Both overlays use the same IPv8 identity. That is what lets the server
    # identify the node from IPv8's authenticated message header.
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(args.port)
    builder.set_log_level(args.log_level)
    builder.add_key(KEY_ALIAS, args.key_type, str(args.key_file))

    walker = [WalkerDefinition(Strategy.RandomWalk, args.target_peers, {"timeout": args.walk_timeout})]

    # Overlay 1: the fixed official community used only for registration.
    builder.add_overlay(
        "Lab3RegistrationCommunity",
        KEY_ALIAS,
        walker,
        default_bootstrap_defs,
        {
            "group_id": group_id,
            "blockchain_community_id": blockchain_community_id,
            "server_public_key": SERVER_PUBLIC_KEY,
            "retry_seconds": args.register_retry_seconds,
        },
        [],
    )
    # Overlay 2: our own blockchain community, where the server will submit the
    # test transaction and query blocks after registration succeeds.
    builder.add_overlay(
        "Lab3BlockchainCommunity",
        KEY_ALIAS,
        walker,
        default_bootstrap_defs,
        {
            "member_id": member_id,
            "member_public_keys": member_public_keys,
            "server_public_key": SERVER_PUBLIC_KEY,
            "difficulty": args.difficulty,
            "required_confirmations": args.required_confirmations,
            "summary_seconds": args.summary_seconds,
            "nonce_batch": args.nonce_batch,
            "mine_empty_blocks": args.mine_empty_blocks,
        },
        [],
    )

    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={
            "Lab3RegistrationCommunity": Lab3RegistrationCommunity,
            "Lab3BlockchainCommunity": Lab3BlockchainCommunity,
        },
    )

    await ipv8.start()
    registration = ipv8.get_overlay(Lab3RegistrationCommunity)
    blockchain = ipv8.get_overlay(Lab3BlockchainCommunity)
    if registration is None or blockchain is None:
        await ipv8.stop()
        raise RuntimeError("IPv8 did not start one of the Lab 3 overlays")

    print(f"IPv8 started on {ipv8.endpoint.get_address()}", flush=True)
    print(f"Using member id {member_id} with public key {self_public_key.hex()}", flush=True)
    print(f"Registration community: {REGISTRATION_COMMUNITY_ID.hex()}", flush=True)
    print(f"Blockchain community:   {blockchain_community_id.hex()}", flush=True)
    print(f"Genesis hash:           {make_genesis_block().block_hash.hex()}", flush=True)

    try:
        while True:
            # IPv8 handles packet I/O in the background; these ticks perform
            # our application-level retries, gossip, and mining decisions.
            registration.tick()
            blockchain.tick()
            await asyncio.sleep(args.tick_seconds)
    finally:
        blockchain.cancel_mining("node is shutting down")
        await ipv8.stop()


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for running one Lab 3 node."""
    parser = argparse.ArgumentParser(description="TU Delft Blockchain Engineering Lab 3 IPv8 blockchain node")
    parser.add_argument("key_file", type=Path, help="IPv8 .pem private key for the member you want to run")
    parser.add_argument("--group-id", help="Lab 2 group id; can also be set with LAB2_GROUP_ID or GROUP_ID")
    parser.add_argument(
        "--member-public-key",
        action="append",
        help="one group member public key as hex; repeat exactly three times, or set PUBLIC_KEYS as in Lab 2",
    )
    parser.add_argument(
        "--blockchain-community-id",
        default=os.getenv("LAB3_COMMUNITY_ID"),
        help="20-byte blockchain community id as hex; default is derived from the group id",
    )
    parser.add_argument("--difficulty", type=int, default=int(os.getenv("LAB3_DIFFICULTY", DEFAULT_DIFFICULTY)))
    parser.add_argument(
        "--required-confirmations",
        type=int,
        default=int(os.getenv("LAB3_CONFIRMATIONS", DEFAULT_CONFIRMATIONS)),
        help="number of blocks that should be mined on top of an included transaction",
    )
    parser.add_argument("--mine-empty-blocks", action="store_true", help="continue mining empty blocks after confirmations")
    parser.add_argument("--port", type=int, default=0, help="local UDP port; 0 lets the OS choose")
    parser.add_argument("--target-peers", type=int, default=20, help="IPv8 RandomWalk target peer count")
    parser.add_argument("--walk-timeout", type=float, default=3.0, help="IPv8 RandomWalk timeout")
    parser.add_argument("--register-retry-seconds", type=float, default=DEFAULT_REGISTER_RETRY_SECONDS)
    parser.add_argument("--summary-seconds", type=float, default=DEFAULT_SUMMARY_SECONDS)
    parser.add_argument("--tick-seconds", type=float, default=DEFAULT_TICK_SECONDS)
    parser.add_argument("--nonce-batch", type=int, default=DEFAULT_NONCE_BATCH)
    parser.add_argument(
        "--key-type",
        default=os.getenv("LAB3_KEY_TYPE", "curve25519"),
        help="IPv8 key type used only if the key file must be generated; existing files keep their own type",
    )
    parser.add_argument(
        "--log-level",
        default=os.getenv("IPV8_LOG_LEVEL", "WARNING"),
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"],
        help="IPv8 log level",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Load environment settings, parse CLI arguments, and run the async node."""
    load_dotenv()
    args = build_parser().parse_args(argv)

    try:
        asyncio.run(start_node(args))
        return 0
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    raise SystemExit(main())
