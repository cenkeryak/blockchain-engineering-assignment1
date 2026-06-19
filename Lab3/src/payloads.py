"""Wire payloads for the registration community and the blockchain community."""

from dataclasses import dataclass

from ipv8.messaging.payload_dataclass import DataClassPayload


# --- Registration community (message ids defined by the server) ---

@dataclass
class RegisterBlockchain(DataClassPayload[1]):
    group_id: str
    community_id: bytes


@dataclass
class RegisterResponse(DataClassPayload[2]):
    success: bool
    message: str


# --- Blockchain community: server queries (message ids defined by the server) ---

@dataclass
class SubmitTransaction(DataClassPayload[1]):
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes


@dataclass
class SubmitTransactionResponse(DataClassPayload[2]):
    success: bool
    tx_hash: bytes
    message: str


@dataclass
class GetChainHeight(DataClassPayload[3]):
    request_id: int


@dataclass
class ChainHeightResponse(DataClassPayload[4]):
    request_id: int
    height: int
    tip_hash: bytes


@dataclass
class GetBlock(DataClassPayload[5]):
    height: int


@dataclass
class BlockResponse(DataClassPayload[6]):
    height: int
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    block_hash: bytes
    tx_hashes: bytes  # concatenated 32-byte tx hashes


# --- Blockchain community: internal messages between our own 3 nodes ---

@dataclass
class NewBlockGossip(DataClassPayload[7]):
    height: int
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    tx_hashes: bytes


@dataclass
class TransactionGossip(DataClassPayload[8]):
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes


@dataclass
class GetTransaction(DataClassPayload[9]):
    tx_hash: bytes


# DataClassPayload registers its wire format on first instantiation, which must
# happen before the first inbound packet of that type is unpacked.
for _cls in (RegisterBlockchain, RegisterResponse, SubmitTransaction,
             SubmitTransactionResponse, GetChainHeight, ChainHeightResponse,
             GetBlock, BlockResponse, NewBlockGossip, TransactionGossip,
             GetTransaction):
    _cls(*([None] * len(_cls.__dataclass_fields__)))
