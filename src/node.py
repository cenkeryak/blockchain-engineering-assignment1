import asyncio
import json
import os
from dataclasses import dataclass

from dotenv import load_dotenv
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.peer import Peer
from ipv8_service import IPv8

from src.blockchain import Blockchain, Transaction
from src.core import Block, BlockHeader


load_dotenv()

NODE_ID = int(os.getenv("NODE_ID", "0"))
KEY_FILE = f"node_data/node{NODE_ID}/lab1_key.pem"

BLOCKCHAIN_COMMUNITY_ID = bytes.fromhex(
    os.getenv("BLOCKCHAIN_COMMUNITY_ID", "4c61623344617277696e436861696e32303236")
)

DIFFICULTY = int(os.getenv("DIFFICULTY", "8"))


@dataclass
class TxPayload(DataClassPayload[11]):
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes


@dataclass
class BlockPayload(DataClassPayload[12]):
    height: int
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    tx_hashes: bytes


@dataclass
class RequestBlockPayload(DataClassPayload[13]):
    height: int


def block_to_payload(block: Block) -> BlockPayload:
    return BlockPayload(
        height=block.height,
        prev_hash=block.header.prev_hash,
        txs_hash=block.header.txs_hash,
        timestamp=block.header.timestamp,
        difficulty=block.header.difficulty,
        nonce=block.header.nonce,
        tx_hashes=block.tx_hashes_blob,
    )


def payload_to_block(payload: BlockPayload) -> Block:
    tx_hashes = [
        payload.tx_hashes[i : i + 32]
        for i in range(0, len(payload.tx_hashes), 32)
    ]

    header = BlockHeader(
        prev_hash=payload.prev_hash,
        txs_hash=payload.txs_hash,
        timestamp=payload.timestamp,
        difficulty=payload.difficulty,
        nonce=payload.nonce,
    )

    return Block(
        height=payload.height,
        header=header,
        tx_hashes=tx_hashes,
    )


class BlockchainCommunity(Community):
    community_id = BLOCKCHAIN_COMMUNITY_ID

    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)

        self.blockchain = Blockchain(difficulty=DIFFICULTY)

        self.add_message_handler(TxPayload, self.on_tx)
        self.add_message_handler(BlockPayload, self.on_block)
        self.add_message_handler(RequestBlockPayload, self.on_request_block)

    def started(self):
        self.register_task("miner", self.mine_loop, interval=3.0, delay=2.0)
        self.register_task("status", self.status_loop, interval=5.0, delay=1.0)

    def known_peers(self) -> list[Peer]:
        return self.get_peers()

    def broadcast(self, payload):
        for peer in self.known_peers():
            self.ez_send(peer, payload)

    @lazy_wrapper(TxPayload)
    def on_tx(self, peer: Peer, payload: TxPayload):
        tx = Transaction(
            sender_key=payload.sender_key,
            data=payload.data,
            timestamp=payload.timestamp,
            signature=payload.signature,
        )

        txh = self.blockchain.add_transaction(tx)
        print(f"received tx {txh.hex()} from {peer}")

        self.broadcast(payload)

    @lazy_wrapper(BlockPayload)
    def on_block(self, peer: Peer, payload: BlockPayload):
        block = payload_to_block(payload)

        print(f"received block height={block.height} hash={block.block_hash.hex()}")

        # Need to add handling for forks and all dat
        if block.height == self.blockchain.height + 1:
            if block.header.prev_hash == self.blockchain.tip_hash:
                try:
                    from src.core import validate_block

                    validate_block(block, self.blockchain.tip)
                    self.blockchain.chain.append(block)
                    self.blockchain.validate()
                    print(f"accepted block height={block.height}")
                    self.broadcast(payload)
                except Exception as e:
                    print(f"rejected block: {e}")
            else:
                print("block does not extend current tip")
        elif block.height <= self.blockchain.height:
            print("already have this height or block is old")
        else:
            print(f"missing blocks before height {block.height}; requesting")
            self.ez_send(peer, RequestBlockPayload(self.blockchain.height + 1))

    @lazy_wrapper(RequestBlockPayload)
    def on_request_block(self, peer: Peer, payload: RequestBlockPayload):
        try:
            block = self.blockchain.get_block(payload.height)
        except IndexError:
            print(f"peer requested missing block height={payload.height}")
            return

        self.ez_send(peer, block_to_payload(block))

    async def mine_loop(self):
        block = self.blockchain.mine_next_block()
        print(
            f"mined height={block.height} "
            f"hash={block.block_hash.hex()} "
            f"txs={len(block.tx_hashes)}"
        )
        self.broadcast(block_to_payload(block))

    async def status_loop(self):
        print(
            f"node={NODE_ID} "
            f"height={self.blockchain.height} "
            f"tip={self.blockchain.tip_hash.hex()} "
            f"peers={len(self.get_peers())} "
            f"mempool={len(self.blockchain.mempool)}"
        )


async def main():
    print(f"NODE_ID={NODE_ID}")
    print(f"PORT={PORT}")
    print(f"KEY_FILE={KEY_FILE}")
    print(f"COMMUNITY_ID={BLOCKCHAIN_COMMUNITY_ID.hex()}")

    builder = ConfigBuilder()
    builder.clear_keys()
    builder.clear_overlays()

    builder.add_key("node-key", "curve25519", KEY_FILE)


    builder.add_overlay(
        "BlockchainCommunity",
        "node-key",
        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )

    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={"BlockchainCommunity": BlockchainCommunity},
    )

    await ipv8.start()

    try:
        while True:
            await asyncio.sleep(1)
    finally:
        await ipv8.stop()


if __name__ == "__main__":
    asyncio.run(main())

# Need to add server protocol 
# handle forks
# prop trx
# longest chain switching