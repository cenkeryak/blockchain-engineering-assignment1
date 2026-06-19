"""Local stand-in for the Lab 3 grading server.

Replays the server's checks against your running nodes: submits a signed test
transaction, then walks every node's chain and verifies PoW, header linking,
body commitment, 3 confirmations, and 3-way consistency.

Usage:
    1. python test_server.py            (prints its public key, then waits)
    2. add to .env:  LAB3_SERVER_KEY=<that key hex>
    3. start your 3 nodes; the script does the rest.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from hashlib import sha256
from pathlib import Path

from dotenv import load_dotenv
from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.peer import Peer
from ipv8_service import IPv8

from src.blocks import leading_zero_bits, pack_header
from src.main import derive_community_id
from src.payloads import (
    BlockResponse,
    ChainHeightResponse,
    GetBlock,
    GetChainHeight,
    SubmitTransaction,
    SubmitTransactionResponse,
)

KEY_FILE = "test_server_key.pem"
CONFIRMATIONS = 3
OVERALL_TIMEOUT = 300.0


class TestServerCommunity(Community):
    __test__ = False
    community_id = b""  # set in main()

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.member_keys: list[bytes] = []
        self.tx_response: SubmitTransactionResponse | None = None
        self.heights: dict[bytes, ChainHeightResponse] = {}
        self.blocks: dict[bytes, dict[int, BlockResponse]] = {}
        self.add_message_handler(SubmitTransactionResponse, self.on_tx_response)
        self.add_message_handler(ChainHeightResponse, self.on_height_response)
        self.add_message_handler(BlockResponse, self.on_block_response)

    def members(self) -> list[Peer]:
        return [p for p in self.get_peers() if p.public_key.key_to_bin() in self.member_keys]

    @lazy_wrapper(SubmitTransactionResponse)
    def on_tx_response(self, peer: Peer, payload: SubmitTransactionResponse) -> None:
        self.tx_response = payload

    @lazy_wrapper(ChainHeightResponse)
    def on_height_response(self, peer: Peer, payload: ChainHeightResponse) -> None:
        self.heights[peer.public_key.key_to_bin()] = payload

    @lazy_wrapper(BlockResponse)
    def on_block_response(self, peer: Peer, payload: BlockResponse) -> None:
        self.blocks.setdefault(peer.public_key.key_to_bin(), {})[payload.height] = payload


async def fetch_chain(server: TestServerCommunity, peer: Peer, height: int) -> dict[int, BlockResponse] | None:
    key = peer.public_key.key_to_bin()
    server.blocks[key] = {}
    deadline = time.time() + 30
    while time.time() < deadline:
        missing = [h for h in range(height + 1) if h not in server.blocks[key]]
        if not missing:
            return server.blocks[key]
        for h in missing:
            server.ez_send(peer, GetBlock(h))
        await asyncio.sleep(0.5)
    return None


def validate_chain(blocks: dict[int, BlockResponse], tx_hash: bytes) -> tuple[bool, int | None]:
    """Returns (chain valid, height of the block containing tx_hash)."""
    tx_height = None
    for h in sorted(blocks):
        b = blocks[h]
        header = pack_header(b.prev_hash, b.txs_hash, b.timestamp, b.difficulty, b.nonce)
        if sha256(header).digest() != b.block_hash:
            print(f"    block {h}: block_hash does not match header")
            return False, None
        if leading_zero_bits(b.block_hash) < b.difficulty:
            print(f"    block {h}: PoW below declared difficulty")
            return False, None
        if h > 0 and b.prev_hash != blocks[h - 1].block_hash:
            print(f"    block {h}: prev_hash does not link to parent")
            return False, None
        hashes = [b.tx_hashes[i:i + 32] for i in range(0, len(b.tx_hashes), 32)]
        if sha256(b"".join(hashes)).digest() != b.txs_hash:
            print(f"    block {h}: body commitment mismatch")
            return False, None
        if tx_hash in hashes:
            tx_height = h
    return True, tx_height


async def run_checks(server: TestServerCommunity, my_key) -> bool:
    print("[server] waiting for all 3 nodes...")
    while len(server.members()) < 3:
        await asyncio.sleep(1)
    members = server.members()
    print(f"[server] found all 3 nodes: {[str(p.address) for p in members]}")

    # Submit a signed test transaction to one node (mirrors the real server).
    sender_key = my_key.pub().key_to_bin()
    data, timestamp = b"lab3 local test transaction", int(time.time())
    signature = default_eccrypto.create_signature(
        my_key, sender_key + data + timestamp.to_bytes(8, "big"))
    while server.tx_response is None:
        server.ez_send(members[0], SubmitTransaction(sender_key, data, timestamp, signature))
        await asyncio.sleep(2)
    if not server.tx_response.success:
        print(f"[FAIL] transaction rejected: {server.tx_response.message}")
        return False
    tx_hash = server.tx_response.tx_hash
    print(f"[ok] transaction accepted, tx_hash {tx_hash.hex()[:16]}")

    deadline = time.time() + OVERALL_TIMEOUT
    while time.time() < deadline:
        await asyncio.sleep(5)

        server.heights.clear()
        for peer in members:
            server.ez_send(peer, GetChainHeight(int(time.time())))
        await asyncio.sleep(2)
        if len(server.heights) < 3:
            print("[server] not all nodes answered the height query, retrying...")
            continue
        common_height = min(r.height for r in server.heights.values())
        print(f"[server] heights: {sorted(r.height for r in server.heights.values())}, "
              f"checking up to {common_height}")

        chains = {}
        for peer in members:
            chain = await fetch_chain(server, peer, common_height)
            if chain is None:
                break
            chains[peer.public_key.key_to_bin()] = chain
        if len(chains) < 3:
            print("[server] could not fetch all chains, retrying...")
            continue

        ok, tx_heights = True, []
        for key, chain in chains.items():
            valid, tx_height = validate_chain(chain, tx_hash)
            if not valid:
                ok = False
            tx_heights.append(tx_height)
        if not ok:
            return False  # a structurally broken chain will not fix itself
        if any(h is None for h in tx_heights):
            print("[server] transaction not yet in every chain, waiting...")
            continue
        if len(set(tx_heights)) != 1:
            print("[server] transaction at different heights, waiting for convergence...")
            continue
        confirmations = common_height - tx_heights[0]
        if confirmations < CONFIRMATIONS:
            print(f"[server] {confirmations}/{CONFIRMATIONS} confirmations, waiting...")
            continue

        consistent = all(
            len({chain[h].block_hash for chain in chains.values()}) == 1
            for h in range(common_height + 1))
        if not consistent:
            print("[server] nodes disagree on a block hash, waiting for convergence...")
            continue

        print(f"[PASS] all checks hold: tx at height {tx_heights[0]} with {confirmations} "
              f"confirmations, all 3 chains consistent up to height {common_height}")
        return True

    print("[FAIL] timed out waiting for the checks to pass")
    return False


async def main() -> None:
    load_dotenv()
    group_id = os.environ["GROUP_ID"]

    if Path(KEY_FILE).exists():
        my_key = default_eccrypto.key_from_private_bin(Path(KEY_FILE).read_bytes())
    else:
        my_key = default_eccrypto.generate_key("curve25519")
        Path(KEY_FILE).write_bytes(my_key.key_to_bin())
    print(f"[server] my public key (put in .env as LAB3_SERVER_KEY):\n"
          f"{my_key.pub().key_to_bin().hex()}")

    TestServerCommunity.community_id = derive_community_id(group_id)
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("test server", "curve25519", KEY_FILE)
    builder.add_overlay("TestServerCommunity", "test server",
                        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
                        default_bootstrap_defs, {}, [])
    ipv8 = IPv8(builder.finalize(), extra_communities={"TestServerCommunity": TestServerCommunity})
    await ipv8.start()

    server = ipv8.get_overlay(TestServerCommunity)
    server.member_keys = [bytes.fromhex(k) for k in json.loads(os.environ["PUBLIC_KEYS"])]
    try:
        await run_checks(server, my_key)
    finally:
        await ipv8.stop()


if __name__ == "__main__":
    asyncio.run(main())
