"""Unit tests for multi-miner chain adoption.

Run with: PYTHONPATH=. pytest test/test_blockchain.py
"""

from __future__ import annotations

from unittest.mock import patch

from ipv8.keyvault.crypto import default_eccrypto
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import Network
from ipv8.test.mocking.endpoint import AutoMockEndpoint

from src.blocks import Blockchain, Transaction, genesis_block, make_block, meets_difficulty
from src.community import BlockchainCommunity, BlockchainSettings
from hashlib import sha256
from src.payloads import GetBlock, GetTransaction

BlockchainCommunity.community_id = b"\xab" * 20

AHEAD_BY = 5
TEST_DIFFICULTY = 8


def mine_chain(length: int, difficulty: int = TEST_DIFFICULTY) -> list:
    """Return a valid chain [genesis, block1, ..., block(length-1)]."""
    chain = [genesis_block()]

    for height in range(1, length):
        prev = chain[-1]
        nonce = 0

        while True:
            block = make_block(
                height,
                prev.block_hash,
                [],
                1_718_000_000 + height,
                difficulty,
                nonce,
            )

            if meets_difficulty(block.block_hash, difficulty):
                chain.append(block)
                break

            nonce += 1

    return chain


def make_community(
    member_keys: list[bytes],
    private_keys: list,
    my_index: int,
) -> BlockchainCommunity:
    endpoint = AutoMockEndpoint()
    endpoint.open()

    settings = BlockchainSettings(
        endpoint=endpoint,
        network=Network(),
        my_peer=Peer(private_keys[my_index], endpoint.wan_address),
        member_keys=member_keys,
        server_key=b"",
    )

    with patch.object(BlockchainCommunity, "register_task"):
        community = BlockchainCommunity(settings)

    community.my_estimated_wan = endpoint.wan_address
    community.my_estimated_lan = endpoint.lan_address

    return community


def install_chain(community: BlockchainCommunity, chain: list) -> None:
    community.blockchain.chain = list(chain)
    community.blockchain.chain_tx_hashes = {
        txh for block in chain for txh in block.tx_hashes
    }

    for block in chain:
        community.blockchain.block_pool[block.block_hash] = block


def connect_members(communities: list[BlockchainCommunity]) -> None:
    for left in communities:
        for right in communities:
            if left is right:
                continue

            peer = Peer(right.my_peer.public_key, right.endpoint.wan_address)
            left.network.add_verified_peer(peer)


def peer_for(community: BlockchainCommunity) -> Peer:
    return Peer(community.my_peer.public_key, community.my_peer.address)


def gossip_block(community: BlockchainCommunity, peer: Peer, block) -> None:
    community.handle_block(
        peer,
        block.height,
        block.prev_hash,
        block.txs_hash,
        block.timestamp,
        block.difficulty,
        block.nonce,
        b"".join(block.tx_hashes),
    )


def serve_blocks_from(leader: BlockchainCommunity, follower: BlockchainCommunity) -> None:
    """Simulate a teammate answering GetBlock requests while adoption runs."""
    leader_peer = peer_for(leader)

    def answer_request(height: int, peer: Peer | None = None) -> None:
        gossip_block(follower, leader_peer, leader.blockchain.chain[height])

    follower.request_block = answer_request  # type: ignore[method-assign]


def make_miners() -> tuple[list[bytes], list, list[BlockchainCommunity]]:
    private_keys = [default_eccrypto.generate_key("curve25519") for _ in range(3)]
    member_keys = [key.pub().key_to_bin() for key in private_keys]
    communities = [make_community(member_keys, private_keys, i) for i in range(3)]
    return member_keys, private_keys, communities


def test_lagging_miners_adopt_longer_chain():
    """When one miner is several blocks ahead, the others adopt its chain."""
    _keys, _private_keys, (leader, follower_a, follower_b) = make_miners()
    connect_members([leader, follower_a, follower_b])

    leader_chain = mine_chain(1 + AHEAD_BY)
    install_chain(leader, leader_chain)

    assert len(follower_a.blockchain.chain) == 1
    assert len(follower_b.blockchain.chain) == 1

    leader_peer = peer_for(leader)

    for block in leader_chain[1:]:
        gossip_block(follower_a, leader_peer, block)
        gossip_block(follower_b, leader_peer, block)

    for follower in (follower_a, follower_b):
        assert len(follower.blockchain.chain) == len(leader_chain)

        for height, expected in enumerate(leader_chain):
            assert follower.blockchain.chain[height].block_hash == expected.block_hash


def test_lagging_miner_catches_up_via_height_sync():
    """A miner behind by several blocks catches up when it polls a taller teammate."""
    _keys, _private_keys, (leader, follower, other) = make_miners()
    connect_members([leader, follower, other])

    leader_chain = mine_chain(1 + AHEAD_BY)
    install_chain(leader, leader_chain)
    serve_blocks_from(leader, follower)

    follower.request_block(leader_chain[-1].height, peer_for(leader))

    assert len(follower.blockchain.chain) == len(leader_chain)
    assert follower.blockchain.chain[-1].block_hash == leader_chain[-1].block_hash


def test_lagging_miner_adopts_when_tip_arrives_first():
    """Receiving the tip before its parents still ends on the longer chain."""
    _keys, _private_keys, (leader, follower, other) = make_miners()
    connect_members([leader, follower, other])

    leader_chain = mine_chain(1 + AHEAD_BY)
    install_chain(leader, leader_chain)
    serve_blocks_from(leader, follower)

    gossip_block(follower, peer_for(leader), leader_chain[-1])

    assert len(follower.blockchain.chain) == len(leader_chain)
    assert follower.blockchain.chain[-1].block_hash == leader_chain[-1].block_hash


def test_remember_missing_block_requests_once():
    _keys, _private_keys, (community, peer_owner, _other) = make_miners()
    peer = peer_for(peer_owner)

    sent = []
    community.ez_send = lambda peer, payload: sent.append((peer, payload))  # type: ignore[method-assign]

    community.remember_missing_block(3, peer)
    community.remember_missing_block(3, peer)

    assert community.missing_block_requests[3][1] == 1
    assert len(sent) == 1
    assert isinstance(sent[0][1], GetBlock)
    assert sent[0][1].height == 3


def test_remember_missing_transactions_requests_only_new_hashes():
    _keys, _private_keys, (community, peer_owner, _other) = make_miners()
    peer = peer_for(peer_owner)
    tx_hash = sha256(b"missing tx").digest()

    sent = []
    community.ez_send = lambda peer, payload: sent.append((peer, payload))  # type: ignore[method-assign]

    community.remember_missing_transactions([tx_hash], peer)
    community.remember_missing_transactions([tx_hash], peer)

    assert community.missing_tx_requests[tx_hash][1] == 1
    assert len(sent) == 1
    assert isinstance(sent[0][1], GetTransaction)
    assert sent[0][1].tx_hash == tx_hash


def test_retry_missing_block_uses_backoff_and_increments_retry_count():
    _keys, _private_keys, (community, _peer, _other) = make_miners()

    requested = []
    community.request_block = lambda height, peer=None: requested.append((height, peer))  # type: ignore[method-assign]

    community.missing_block_requests[4] = (0.0, 1)

    with patch("src.community.time.time", return_value=10.0):
        community.retry_missing_blocks()

    assert community.missing_block_requests[4][1] == 2
    assert requested == [(4, None)]


def test_retry_missing_transaction_uses_backoff_and_increments_retry_count():
    _keys, _private_keys, (community, _peer, _other) = make_miners()
    tx_hash = sha256(b"missing tx").digest()

    requested = []
    community.request_transactions = lambda tx_hashes, peer=None: requested.append((tx_hashes, peer))  # type: ignore[method-assign]

    community.missing_tx_requests[tx_hash] = (0.0, 1)

    with patch("src.community.time.time", return_value=10.0):
        community.retry_missing_transactions()

    assert community.missing_tx_requests[tx_hash][1] == 2
    assert requested == [([tx_hash], None)]


def test_retry_missing_transaction_removed_when_arrived():
    _keys, _private_keys, (community, _peer, _other) = make_miners()

    tx_hash = sha256(b"tx").digest()

    community.missing_tx_requests[tx_hash] = (0.0, 1)

    community.blockchain.chain_tx_hashes.add(tx_hash)

    community.retry_missing_transactions()

    assert tx_hash not in community.missing_tx_requests


# --- regression tests: a transaction shared across competing branches ----------
#
# Two miners can independently mine the *same* transaction into competing blocks
# at the same height. The losing block must still be adoptable, otherwise the two
# nodes stay stuck on their own branch forever and the 3-way consistency check
# fails. We used to reject such a block as a double-spend because the tx was still
# present in the chain we were about to roll back.


def signed_tx(data: bytes = b"shared tx") -> Transaction:
    key = default_eccrypto.generate_key("curve25519")
    sender_key = key.pub().key_to_bin()
    timestamp = 1_718_000_000
    signature = default_eccrypto.create_signature(
        key, sender_key + data + timestamp.to_bytes(8, "big")
    )
    return Transaction(sender_key, data, timestamp, signature)


def mine_block(height, prev_hash, tx_hashes, timestamp, difficulty=TEST_DIFFICULTY):
    nonce = 0
    while True:
        block = make_block(height, prev_hash, tx_hashes, timestamp, difficulty, nonce)
        if meets_difficulty(block.block_hash, difficulty):
            return block
        nonce += 1


def test_equal_height_tiebreak_with_shared_transaction():
    """Two height-1 blocks both carry the same tx. After adopting the higher-hash
    one, the smaller-hash competitor must win the tie-break instead of being
    rejected as a double-spend."""
    bc = Blockchain()
    tx = signed_tx()
    bc.accept_transaction(tx)
    genesis = bc.tip

    # Distinct timestamps -> distinct block hashes for the two competing blocks.
    a = mine_block(1, genesis.block_hash, [tx.tx_hash], 1_718_000_001)
    b = mine_block(1, genesis.block_hash, [tx.tx_hash], 1_718_000_002)
    smaller, larger = sorted((a, b), key=lambda blk: blk.block_hash)

    accepted, _, _ = bc.add_block(larger)
    assert accepted
    assert bc.tip.block_hash == larger.block_hash

    # The competitor arrives; the smaller hash must take over at the same height.
    bc.add_block(smaller)
    assert bc.tip.block_hash == smaller.block_hash
    assert bc.height == 1


def test_longer_branch_reusing_transaction_is_adopted():
    """A taller competing branch whose base block re-includes our chain's tx must
    still be adoptable, even when its tip arrives before its parent."""
    bc = Blockchain()
    tx = signed_tx()
    bc.accept_transaction(tx)
    genesis = bc.tip

    ours = mine_block(1, genesis.block_hash, [tx.tx_hash], 1_718_000_001)
    bc.add_block(ours)
    assert bc.tip.block_hash == ours.block_hash

    # Competing branch: b1 also carries the tx, b2 extends it one higher.
    b1 = mine_block(1, genesis.block_hash, [tx.tx_hash], 1_718_000_050)
    b2 = mine_block(2, b1.block_hash, [], 1_718_000_051)

    # Out-of-order delivery: tip first, then the missing parent.
    bc.add_block(b2)
    bc.add_block(b1)

    assert bc.height == 2
    assert bc.tip.block_hash == b2.block_hash
    assert bc.chain[1].block_hash == b1.block_hash


def test_genuine_double_spend_within_branch_is_rejected():
    """Guard rail: the same tx in two blocks of one branch is still a real
    double-spend and must not be adopted."""
    bc = Blockchain()
    tx = signed_tx()
    bc.accept_transaction(tx)
    genesis = bc.tip

    b1 = mine_block(1, genesis.block_hash, [tx.tx_hash], 1_718_000_001)
    b2 = mine_block(2, b1.block_hash, [tx.tx_hash], 1_718_000_002)

    bc.add_block(b1)
    bc.add_block(b2)

    # b1 is fine; b2 reusing the same tx must not extend the chain.
    assert bc.height == 1
    assert bc.tip.block_hash == b1.block_hash


if __name__ == "__main__":
    BlockchainCommunity.community_id = b"\xab" * 20

    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")

    print("all tests passed")