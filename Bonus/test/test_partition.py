"""Bonus 4: fork convergence after a network partition.

These tests split the group into two halves that cannot reach each other, let
each half build its own chain, then heal the split and assert the group:

* converges on a single chain (the one with the most accumulated work),
* switches branches in one atomic step,
* loses no transaction (orphans return to the mempool),
* bounds how deep a reorg can run, and
* refuses a branch that is longer but fake — here, cheap off-schedule blocks
  rejected by the adaptive difficulty rule.

Run with:  cd Bonus && pytest test/test_partition.py
"""

from __future__ import annotations

from unittest.mock import patch

from ipv8.keyvault.crypto import default_eccrypto
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import Network
from ipv8.test.mocking.endpoint import AutoMockEndpoint

import src.blocks as blocks
import src.community as community_module
from src.blocks import (
    MAX_REORG_DEPTH,
    MIN_DIFFICULTY,
    Block,
    Blockchain,
    Transaction,
    chain_work,
    genesis_block,
    make_block,
    meets_difficulty,
)
from src.community import BlockchainCommunity, BlockchainSettings

BlockchainCommunity.community_id = b"\xab" * 20

# Cheap to mine, comfortably above the floor. Aligning the bootstrap difficulty
# with it keeps these short partition chains inside the retarget's bootstrap
# window, so the adaptive schedule check accepts them. (The retarget itself is
# exercised in test_difficulty.py.)
TEST_DIFFICULTY = 8
blocks.DIFFICULTY = TEST_DIFFICULTY


# --- helpers ----------------------------------------------------------------


def mine_block(height, prev_hash, transactions, timestamp, difficulty=TEST_DIFFICULTY):
    nonce = 0
    while True:
        block = make_block(height, prev_hash, transactions, timestamp, difficulty, nonce)
        if meets_difficulty(block.block_hash, difficulty):
            return block
        nonce += 1


def extend(chain: list[Block], count: int, *, seed: int, difficulty=TEST_DIFFICULTY) -> list[Block]:
    """Append `count` empty blocks to a copy of `chain`. `seed` keeps the two
    halves' timestamps distinct so they mine genuinely different blocks."""
    chain = list(chain)
    for i in range(count):
        prev = chain[-1]
        chain.append(
            mine_block(prev.height + 1, prev.block_hash, [], 1_718_000_000 + seed * 10_000 + i, difficulty)
        )
    return chain


def signed_tx(data: bytes) -> Transaction:
    key = default_eccrypto.generate_key("curve25519")
    sender_key = key.pub().key_to_bin()
    timestamp = 1_718_000_000
    signature = default_eccrypto.create_signature(key, sender_key + data + timestamp.to_bytes(8, "big"))
    return Transaction(sender_key, data, timestamp, signature)


def feed(bc: Blockchain, blocks_in_order: list[Block]) -> None:
    for block in blocks_in_order:
        bc.add_block(block)


# --- community-level partition harness --------------------------------------


def make_community(member_keys, private_keys, my_index) -> BlockchainCommunity:
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


def make_miners(n=3):
    private_keys = [default_eccrypto.generate_key("curve25519") for _ in range(n)]
    member_keys = [k.pub().key_to_bin() for k in private_keys]
    communities = [make_community(member_keys, private_keys, i) for i in range(n)]
    return member_keys, private_keys, communities


def peer_for(community: BlockchainCommunity) -> Peer:
    return Peer(community.my_peer.public_key, community.my_peer.address)


def install_chain(community: BlockchainCommunity, chain: list[Block]) -> None:
    community.blockchain.chain = list(chain)
    community.blockchain.chain_tx_hashes = {txh for b in chain for txh in b.tx_hashes}
    for block in chain:
        community.blockchain.block_pool[block.block_hash] = block


def sync_should_fetch(observer: BlockchainCommunity, other: BlockchainCommunity) -> bool:
    """Mirror of on_chain_height_response's decision (the handler itself is wrapped
    by lazy_wrapper and can only be invoked with raw packet bytes)."""
    tip = other.blockchain.tip
    if tip.block_hash in observer.blockchain.block_pool:
        return False
    lowest_reorg_tip = max(1, observer.blockchain.height - community_module.MAX_REORG_DEPTH)
    return other.blockchain.height >= lowest_reorg_tip


def serve_blocks_from(leader: BlockchainCommunity, follower: BlockchainCommunity, counter: list[int]):
    """Make `follower.request_block` pull straight from `leader`'s chain, counting
    how many blocks actually cross the wire."""
    leader_peer = peer_for(leader)

    def answer(height: int, peer=None) -> None:
        counter[0] += 1
        block = leader.blockchain.chain[height]
        follower.handle_block(
            leader_peer, block.height, block.prev_hash, block.txs_hash,
            block.timestamp, block.difficulty, block.nonce, b"".join(block.tx_hashes),
        )

    follower.request_block = answer  # type: ignore[method-assign]


# --- tests: pure Blockchain fork choice -------------------------------------


def test_partition_heal_converges_on_heavier_chain():
    """Two halves mine independently; on heal the lagging half adopts the
    heavier chain and both end on the exact same blocks."""
    genesis = [genesis_block()]
    big = extend(genesis, 6, seed=1)    # half A: 6 blocks past genesis
    small = extend(genesis, 3, seed=2)  # half C: 3 blocks past genesis

    a = Blockchain()
    feed(a, big[1:])
    assert a.height == 6

    c = Blockchain()
    feed(c, small[1:])
    assert c.height == 3

    # Heal: C learns A's branch (deliver tip-first to prove out-of-order works).
    feed(c, list(reversed(big[1:])))

    assert c.height == 6
    assert [b.block_hash for b in c.chain] == [b.block_hash for b in a.chain]
    assert c.reorg_count == 1
    assert c.last_reorg_depth == 3  # rolled back its own 3 blocks


def test_no_transaction_lost_across_reorg():
    """A tx confirmed only on the losing branch returns to the mempool."""
    genesis = [genesis_block()]
    tx = signed_tx(b"only on the losing branch")

    c = Blockchain()
    c.accept_transaction(tx)
    # C mines the tx into its (shorter) branch.
    c_block = mine_block(1, genesis[0].block_hash, [tx], 1_718_020_001)
    c.add_block(c_block)
    assert tx.tx_hash in c.chain_tx_hashes
    assert tx.tx_hash not in c.pending_tx_hashes()

    # A heavier branch without the tx arrives and wins.
    big = extend(genesis, 3, seed=9)
    feed(c, big[1:])

    assert c.height == 3
    assert tx.tx_hash not in c.chain_tx_hashes
    # The orphaned tx is pending again and was recorded by the reorg.
    assert tx.tx_hash in c.pending_tx_hashes()
    assert tx.tx_hash in c.last_orphaned_txs


def test_longer_but_fake_branch_is_rejected():
    """A "longer but fake" branch — cheap, off-schedule blocks — is refused.

    With adaptive difficulty the mandated difficulty here is TEST_DIFFICULTY. A
    miner that tries to manufacture a *longer* branch cheaply by declaring a
    lower difficulty has every block rejected by the schedule check, so length
    buys it nothing. Only a branch that does the mandated work can compete.
    """
    genesis = genesis_block()
    cheap = MIN_DIFFICULTY  # below the mandated TEST_DIFFICULTY (8)
    assert cheap < TEST_DIFFICULTY

    bc = Blockchain()
    honest = mine_block(1, genesis.block_hash, [], 1_718_000_001, difficulty=TEST_DIFFICULTY)
    bc.add_block(honest)
    assert bc.tip.block_hash == honest.block_hash

    # A longer branch of cheap, off-schedule blocks (each declares `cheap`, but
    # the schedule mandates TEST_DIFFICULTY at every one of these positions).
    fake1 = mine_block(1, genesis.block_hash, [], 1_718_030_001, difficulty=cheap)
    fake2 = mine_block(2, fake1.block_hash, [], 1_718_030_002, difficulty=cheap)
    fake3 = mine_block(3, fake2.block_hash, [], 1_718_030_003, difficulty=cheap)
    assert chain_work([fake1, fake2, fake3]) < chain_work([honest])

    bc.add_block(fake1)
    bc.add_block(fake2)
    bc.add_block(fake3)

    # The fake branch is longer (height 3 vs 1) yet never adopted.
    assert bc.height == 1
    assert bc.tip.block_hash == honest.block_hash


def test_fork_choice_selects_max_work_not_first_tall_candidate():
    """When several valid candidates are known, choose maximum work, not the first
    height-sorted branch that happens to beat the current chain."""
    current_ts = 1_718_000_010
    low_ts = 1_718_010_000
    high_ts = 1_718_020_000
    high_difficulty = TEST_DIFFICULTY + 4

    def variable_schedule(prefix: list[Block]) -> int:
        if len(prefix) == 1:
            return TEST_DIFFICULTY
        last = prefix[-1]
        if last.timestamp == low_ts or last.difficulty == MIN_DIFFICULTY:
            return MIN_DIFFICULTY
        if last.timestamp == high_ts:
            return high_difficulty
        return TEST_DIFFICULTY

    with patch.object(blocks, "expected_difficulty", side_effect=variable_schedule):
        bc = Blockchain()
        genesis = bc.tip

        current = mine_block(1, genesis.block_hash, [], current_ts, TEST_DIFFICULTY)
        bc.add_block(current)
        assert bc.tip.block_hash == current.block_hash

        # Candidate A is taller and still heavier than our current chain, so the
        # old height-sorted/first-acceptable implementation would switch to it.
        low1 = mine_block(1, genesis.block_hash, [], low_ts, TEST_DIFFICULTY)
        low2 = mine_block(2, low1.block_hash, [], low_ts + 1, MIN_DIFFICULTY)
        low3 = mine_block(3, low2.block_hash, [], low_ts + 2, MIN_DIFFICULTY)

        # Candidate B is shorter but much heavier under the variable schedule.
        high1 = mine_block(1, genesis.block_hash, [], high_ts, TEST_DIFFICULTY)
        high2 = mine_block(2, high1.block_hash, [], high_ts + 1, high_difficulty)

        assert low3.height > high2.height
        assert chain_work([high1, high2]) > chain_work([low1, low2, low3])

        for block in (low1, low2, low3, high1, high2):
            bc.block_pool[block.block_hash] = block

        bc.try_adopt()

        assert bc.height == 2
        assert bc.chain[1].block_hash == high1.block_hash
        assert bc.tip.block_hash == high2.block_hash


def test_sub_floor_blocks_are_not_admitted():
    """A block below the difficulty floor cannot even enter the chain, so it can
    never be spliced into a 'longer' fake branch."""
    genesis = genesis_block()
    bc = Blockchain()
    junk = mine_block(1, genesis.block_hash, [], 1_718_000_001, difficulty=MIN_DIFFICULTY - 1)
    accepted, _, _ = bc.add_block(junk)
    assert not accepted
    assert bc.height == 0


def test_reorg_depth_is_bounded():
    """A competing branch that would force a reorg deeper than MAX_REORG_DEPTH is
    refused, even though it is heavier."""
    genesis = [genesis_block()]

    # Our chain: a small depth past genesis.
    ours = extend(genesis, 3, seed=1)
    bc = Blockchain()
    feed(bc, ours[1:])
    assert bc.height == 3

    # A heavier, much longer competing branch from genesis.
    rival = extend(genesis, 5, seed=2)

    with patch.object(blocks, "MAX_REORG_DEPTH", 2):
        feed(bc, list(reversed(rival[1:])))

    # Reorg from height 3 back to genesis is depth 3 > 2 -> refused.
    assert bc.height == 3
    assert [b.block_hash for b in bc.chain] == [b.block_hash for b in ours]
    assert bc.reorg_count == 0


# --- tests: community-level partition + heal --------------------------------


def test_community_partition_and_heal_only_fetches_differing_blocks():
    _keys, _priv, (a, b, c) = make_miners(3)

    # Partition: {A, B} on one side, {C} on the other.
    a.set_partition({c.my_peer.public_key.key_to_bin()})
    b.set_partition({c.my_peer.public_key.key_to_bin()})
    c.set_partition({a.my_peer.public_key.key_to_bin(), b.my_peer.public_key.key_to_bin()})

    assert not a.is_member(peer_for(c))
    assert not c.is_member(peer_for(a))

    genesis = [genesis_block()]
    big = extend(genesis, 8, seed=1)    # group {A,B}
    small = extend(genesis, 3, seed=2)  # lone C

    install_chain(a, big)
    install_chain(b, big)
    install_chain(c, small)

    # Heal the split.
    for node in (a, b, c):
        node.heal_partition()
    assert c.is_member(peer_for(a))

    # On heal, C's tip poll sees A's unseen tip and pulls it; that kicks off a
    # parent-by-parent walk to the fork. A would also inspect C's shorter unseen
    # tip because shorter branches can be heavier under adaptive difficulty, but
    # it will not switch to C's lower-work branch.
    assert sync_should_fetch(c, a)  # C is behind -> fetch
    assert sync_should_fetch(a, c)  # shorter-but-possible fork -> inspect

    served = [0]
    serve_blocks_from(a, c, served)
    c.request_block(a.blockchain.height, peer_for(a))

    assert c.blockchain.height == 8
    assert [bl.block_hash for bl in c.blockchain.chain] == [bl.block_hash for bl in a.blockchain.chain]
    assert c.blockchain.reorg_count == 1
    # Only the 8 blocks above the genesis fork differ; we fetch exactly those,
    # not C's own 3 blocks and not the shared genesis.
    assert served[0] == 8
    # The taller group never moved.
    assert a.blockchain.height == 8


def test_partition_then_heal_full_three_way_consistency():
    """End to end: all three nodes agree on every block after the heal."""
    _keys, _priv, (a, b, c) = make_miners(3)

    genesis = [genesis_block()]
    big = extend(genesis, 7, seed=3)
    small = extend(genesis, 4, seed=4)
    install_chain(a, big)
    install_chain(b, big)
    install_chain(c, small)

    served = [0]
    serve_blocks_from(a, c, served)
    c.request_block(a.blockchain.height, peer_for(a))

    for height in range(a.blockchain.height + 1):
        hashes = {node.blockchain.chain[height].block_hash for node in (a, b, c)}
        assert len(hashes) == 1, f"nodes disagree at height {height}"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all partition tests passed")
