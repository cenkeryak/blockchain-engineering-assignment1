from src.blockchain import Blockchain, Transaction


def test_blockchain_starts_with_genesis():
    bc = Blockchain(difficulty=8)

    assert bc.height == 0
    assert len(bc.chain) == 1
    bc.validate()


def test_add_transaction_to_mempool():
    bc = Blockchain(difficulty=8)

    tx = Transaction(
        sender_key=b"sender",
        data=b"hello",
        timestamp=123,
        signature=b"sig",
    )

    txh = bc.add_transaction(tx)

    assert len(bc.mempool) == 1
    assert txh == tx.hash


def test_mine_block_includes_transaction_and_clears_mempool():
    bc = Blockchain(difficulty=8)

    tx = Transaction(
        sender_key=b"sender",
        data=b"hello",
        timestamp=123,
        signature=b"sig",
    )

    txh = bc.add_transaction(tx)
    block = bc.mine_next_block()

    assert bc.height == 1
    assert block.height == 1
    assert block.header.prev_hash == bc.chain[0].block_hash
    assert block.tx_hashes == [txh]
    assert bc.mempool == []

    bc.validate()


def test_mine_empty_block():
    bc = Blockchain(difficulty=8)

    block = bc.mine_next_block()

    assert bc.height == 1
    assert block.tx_hashes == []
    assert bc.mempool == []

    bc.validate()


def test_multiple_blocks_link_correctly():
    bc = Blockchain(difficulty=8)

    b1 = bc.mine_next_block()
    b2 = bc.mine_next_block()
    b3 = bc.mine_next_block()

    assert bc.height == 3
    assert b2.header.prev_hash == b1.block_hash
    assert b3.header.prev_hash == b2.block_hash

    bc.validate()