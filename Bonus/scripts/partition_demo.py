"""Bonus 4 demo: fork convergence after a network partition.

Runs the whole partition story in one process so you can watch it without
spinning up three machines:

    1. Three nodes share a genesis block.
    2. The network splits: {A, B} on one side, {C} on the other. Neither side
       can hear the other.
    3. Both sides keep mining. They drift onto different chains. A transaction
       lands only on C's (losing) side.
    4. The split heals. The lagging side fetches only the blocks that differ,
       switches to the heavier chain in one atomic step, and puts the orphaned
       transaction back in its mempool.
    5. For good measure, a peer offers a chain that is *longer* but built from
       cheap, low-work blocks. It is rejected: work wins, not length.

Run with:  cd Bonus && python scripts/partition_demo.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ipv8.keyvault.crypto import default_eccrypto

import src.blocks as blocks
from src.blocks import (
    MIN_DIFFICULTY,
    Blockchain,
    Transaction,
    chain_work,
    genesis_block,
    make_block,
    meets_difficulty,
)

DIFF = 8  # cheap to mine for a live demo, comfortably above the floor
# Align the bootstrap difficulty with the demo blocks so the (now enforced)
# adaptive schedule accepts these short chains.
blocks.DIFFICULTY = DIFF


def mine(height, prev_hash, transactions, ts, difficulty=DIFF):
    nonce = 0
    while True:
        block = make_block(height, prev_hash, transactions, ts, difficulty, nonce)
        if meets_difficulty(block.block_hash, difficulty):
            return block
        nonce += 1


def mine_run(start_block, count, *, seed, tx_at=None, tx=None, difficulty=DIFF):
    """Mine `count` blocks on top of start_block. Optionally embed `tx` in the
    block at index `tx_at`."""
    out = []
    prev = start_block
    for i in range(count):
        txs = [tx] if (tx_at is not None and i == tx_at and tx is not None) else []
        block = mine(prev.height + 1, prev.block_hash, txs, 1_700_000_000 + seed * 10_000 + i, difficulty)
        out.append(block)
        prev = block
    return out


def signed_tx(data: bytes) -> Transaction:
    key = default_eccrypto.generate_key("curve25519")
    sender = key.pub().key_to_bin()
    ts = 1_700_000_000
    sig = default_eccrypto.create_signature(key, sender + data + ts.to_bytes(8, "big"))
    return Transaction(sender, data, ts, sig)


def tips_agree(*chains) -> bool:
    tips = {c.tip.block_hash for c in chains}
    return len(tips) == 1


def show(label, *nodes):
    for name, bc in nodes:
        print(f"    {name}: height {bc.height:>2}  work {bc.total_work:>8}  tip {bc.tip.block_hash.hex()[:12]}")


def main() -> None:
    print("=" * 70)
    print("Bonus 4 - fork convergence after a partition")
    print("=" * 70)

    # 1. Shared genesis on all three nodes.
    g = genesis_block()
    a, b, c = Blockchain(), Blockchain(), Blockchain()
    print(f"\n[1] Genesis shared by A, B, C: {g.block_hash.hex()[:12]}")

    # A transaction that the {A,B} side never hears about during the split.
    tx = signed_tx(b"payment that gets orphaned")
    c.accept_transaction(tx)

    # 2 + 3. Partition. Each side mines its own run.
    print("\n[2] PARTITION: {A,B}  |  {C}   (the two sides cannot reach each other)")
    big = mine_run(g, 6, seed=1)                       # {A, B}: 6 blocks
    small = mine_run(g, 3, seed=2, tx_at=1, tx=tx)  # {C}: 3 blocks, tx in block 2

    for blk in big:
        a.add_block(blk)
        b.add_block(blk)
    for blk in small:
        c.add_block(blk)

    print("\n[3] Both sides mined independently and drifted apart:")
    show("after split", ("A", a), ("B", b), ("C", c))
    print(f"    tx {tx.tx_hash.hex()[:12]} is confirmed ONLY on C's branch "
          f"(in chain: {tx.tx_hash in c.chain_tx_hashes})")
    assert not tips_agree(a, c)

    # 4. Heal. C fetches the heavier chain and reorganises.
    print("\n[4] HEAL: C learns A's branch. Switching to the heavier chain...")
    t0 = time.perf_counter()
    # Deliver tip-first to prove out-of-order arrival still converges.
    for blk in reversed(big):
        c.add_block(blk)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    show("after heal", ("A", a), ("B", b), ("C", c))
    print(f"    converged in {elapsed_ms:.1f} ms   reorgs={c.reorg_count} "
          f"depth={c.last_reorg_depth} orphaned_txs={len(c.last_orphaned_txs)}")
    assert tips_agree(a, b, c), "nodes failed to converge"
    assert tx.tx_hash not in c.chain_tx_hashes, "tx should have been orphaned"
    assert tx.tx_hash in c.pending_tx_hashes(), "orphaned tx must return to the mempool"
    print(f"    no node lost, no tx lost: orphaned tx {tx.tx_hash.hex()[:12]} is "
          f"pending again (mineable): {tx.tx_hash in c.pending_tx_hashes()}")

    # 5. A longer-but-fake branch is offered and rejected.
    print("\n[5] ATTACK: a peer offers a LONGER branch built from cheap off-schedule blocks.")
    cheaper = MIN_DIFFICULTY  # below the mandated DIFF
    fake = mine_run(genesis_block(), len(big) + 4, seed=99, difficulty=cheaper)

    victim = Blockchain()
    for blk in big:
        victim.add_block(blk)            # honest chain
    before, before_height = victim.tip.block_hash, victim.height
    for blk in fake:                     # attacker's longer, cheaper branch
        victim.add_block(blk)

    print(f"    honest chain  : height {before_height}, every block at difficulty {DIFF}")
    print(f"    fake branch   : height {len(fake)}, every block at difficulty {cheaper} "
          f"(work {chain_work(fake)} vs honest {victim.total_work})")
    print(f"    victim tip unchanged : {victim.tip.block_hash == before}  "
          f"(off-schedule cheap blocks rejected, despite being longer)")
    assert victim.tip.block_hash == before, "victim must not follow the fake longer branch"
    assert victim.height == before_height

    print("\n" + "=" * 70)
    print("All invariants held: converged fast, lost no node, lost no tx,")
    print("bounded the reorg, and rejected the longer-but-fake branch.")
    print("=" * 70)


if __name__ == "__main__":
    main()
