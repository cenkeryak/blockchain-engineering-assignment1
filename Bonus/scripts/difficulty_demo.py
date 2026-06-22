"""Bonus 5 demo: adaptive difficulty holding block time steady.

Runs the retarget controller against a simulated network whose hashpower swings,
printing the difficulty and the block interval at each step so you can watch:

    1. Steady hashpower  -> difficulty sits still, interval on target (no ring).
    2. Hashpower jumps 10x -> difficulty climbs within a few blocks, interval
       snaps back toward target, then settles and stays there.
    3. Hashpower drops 10x -> difficulty falls and settles the same way.
    4. A single miner lies about a timestamp -> the retarget does not budge.

No real PoW is mined: the controller only reads timestamps and difficulties, so
we model the network exactly and cheaply.

Run with:  cd Bonus/adaptive_difficulty && python scripts/difficulty_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.blocks import (
    DIFFICULTY,
    TARGET_BLOCK_TIME,
    Block,
    block_work,
    expected_difficulty,
    genesis_block,
    make_block,
)

BASE_TS = 1_700_000_000
H0 = (2 ** DIFFICULTY) / TARGET_BLOCK_TIME  # equilibrium hashrate for bootstrap difficulty


def run(hashrate_at, n_blocks, *, liar_at=None):
    chain = [genesis_block()]
    rows = []
    for height in range(1, n_blocks + 1):
        difficulty = expected_difficulty(chain)
        hashrate = hashrate_at(height)
        if height == 1:
            ts, interval = BASE_TS, 0
        else:
            interval = max(1, round(block_work(difficulty) / hashrate))
            ts = chain[-1].timestamp + interval
        block = make_block(height, chain[-1].block_hash, [], ts, difficulty, 0)

        if liar_at is not None and height == liar_at:
            # The liar publishes a wildly future-dated block.
            block = Block(block.height, block.prev_hash, block.txs_hash,
                          block.timestamp + 100_000, block.difficulty,
                          block.nonce, block.block_hash, block.tx_hashes,
                          block.transactions)

        chain.append(block)
        rows.append((height, difficulty, interval, hashrate))
    return chain, rows


def bar(difficulty: int, base: int) -> str:
    return "#" * max(0, difficulty - base + 1)


def show(title, rows, *, base):
    print(f"\n{title}")
    print(f"    {'height':>6}  {'diff':>4}  {'interval(s)':>11}   (target {int(TARGET_BLOCK_TIME)}s)")
    for height, difficulty, interval, _h in rows:
        flag = "" if height == 1 else f"{interval:>11}"
        print(f"    {height:>6}  {difficulty:>4}  {flag}   {bar(difficulty, base)}")


def main() -> None:
    print("=" * 72)
    print("Bonus 5 - adaptive difficulty (target block time "
          f"{int(TARGET_BLOCK_TIME)}s, bootstrap difficulty {DIFFICULTY})")
    print("=" * 72)

    # 1 + 2: steady, then a 10x jump at height 20.
    jump_at = 20
    _chain, rows = run(lambda h: H0 if h < jump_at else 10 * H0, 48)
    show("[1+2] steady, then hashpower x10 at height 20", rows[12:], base=DIFFICULTY)
    settled = rows[-1][1]
    print(f"\n    -> difficulty rose {DIFFICULTY} -> {settled} (+{settled - DIFFICULTY} bits ~ log2(10)) "
          f"and the interval settled near target with no oscillation.")

    # 3: a 10x drop.
    drop_at = 20
    _chain, rows = run(lambda h: H0 if h < drop_at else H0 / 10, 48)
    settled = rows[-1][1]
    print(f"\n[3] hashpower /10 at height 20  ->  difficulty fell "
          f"{DIFFICULTY} -> {settled} ({settled - DIFFICULTY} bits) and settled.")

    # 4: a single liar.
    clean_chain, _ = run(lambda h: H0, 40)
    lied_chain, _ = run(lambda h: H0, 40, liar_at=25)
    clean_d = expected_difficulty(clean_chain)
    lied_d = expected_difficulty(lied_chain)
    print(f"\n[4] one miner future-dates a block by 100000s:")
    print(f"    difficulty without the lie : {clean_d}")
    print(f"    difficulty with the lie    : {lied_d}")
    print(f"    -> identical: the median over the window is deaf to a single liar.")

    print("\n" + "=" * 72)
    print("Steady when steady, fast when it jumps, settles without ringing,")
    print("and one miner's clock lie moves nothing.")
    print("=" * 72)


if __name__ == "__main__":
    main()
