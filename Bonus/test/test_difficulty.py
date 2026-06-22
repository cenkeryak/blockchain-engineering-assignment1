"""Bonus 5: adaptive difficulty.

These tests drive the retarget controller through the four behaviours the task
asks for:

* steady when the rate is steady (no ringing),
* fast when the rate jumps (a tenfold swing tracked in a handful of blocks),
* settled without oscillation after the jump, and
* deaf to a single miner lying about timestamps.

Plus the consensus glue: median-time-past rejects backdated blocks, and the
adaptive schedule is enforced when a block is adopted.

Run with:  cd Bonus/adaptive_difficulty && pytest test/test_difficulty.py
"""

from __future__ import annotations

import math

from unittest.mock import patch

import src.blocks as blocks
from src.blocks import (
    DIFFICULTY,
    DIFFICULTY_WINDOW,
    MAX_FUTURE_TIME,
    TARGET_BLOCK_TIME,
    Block,
    Blockchain,
    block_work,
    expected_difficulty,
    genesis_block,
    make_block,
    median_time_past,
    meets_difficulty,
    timestamp_is_valid,
)

BASE_TS = 1_700_000_000
# Base hashrate whose equilibrium difficulty is exactly the bootstrap DIFFICULTY,
# so a steady network sits still from the first retarget (clean steady-state test).
H0 = (2 ** DIFFICULTY) / TARGET_BLOCK_TIME


def equilibrium_difficulty(hashrate: float) -> int:
    return round(math.log2(hashrate * TARGET_BLOCK_TIME))


def simulate(hashrate_at, n_blocks: int):
    """Build a chain where each block is produced at the *expected* time for the
    current difficulty and the hashrate in force at that height. Returns the
    chain plus the per-block difficulties and inter-block intervals.

    No real PoW is mined: the controller only reads timestamps and difficulties,
    so we can model the network's behaviour exactly and cheaply.
    """
    chain = [genesis_block()]
    difficulties: list[int] = []
    intervals: list[int] = []
    for height in range(1, n_blocks + 1):
        difficulty = expected_difficulty(chain)
        hashrate = hashrate_at(height)
        if height == 1:
            ts = BASE_TS
        else:
            solve = max(1, round(block_work(difficulty) / hashrate))
            ts = chain[-1].timestamp + solve
            intervals.append(ts - chain[-1].timestamp)
        block = make_block(height, chain[-1].block_hash, [], ts, difficulty, 0)
        chain.append(block)
        difficulties.append(difficulty)
    return chain, difficulties, intervals


# --- steady when steady -----------------------------------------------------


def test_steady_rate_holds_difficulty_constant_no_ring():
    _chain, difficulties, intervals = simulate(lambda h: H0, 60)

    # After the bootstrap window the difficulty never moves: no hunting, no ring.
    settled = difficulties[DIFFICULTY_WINDOW + 2:]
    assert set(settled) == {DIFFICULTY}
    # And the block interval sits exactly on target.
    steady_intervals = intervals[DIFFICULTY_WINDOW + 2:]
    assert set(steady_intervals) == {round(TARGET_BLOCK_TIME)}


# --- fast when it jumps, then settles ---------------------------------------


def test_tenfold_hashpower_jump_is_tracked_and_settles():
    jump_at = 20
    chain, difficulties, intervals = simulate(
        lambda h: H0 if h < jump_at else 10 * H0, 70
    )

    before = difficulties[jump_at - 2]
    target = equilibrium_difficulty(10 * H0)
    assert before == DIFFICULTY
    assert target == DIFFICULTY + 3  # log2(10) ~ 3.3 bits

    # Tracked quickly: within one window past the jump we are at the new level.
    soon = difficulties[jump_at + DIFFICULTY_WINDOW + 1]
    assert soon == target

    # Settled without oscillation: the long tail is a single value.
    tail = difficulties[-15:]
    assert set(tail) == {target}

    # Block time is back near target (not stuck fast).
    tail_intervals = intervals[-15:]
    assert all(0.4 * TARGET_BLOCK_TIME <= iv <= 1.6 * TARGET_BLOCK_TIME for iv in tail_intervals)


def test_tenfold_hashpower_drop_is_tracked_and_settles():
    drop_at = 20
    _chain, difficulties, _intervals = simulate(
        lambda h: H0 if h < drop_at else H0 / 10, 70
    )

    target = equilibrium_difficulty(H0 / 10)
    assert target == DIFFICULTY - 3
    assert difficulties[drop_at + DIFFICULTY_WINDOW + 1] == target
    assert set(difficulties[-15:]) == {target}


def test_difficulty_never_oscillates_under_steady_load_after_jump():
    """Once converged after a jump, consecutive difficulties never flap by a bit
    back and forth (the classic over/under-shoot ring)."""
    _chain, difficulties, _ = simulate(lambda h: H0 if h < 15 else 3 * H0, 80)
    tail = difficulties[-20:]
    # No alternation: every adjacent pair is equal once settled.
    assert all(a == b for a, b in zip(tail, tail[1:]))


# --- deaf to a single liar --------------------------------------------------


def test_single_timestamp_liar_does_not_move_difficulty():
    chain, _difficulties, _intervals = simulate(lambda h: H0, 40)
    honest = expected_difficulty(chain)

    # One miner lies: shove a single block's timestamp far into the future. Its
    # own interval balloons and the next one collapses, but both are clamped and,
    # crucially, the median over the window ignores the outlier.
    liar_chain = list(chain)
    victim = liar_chain[25]
    liar_chain[25] = Block(
        victim.height, victim.prev_hash, victim.txs_hash,
        victim.timestamp + 100_000,  # blatant future lie
        victim.difficulty, victim.nonce, victim.block_hash, victim.tx_hashes,
        victim.transactions,
    )

    assert expected_difficulty(liar_chain) == honest


def test_liar_cannot_drag_difficulty_across_many_recomputes():
    """Even recomputing at every height as the liar's block ages out, the lie
    never changes the retarget result."""
    chain, _d, _i = simulate(lambda h: H0, 50)
    for idx in range(DIFFICULTY_WINDOW + 2, len(chain)):
        prefix = chain[:idx]
        honest = expected_difficulty(prefix)
        lied = list(prefix)
        lied[-1] = Block(
            lied[-1].height, lied[-1].prev_hash, lied[-1].txs_hash,
            lied[-1].timestamp + 50_000, lied[-1].difficulty,
            lied[-1].nonce, lied[-1].block_hash, lied[-1].tx_hashes,
            lied[-1].transactions,
        )
        assert expected_difficulty(lied) == honest


# --- timestamp rule ---------------------------------------------------------


def test_median_time_past_rejects_backdated_block():
    chain, _d, _i = simulate(lambda h: H0, 20)
    mtp = median_time_past(chain)
    assert not timestamp_is_valid(chain, mtp)        # equal is not "strictly after"
    assert not timestamp_is_valid(chain, mtp - 5)    # backdated
    assert timestamp_is_valid(chain, mtp + 1)        # moves forward -> ok


def test_genesis_only_chain_accepts_non_future_forward_timestamp():
    chain = [genesis_block()]
    assert median_time_past(chain) == 0
    assert timestamp_is_valid(chain, 1)


def test_timestamp_rule_rejects_far_future_block():
    chain = [genesis_block()]
    with patch("src.blocks.time.time", return_value=BASE_TS):
        assert timestamp_is_valid(chain, BASE_TS + MAX_FUTURE_TIME)
        assert not timestamp_is_valid(chain, BASE_TS + MAX_FUTURE_TIME + 1)


# --- schedule enforcement on adoption ---------------------------------------


def mine_at(height, prev_hash, ts, difficulty):
    nonce = 0
    while True:
        block = make_block(height, prev_hash, [], ts, difficulty, nonce)
        if meets_difficulty(block.block_hash, difficulty):
            return block
        nonce += 1


def test_off_schedule_block_is_not_adopted_but_correct_one_is():
    # Cheap difficulty so the test mines real PoW quickly; short chain stays in
    # the bootstrap window, so the mandated difficulty is exactly this value.
    with patch.object(blocks, "DIFFICULTY", 8):
        bc = Blockchain()
        genesis = bc.tip
        assert bc.next_difficulty() == 8

        # A block declaring the wrong difficulty (too easy) must not be adopted,
        # even though its PoW is internally valid and it lands in the pool.
        wrong = mine_at(1, genesis.block_hash, BASE_TS + 10, difficulty=6)
        bc.add_block(wrong)
        assert bc.height == 0  # never extends the chain

        # The on-schedule block at the mandated difficulty is adopted.
        right = mine_at(1, genesis.block_hash, BASE_TS + 10, difficulty=8)
        bc.add_block(right)
        assert bc.height == 1
        assert bc.tip.block_hash == right.block_hash


def test_backdated_block_is_not_adopted():
    with patch.object(blocks, "DIFFICULTY", 8):
        bc = Blockchain()
        genesis = bc.tip
        first = mine_at(1, genesis.block_hash, BASE_TS + 100, difficulty=8)
        bc.add_block(first)
        assert bc.height == 1

        # A second block whose timestamp is not strictly past the median time
        # (here it equals it) must not be adopted.
        stale = mine_at(2, first.block_hash, BASE_TS + 100, difficulty=8)  # == MTP
        bc.add_block(stale)
        assert bc.height == 1


def test_future_dated_block_is_not_adopted():
    with patch.object(blocks, "DIFFICULTY", 8), patch("src.blocks.time.time", return_value=BASE_TS):
        bc = Blockchain()
        genesis = bc.tip
        future = mine_at(
            1,
            genesis.block_hash,
            BASE_TS + MAX_FUTURE_TIME + 1,
            difficulty=8,
        )

        bc.add_block(future)

        assert bc.height == 0


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all adaptive-difficulty tests passed")
