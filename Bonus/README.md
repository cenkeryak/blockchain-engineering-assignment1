# Bonus implementation

This folder contains our bonus version of the Lab 3 blockchain node.

The normal assignment code is still kept in the main project files. The `Bonus/`
folder is a separate copy where we added two bonus tasks:

* Bonus 4: fork convergence after a partition
* Bonus 5: adaptive difficulty

The important point is that this is not just extra demo code. The bonus version
changes the actual consensus logic of the node. In the base version, a node mostly
follows the longest chain. In this bonus version, that rule is replaced with a
stronger rule: the node follows the chain with the most accumulated proof-of-work.
That matters because, after adaptive difficulty is added, a shorter chain can
sometimes have more real work than a longer chain.

Most of the implementation is in:

* `src/blocks.py`: block validation, fork choice, reorgs, adaptive difficulty
* `src/community.py`: mining, sync between the three nodes, partition simulation

## What changed from the base version

The base implementation already has blocks, transactions, mining, gossip, and
basic chain adoption. The bonus version keeps that structure, but changes a few
core parts:

* Chain choice is no longer "longest chain wins".
* A branch is chosen by total proof-of-work instead of height.
* Reorgs are allowed, but only up to a fixed maximum depth.
* If a reorg removes blocks from the old chain, transactions from those old blocks
  are not lost. They become pending again in the mempool.
* Difficulty is no longer fixed forever. The next block difficulty is calculated
  from recent block times.
* Blocks must use the expected difficulty for their position in the chain.
* Bad timestamps are limited. A block cannot go backwards according to
  median-time-past, and it also cannot be far in the future.

## Bonus 4: fork convergence after a partition

The task asks us to split the three nodes into two groups, let both sides keep
mining, then reconnect them. When the network heals, all nodes should quickly
agree on the correct branch.

We implemented this in a few steps.

First, nodes can simulate a partition. A partitioned peer is treated like a
non-member peer: we ignore its packets and do not send gossip to it. This is done
at the IPv8 overlay level, so it does not physically block UDP traffic, but it is
enough to test the blockchain behavior during a split.

Second, when the network heals, nodes compare branches by work, not by length.
Each block contributes work based on its difficulty. The node checks every valid
candidate branch it knows about and switches to the branch with the highest total
work. If two branches have the same work, a deterministic tie-break using the tip
hash is used so all nodes make the same choice.

Third, the node fetches only the blocks it needs. When it hears about an unknown
tip from a teammate, it requests that block and then walks backwards through the
parents until it reaches a block it already knows. This means it only downloads
the different part of the branch, not the whole chain again.

Fourth, the chain switch is done in one step. The old branch is replaced with the
new branch, and transactions from orphaned blocks are returned to the mempool if
they were not included in the new branch. This is how we avoid losing
transactions during a reorg.

Finally, reorg depth is bounded with `MAX_REORG_DEPTH`. This prevents one peer
from making us rewrite very old history.

This also protects against a fake "longer" branch. A peer cannot just create many
cheap blocks and win by height, because the node checks both total work and the
expected difficulty schedule.

## Bonus 5: adaptive difficulty

The base version mines at a fixed difficulty. That works for a small demo, but it
does not react when hashpower changes. If miners become ten times faster, blocks
arrive too quickly. If miners become slower, blocks arrive too slowly.

In the bonus version, the next block difficulty is calculated by
`expected_difficulty(chain)`.

The idea is simple:

* Look at recent blocks.
* Estimate how much hashpower was needed to produce them.
* Use the median estimate, so one strange timestamp does not control the result.
* Pick the difficulty that should bring the block time back toward the target.

The difficulty rule is part of consensus. When a node receives a block, it checks
whether that block uses the difficulty that was expected at that exact height. If
the block declares an easier difficulty than it should, the branch is not adopted.

We also added timestamp checks. A block must be newer than the median time of
recent blocks, which stops simple backdating attacks. A block is also rejected if
its timestamp is more than `MAX_FUTURE_TIME` seconds ahead of local time. This
keeps one miner's clock from pushing the difficulty calculation around too much.

## How to run

From inside the `Bonus/` folder:

```bash
python scripts/partition_demo.py
python scripts/difficulty_demo.py
pytest
```

The partition demo shows the split, separate mining, healing, and convergence.
The difficulty demo shows steady mining, a 10x hashpower increase, a 10x decrease,
and timestamp-liar behavior.

## Tests

The tests cover both the original behavior and the bonus behavior:

| File | What it checks |
|---|---|
| `test/test_chain.py` | basic block, transaction, hash, and payload behavior |
| `test/test_blockchain.py` | multi-miner adoption, sync, retries, and competing branches |
| `test/test_partition.py` | fork convergence, work-based fork choice, bounded reorgs, no lost transactions, fake longer branch rejection |
| `test/test_difficulty.py` | adaptive difficulty, 10x hashpower changes, no oscillation, timestamp liar resistance, invalid difficulty rejection |

The full Bonus test suite currently passes with 43 tests.

## Main constants

| Constant | Meaning |
|---|---|
| `TARGET_BLOCK_TIME` | wanted time between blocks |
| `DIFFICULTY` | starting difficulty before there is enough history |
| `DIFFICULTY_WINDOW` | how many recent blocks are used for retargeting |
| `SOLVE_CLAMP_LOW` / `SOLVE_CLAMP_HIGH` | limits for one block-time sample |
| `MEDIAN_TIME_BLOCKS` | window used for median-time-past |
| `MAX_FUTURE_TIME` | how far into the future a block timestamp may be |
| `MIN_DIFFICULTY` / `MAX_DIFFICULTY` | lower and upper bounds for difficulty |
| `MAX_REORG_DEPTH` | deepest reorg the node will accept |
