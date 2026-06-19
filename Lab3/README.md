# Design Overview

Requirements

* Python 3.12+
* Project dependencies are managed through pyproject.toml
* Optional: uv for dependency management and execution

Installation

Using standard Python tooling:

python -m venv .venv
source .venv/bin/activate
pip install -e .

Using uv:

uv sync

Running

Using standard Python tooling:

python main.py --key ec_multichain.pem

Using uv:

uv run python main.py --key ec_multichain.pem

To register the blockchain with the grading server:

python main.py --key ec_multichain.pem --register

Testing

Using standard Python tooling:

pytest

Using uv:

uv run pytest

Continuous Integration

A GitHub Actions workflow automatically executes the test suite on every push and pull request to ensure that changes do not introduce regressions.

## Architecture

The system implements a proof-of-work blockchain using IPv8 peer-to-peer communication. Three miner nodes participate in a private blockchain network and concurrently mine blocks containing transactions submitted by a trusted server.

The implementation is split into two main components:

### Blockchain

The `Blockchain` class manages all blockchain state and validation logic. It maintains:

- The active blockchain
- A mempool of pending transactions
- A block pool containing known blocks
- A set of transaction hashes already included in the active chain

The blockchain component is responsible for:

- Transaction acceptance and deduplication
- Block validation
- Fork resolution
- Chain adoption
- Reconstruction of the active chain

### Blockchain Community

The `BlockchainCommunity` class handles all network communication through IPv8. It is responsible for:

- Transaction gossip
- Block gossip
- Chain synchronization
- Missing block recovery
- Missing transaction recovery
- Mining coordination

This separation keeps blockchain state management independent from networking concerns.

## Transactions

Transactions are received from a trusted server and verified using IPv8 public-key signatures.

Before entering the mempool a transaction must:

1. Have a valid signature.
2. Not already be present in the active chain.
3. Not already exist in the mempool.

Accepted transactions are propagated to all peers using gossip messages. This allows miners to maintain similar mempool contents and mine compatible blocks.

## Blocks

A block contains:

- Height
- Previous block hash
- Transaction commitment hash
- Timestamp
- Difficulty
- Nonce
- Block hash
- Transaction hash list

Blocks are validated by checking:

1. The block hash matches the block header.
2. The proof-of-work satisfies the declared difficulty.
3. The transaction commitment matches the transaction list.
4. Referenced transactions are known and valid.
5. No duplicate transaction hashes appear within the block.

Only valid blocks are added to the block pool.

## Mining

All nodes mine concurrently.

Mining is performed on top of the current chain tip using the set of pending transactions currently present in the mempool.

To reduce duplicate work between miners, each miner begins searching from a random nonce value and then searches sequentially.

If the local chain tip changes or the mempool contents change while mining, the current mining attempt is abandoned and restarted using the updated state.

When a valid proof-of-work is found, the block is added locally and immediately propagated to peers.

## Consensus

Nodes follow a longest-chain consensus protocol.

When a block is received it is first validated and stored in the local block pool. The node then attempts to reconstruct the best chain reachable through all known blocks.

A chain is adopted when:

- It is strictly longer than the current chain, or
- It has the same height but a smaller tip block hash.

The second rule provides deterministic tie-breaking and ensures eventual convergence after temporary forks.

## Fork Handling

Blocks are not required to arrive in order.

The block pool stores blocks that are not currently part of the active chain. This includes:

- Competing fork branches
- Newly received blocks whose parents are not yet known
- Future candidates for chain adoption

When a better chain becomes available, the node reconstructs the branch from the block pool and switches to the new chain.

Double-spend protection is evaluated against the chain a branch *would* create, not the chain we are currently on. The blocks above the fork point are rolled back when we switch, so the transactions they hold are released. This lets a competing branch legitimately re-include a transaction that our current tip still carries — which is exactly what happens when two miners independently mine the same transaction into competing blocks at the same height. A transaction is only treated as a genuine double-spend if it appears twice within the prospective chain (the kept prefix plus the new branch). Without this, the two nodes would each stay stuck on their own block and never converge.

## Synchronization

Nodes periodically exchange chain height information.

If a peer advertises a chain height that exceeds the local height, the node requests the corresponding block and attempts to reconstruct the missing portion of the chain.

When a block references an unknown parent block, the missing parent height is recorded and requested from peers.

Similarly, if a block references transactions that are not present locally, the node requests the missing transaction data.

Missing blocks and transactions are retried using bounded exponential backoff. This allows the network to recover from out-of-order delivery or dropped messages while avoiding excessive request traffic.

## Testing

The implementation includes:

- Unit tests for block and transaction primitives
- Payload serialization tests
- Multi-node synchronization tests
- Chain adoption tests
- Fork recovery tests
- Competing-branch tests covering a transaction shared across forks (equal-height tie-break, longer-branch reorg, and genuine double-spend rejection)

The tests verify that lagging miners correctly synchronize with peers and eventually converge on the same active chain. Tests are visible in the github actions pipeline.

