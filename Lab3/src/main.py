"""Lab 3 PoW blockchain node.

Usage:
    python main.py --key ec_multichain.pem             # run a mining node
    python main.py --key ec_multichain.pem --register  # ... and (re)register the chain

Reads a .env file from the working directory:
    GROUP_ID        - group id from Lab 2
    PUBLIC_KEYS     - JSON list of the 3 members' IPv8 public keys (hex), e.g.
                      PUBLIC_KEYS=["4c69...", "4c69...", "4c69..."]
    LAB3_SERVER_KEY - optional; overrides the grading server key, only for
                      local testing with test_server.py

Every member runs one node with their own Lab 1 key. All 3 nodes share the same
GROUP_ID, so they all derive the same 20-byte blockchain community id.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os

from dotenv import load_dotenv
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.util import run_forever
from ipv8_service import IPv8

from src.community import BlockchainCommunity
from src.registration import SERVER_PUBLIC_KEY, RegistrationCommunity

KEY_ALIAS = "lab3 identity"


def derive_community_id(group_id: str) -> bytes:
    """Deterministic 20-byte community id every group member derives identically."""
    return hashlib.sha256(f"lab3-blockchain:{group_id}".encode("utf-8")).digest()[:20]


def build_config(key_file: str, register: bool, group_id: str, community_id: bytes,
                 member_keys: list[bytes], server_key: bytes) -> dict:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key(KEY_ALIAS, "curve25519", key_file)
    walkers = [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})]
    builder.add_overlay("BlockchainCommunity", KEY_ALIAS, walkers, default_bootstrap_defs,
                        {"member_keys": member_keys, "server_key": server_key}, [])
    if register:
        builder.add_overlay("RegistrationCommunity", KEY_ALIAS, walkers, default_bootstrap_defs,
                            {"group_id": group_id, "blockchain_community_id": community_id}, [])
    return builder.finalize()


async def main(args: argparse.Namespace) -> None:
    load_dotenv()
    group_id = os.environ["GROUP_ID"]
    member_keys = [bytes.fromhex(k) for k in json.loads(os.environ["PUBLIC_KEYS"])]
    if len(member_keys) != 3:
        raise SystemExit("PUBLIC_KEYS must list exactly 3 keys")

    server_key = SERVER_PUBLIC_KEY
    if os.environ.get("LAB3_SERVER_KEY"):
        server_key = bytes.fromhex(os.environ["LAB3_SERVER_KEY"])
        print("[main] WARNING: using LAB3_SERVER_KEY override (local testing only)")

    community_id = derive_community_id(group_id)
    BlockchainCommunity.community_id = community_id
    print(f"[main] group {group_id!r}, blockchain community id {community_id.hex()}")

    config = build_config(args.key, args.register, group_id, community_id, member_keys, server_key)
    ipv8 = IPv8(config, extra_communities={"BlockchainCommunity": BlockchainCommunity,
                                           "RegistrationCommunity": RegistrationCommunity})
    await ipv8.start()
    me = ipv8.get_overlay(BlockchainCommunity).my_peer.public_key.key_to_bin()
    print(f"[main] node started, my public key: {me.hex()}")
    if me not in member_keys:
        print("[main] WARNING: my key is not in PUBLIC_KEYS - teammates will ignore me!")

    try:
        await run_forever()
    finally:
        await ipv8.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lab 3 PoW blockchain node")
    parser.add_argument("--key", default="ec_multichain.pem",
                        help="Path to this member's Lab 1 private key (default: ec_multichain.pem)")
    parser.add_argument("--register", action="store_true",
                        help="Also (re)register the blockchain with the Lab 3 server")
    return parser.parse_args()


if __name__ == "__main__":
    asyncio.run(main(parse_args()))
