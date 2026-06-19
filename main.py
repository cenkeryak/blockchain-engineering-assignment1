import argparse
import asyncio
from enum import Enum, auto
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8_service import IPv8
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.peer import Peer
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.keyvault.crypto import default_eccrypto
from dataclasses import dataclass
import os
import json
from dotenv import load_dotenv

KEY_FILE = None

COMMUNITY_ID = bytes.fromhex(
    "4c61623247726f75705369676e696e6732303236"
)

SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
)

load_dotenv()

PUBLIC_KEYS = [bytes.fromhex(k) for k in json.loads(os.getenv("PUBLIC_KEYS"))]


class State(Enum):
    FIND_PEERS = auto()
    READY = auto()
    REGISTER = auto()
    BEGIN_CHALLENGE = auto()
    BEGIN_ROUND = auto()
    ROUND = auto()
    SUCCESS = auto()



@dataclass
class RegisterPayload(DataClassPayload[1]):
    member_key1: bytes
    member_key2: bytes
    member_key3: bytes

@dataclass
class RegisterResponsePayload(DataClassPayload[2]):
    success: bool
    group_id: str
    message: str

@dataclass
class ChallengeRequestPayload(DataClassPayload[3]):
    group_id: str

@dataclass
class ChallengeResponsePayload(DataClassPayload[4]):
    nonce: bytes
    round_number: int
    deadline: float

@dataclass
class SubmissionPayload(DataClassPayload[5]):
    group_id: str
    round_number: int
    sig1: bytes
    sig2: bytes
    sig3: bytes

@dataclass
class InternalSubmissionPayload(DataClassPayload[7]):
    nonce: bytes
    payload: SubmissionPayload
                                
@dataclass
class SubmissionResponsePayload(DataClassPayload[6]):
    success: bool
    round_number: int
    rounds_completed: int
    message: str

@dataclass
class ReadyPayload(DataClassPayload[8]):
    pass

RegisterResponsePayload(False, None, None)
ChallengeResponsePayload(None, None, None)
SubmissionPayload(None, None, None, None, None)
SubmissionResponsePayload(False, None, None, None)
InternalSubmissionPayload(None, None)

class HetCommunity(Community):
    community_id = COMMUNITY_ID


    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        if not hasattr(settings, "node_id"):
            msg = "HetCommunity overlay initialize must include node_id"
            raise ValueError(msg)
        self.node_id: int = settings.node_id  # type: ignore[attr-defined]
        self.done = False
        
        self.boss = None
        self.peers = {}

        self.readies = set()
        
        self.group_id = None
        self.state = State.FIND_PEERS
        self.curr_challenge = None
        self.begun_round = 0
        self.submitted = 0
        self.sigs = {
            0: b"",
            1: b"",
            2: b"",
        }
        
        self.add_message_handler(ReadyPayload, self.ready)
        self.add_message_handler(RegisterResponsePayload, self.register_response)
        self.add_message_handler(ChallengeResponsePayload, self.challenge_response)
        self.add_message_handler(InternalSubmissionPayload, self.submission_payload)
        self.add_message_handler(SubmissionResponsePayload, self.submission_response)

    def find_peers(self) -> bool:
        print(f"Searching for peers...")
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                self.boss = peer
            if peer.public_key.key_to_bin() in PUBLIC_KEYS:
                self.peers[PUBLIC_KEYS.index(peer.public_key.key_to_bin())] = peer
        
        return len(self.peers.keys()) == 2 and self.boss
    
    def register_group(self) -> bool:
        self.ez_send(self.boss, RegisterPayload(PUBLIC_KEYS[0], PUBLIC_KEYS[1], PUBLIC_KEYS[2]))


    @lazy_wrapper(ReadyPayload)
    def ready(self, peer: Peer, payload: ReadyPayload) -> bool:
        self.readies.add(peer.public_key.key_to_bin())

    def send_ready(self) -> bool:
        for peer in self.peers.values():
            self.ez_send(peer, ReadyPayload())

    @lazy_wrapper(RegisterResponsePayload)
    def register_response(self, peer: Peer, payload: RegisterResponsePayload) -> bool:
        if payload.success:
            self.group_id = payload.group_id
            self.state = State.READY
            return True
    
    def begin_challenge(self) -> bool:
        self.ez_send(self.boss, ChallengeRequestPayload(self.group_id))
    
    @lazy_wrapper(ChallengeResponsePayload)
    def challenge_response(self, peer: Peer, payload: ChallengeResponsePayload) -> bool:
        if self.curr_challenge is not None and payload.round_number <= self.curr_challenge.round_number and self.begun_round == payload.round_number:
            if not self.state == State.SUCCESS:
                self.state = State.ROUND
            return True
        self.curr_challenge = payload
        self.sigs = {
            0: b"",
            1: b"",
            2: b"",
        }
        if not self.state == State.SUCCESS:
            self.state = State.BEGIN_ROUND
        return True
    
    def begin_round(self) -> bool:
        with open(KEY_FILE, "rb") as f:
            pem_bytes = f.read()
        
        key = default_eccrypto.key_from_private_bin(pem_bytes)
        signature = default_eccrypto.create_signature(key, self.curr_challenge.nonce)
        
        self.sigs = {
            0: b"",
            1: b"",
            2: b"",
        }

        self.sigs[self.node_id] = signature
        message = InternalSubmissionPayload(nonce=self.curr_challenge.nonce, 
                                            payload=SubmissionPayload(self.group_id, self.curr_challenge.round_number, *self.sigs.values()))
        
        
        for _, peer in self.peers.items():
            self.ez_send(peer, message)
        
        self.begun_round = self.curr_challenge.round_number
        self.state = State.ROUND

    @lazy_wrapper(InternalSubmissionPayload)
    def submission_payload(self, peer: Peer, payload: InternalSubmissionPayload) -> bool:
        # if len(payload_sigs[self.node_id]) > 0 or self.curr_challenge is not None and payload.payload.round_number < self.curr_challenge.round_number:
        if self.curr_challenge is not None and payload.payload.round_number < self.curr_challenge.round_number:
            return
        
        payload_sigs = {
            0: payload.payload.sig1,
            1: payload.payload.sig2,
            2: payload.payload.sig3
        }

        if self.curr_challenge is None or payload.payload.round_number > self.curr_challenge.round_number:
            self.sigs = payload_sigs
            self.curr_challenge = ChallengeResponsePayload(payload.nonce, payload.payload.round_number, None)
            if self.state != State.SUCCESS:
                self.state = State.ROUND
        else:
            self.sigs = {
                0: payload.payload.sig1 if len(payload.payload.sig1) > 0 else self.sigs[0],
                1: payload.payload.sig2 if len(payload.payload.sig2) > 0 else self.sigs[1],
                2: payload.payload.sig3 if len(payload.payload.sig3) > 0 else self.sigs[2]
            }

        with open(KEY_FILE, "rb") as f:
            pem_bytes = f.read()
        key = default_eccrypto.key_from_private_bin(pem_bytes)
        signature = default_eccrypto.create_signature(key, payload.nonce)
        self.sigs[self.node_id] = signature

        message = SubmissionPayload(self.group_id, payload.payload.round_number, *self.sigs.values())

        if all(len(sig) > 0 for sig in self.sigs.values()):
            if not self.state == State.SUCCESS and self.submitted < payload.payload.round_number:
                print(f"Sending to boss: {message}")
                self.ez_send(self.boss, message)
                self.submitted = payload.payload.round_number
        else:
            for _, peer in self.peers.items():
                self.ez_send(peer, InternalSubmissionPayload(nonce=payload.nonce, payload=message))
        
    @lazy_wrapper(SubmissionResponsePayload)
    def submission_response(self, peer: Peer, payload: SubmissionResponsePayload):
        print(f"Submission response: {payload.message}")
        if payload.success:
            self.state = State.SUCCESS
        elif self.state != State.SUCCESS:
            self.state = State.BEGIN_CHALLENGE
            


async def start_ipv8(node_id: int) -> None:
    builder = ConfigBuilder()
    builder.clear_keys()
    builder.clear_overlays()

    builder.add_key(
        "hetpeer",
        "curve25519",
        KEY_FILE
    )

    builder.add_overlay("HetCommunity", "hetpeer",
                            [WalkerDefinition(Strategy.RandomWalk,
                                              10, {"timeout": 3.0})],
                            default_bootstrap_defs, {"node_id": node_id}, [])

    ipv8 = IPv8(builder.finalize(),
                   extra_communities={"HetCommunity": HetCommunity})
    await ipv8.start()

    community = ipv8.get_overlay(HetCommunity)

    print("IPv8 started, searching for peer")
    try:
        print(f"Starting main loop...")
        while not community.done:
            print(f"Current state: {community.state}")
            match community.state:    
                case State.FIND_PEERS:
                    if community.find_peers():
                        community.state = State.REGISTER
                    else:
                        await asyncio.sleep(0.2)
                case State.REGISTER:
                    community.register_group()
                case State.READY:
                    community.send_ready()
                    if len(community.readies) == 2:
                        community.state = State.BEGIN_CHALLENGE
                    else:
                        await asyncio.sleep(0.01)
                case State.BEGIN_CHALLENGE:
                    print("begin challenge")
                    community.begin_challenge()
                case State.BEGIN_ROUND:
                    community.begin_round()
                    # await asyncio.sleep(0.2)
                    # community.state = State.BEGIN_CHALLENGE
                case State.ROUND:
                    community.begin_challenge()
                    pass
                case State.SUCCESS:
                    print("Success state")
                    await asyncio.sleep(10)
            
            await asyncio.sleep(0.001)
            
        
        # await community.done.wait()


    finally:
        await ipv8.stop()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IPv8 PoW signing client")
    parser.add_argument(
        "--node-id",
        type=int,
        required=True,
        choices=(0, 1, 2),
        help="This peer's index in the group (matches sig slot and PUBLIC_KEYS order)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    _args = _parse_args()
    KEY_FILE = f"lab1_key_{_args.node_id}.pem"
    asyncio.run(start_ipv8(_args.node_id))