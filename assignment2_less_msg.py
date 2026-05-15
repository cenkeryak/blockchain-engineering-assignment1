import argparse
import asyncio
import json
import os
import time
from dataclasses import dataclass
from enum import Enum, auto

from dotenv import load_dotenv
from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.peer import Peer
from ipv8_service import IPv8

KEY_FILE: str | None = None

GROUP_SIZE = 3
ROUNDS = 3

REGISTER_RETRY_SECONDS = 1.0
READY_RETRY_SECONDS = 0.5
CHALLENGE_RETRY_SECONDS = 0.25
SIGNATURE_RETRY_SECONDS = 0.25
SUBMISSION_RETRY_SECONDS = 0.75
ROUND_BROADCAST_RETRY_SECONDS = 0.5
SHUTDOWN_GRACE_SECONDS = 1.0

COMMUNITY_ID = bytes.fromhex(
    "4c61623247726f75705369676e696e6732303236"
)

SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
)

load_dotenv()

PUBLIC_KEYS = [bytes.fromhex(k) for k in json.loads(os.getenv("PUBLIC_KEYS"))]
if len(PUBLIC_KEYS) != GROUP_SIZE:
    raise ValueError(f"PUBLIC_KEYS must contain exactly {GROUP_SIZE} keys")


class State(Enum):
    FIND_PEERS = auto()
    REGISTER = auto()
    READY = auto()
    RUNNING = auto()
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
class SubmissionResponsePayload(DataClassPayload[6]):
    success: bool
    round_number: int
    rounds_completed: int
    message: str


@dataclass
class InternalSubmissionPayload(DataClassPayload[7]):
    nonce: bytes
    payload: SubmissionPayload


@dataclass
class ReadyPayload(DataClassPayload[8]):
    pass


@dataclass
class InternalRoundDonePayload(DataClassPayload[9]):
    round_number: int
    rounds_completed: int
    message: str


# Touch payload classes once so IPv8's dataclass serializer sees nested payloads eagerly.
RegisterResponsePayload(False, "", "")
ChallengeResponsePayload(b"", 0, 0.0)
SubmissionPayload("", 0, b"", b"", b"")
SubmissionResponsePayload(False, 0, 0, "")
InternalSubmissionPayload(b"", SubmissionPayload("", 0, b"", b"", b""))
InternalRoundDonePayload(0, 0, "")


class HetCommunity(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        if not hasattr(settings, "node_id"):
            msg = "HetCommunity overlay initialize must include node_id"
            raise ValueError(msg)
        if KEY_FILE is None:
            raise ValueError("KEY_FILE must be set before HetCommunity starts")

        self.node_id: int = settings.node_id  # type: ignore[attr-defined]
        self.done = False
        self.state = State.FIND_PEERS

        self.boss: Peer | None = None
        self.peers: dict[int, Peer] = {}
        self.readies: set[int] = set()
        self.group_id: str | None = None

        with open(KEY_FILE, "rb") as f:
            self.private_key = default_eccrypto.key_from_private_bin(f.read())

        self.nonces: dict[int, bytes] = {}
        self.signatures: dict[int, dict[int, bytes]] = {}
        self.submitted_rounds: set[int] = set()
        self.rounds_completed = 0
        self.challenge_driver_round: int | None = None

        self.last_register_at = 0.0
        self.last_ready_at = 0.0
        self.last_challenge_request_at = 0.0
        self.last_signature_share_at: dict[int, float] = {}
        self.last_submission_at: dict[int, float] = {}
        self.last_round_broadcast_at: dict[int, float] = {}
        self.stop_at: float | None = None

        self.add_message_handler(ReadyPayload, self.ready)
        self.add_message_handler(RegisterResponsePayload, self.register_response)
        self.add_message_handler(ChallengeResponsePayload, self.challenge_response)
        self.add_message_handler(InternalSubmissionPayload, self.submission_payload)
        self.add_message_handler(SubmissionResponsePayload, self.submission_response)
        self.add_message_handler(InternalRoundDonePayload, self.internal_round_done)

    def _node_id_for_key(self, public_key: bytes) -> int | None:
        try:
            return PUBLIC_KEYS.index(public_key)
        except ValueError:
            return None

    def _node_id_for_peer(self, peer: Peer) -> int | None:
        return self._node_id_for_key(peer.public_key.key_to_bin())

    def _is_server(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY

    def _is_submitter(self, round_number: int) -> bool:
        return self.node_id == self._submitter_for_round(round_number)

    def _submitter_for_round(self, round_number: int) -> int:
        return round_number - 1

    def _valid_round(self, round_number: int) -> bool:
        return 1 <= round_number <= ROUNDS

    def find_peers(self) -> bool:
        for peer in self.get_peers():
            public_key = peer.public_key.key_to_bin()
            if public_key == SERVER_PUBLIC_KEY:
                self.boss = peer
                continue

            peer_id = self._node_id_for_key(public_key)
            if peer_id is not None and peer_id != self.node_id:
                self.peers[peer_id] = peer

        return len(self.peers) == GROUP_SIZE - 1 and self.boss is not None

    def register_group(self, *, force: bool = False) -> None:
        if self.boss is None:
            return

        now = time.monotonic()
        if not force and now - self.last_register_at < REGISTER_RETRY_SECONDS:
            return

        print("Registering group")
        self.ez_send(self.boss, RegisterPayload(PUBLIC_KEYS[0], PUBLIC_KEYS[1], PUBLIC_KEYS[2]))
        self.last_register_at = now

    @lazy_wrapper(RegisterResponsePayload)
    def register_response(self, peer: Peer, payload: RegisterResponsePayload) -> None:
        if not self._is_server(peer):
            return

        print(f"Registration response: {payload.message}")
        if not payload.success:
            return

        self.group_id = payload.group_id
        if self.state in (State.FIND_PEERS, State.REGISTER):
            self.state = State.READY

    @lazy_wrapper(ReadyPayload)
    def ready(self, peer: Peer, payload: ReadyPayload) -> None:
        peer_id = self._node_id_for_peer(peer)
        if peer_id is not None and peer_id != self.node_id:
            self.readies.add(peer_id)

    def send_ready(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self.last_ready_at < READY_RETRY_SECONDS:
            return

        for peer in self.peers.values():
            self.ez_send(peer, ReadyPayload())
        self.last_ready_at = now

    def begin_if_ready(self) -> None:
        self.send_ready()
        if len(self.readies) != GROUP_SIZE - 1:
            return

        self.state = State.RUNNING
        print("All teammates ready")
        if self.node_id == 0:
            self.challenge_driver_round = 1
            self.request_challenge(force=True)

    def request_challenge(self, *, force: bool = False) -> None:
        if self.boss is None or self.group_id is None:
            return

        now = time.monotonic()
        if not force and now - self.last_challenge_request_at < CHALLENGE_RETRY_SECONDS:
            return

        self.ez_send(self.boss, ChallengeRequestPayload(self.group_id))
        self.last_challenge_request_at = now

    @lazy_wrapper(ChallengeResponsePayload)
    def challenge_response(self, peer: Peer, payload: ChallengeResponsePayload) -> None:
        if not self._is_server(peer) or not self._valid_round(payload.round_number):
            return

        if self.challenge_driver_round == payload.round_number:
            self.challenge_driver_round = None

        self.handle_round_data(
            payload.round_number,
            payload.nonce,
            source_peer_id=None,
            source="server",
        )

    @lazy_wrapper(InternalSubmissionPayload)
    def submission_payload(self, peer: Peer, payload: InternalSubmissionPayload) -> None:
        peer_id = self._node_id_for_peer(peer)
        if peer_id is None or peer_id == self.node_id:
            return

        round_number = payload.payload.round_number
        if not self._valid_round(round_number):
            return
        if self.group_id is not None and payload.payload.group_id != self.group_id:
            return

        payload_sigs = {
            0: payload.payload.sig1,
            1: payload.payload.sig2,
            2: payload.payload.sig3,
        }

        self.handle_round_data(
            round_number,
            payload.nonce,
            source_peer_id=peer_id,
            source="teammate",
            source_signature=payload_sigs.get(peer_id, b""),
        )

    @lazy_wrapper(SubmissionResponsePayload)
    def submission_response(self, peer: Peer, payload: SubmissionResponsePayload) -> None:
        if not self._is_server(peer):
            return

        print(f"Submission response: {payload.message}")
        if not payload.success:
            if self.state != State.SUCCESS:
                self.request_challenge(force=True)
            return

        self.mark_round_done(payload.round_number, payload.rounds_completed, payload.message)
        self.broadcast_round_done(payload.round_number, self.rounds_completed, payload.message)

        if self.rounds_completed >= ROUNDS:
            self.mark_success()
            return

        self.challenge_driver_round = self.rounds_completed + 1
        self.request_challenge(force=True)

    @lazy_wrapper(InternalRoundDonePayload)
    def internal_round_done(self, peer: Peer, payload: InternalRoundDonePayload) -> None:
        peer_id = self._node_id_for_peer(peer)
        if peer_id is None or peer_id == self.node_id:
            return
        if not self._valid_round(payload.round_number):
            return

        self.mark_round_done(payload.round_number, payload.rounds_completed, payload.message)
        if payload.rounds_completed >= ROUNDS:
            self.mark_success()
            return

        next_round = self.rounds_completed + 1
        if self._is_submitter(next_round):
            print(f"Taking over as submitter for round {next_round}")
            if self.state != State.SUCCESS:
                self.state = State.RUNNING
            self.challenge_driver_round = next_round
            self.request_challenge(force=True)

    def handle_round_data(
        self,
        round_number: int,
        nonce: bytes,
        *,
        source_peer_id: int | None,
        source: str,
        source_signature: bytes = b"",
    ) -> None:
        if len(nonce) != 32 or round_number <= self.rounds_completed:
            return

        if round_number > self.rounds_completed + 1:
            self.rounds_completed = round_number - 1

        first_nonce = self.remember_nonce(round_number, nonce)
        if first_nonce is None:
            return

        if self.challenge_driver_round == round_number:
            self.challenge_driver_round = None

        if source_peer_id is not None and source_signature:
            self.remember_signature(round_number, source_peer_id, source_signature)

        own_signature_created = self.ensure_own_signature(round_number, nonce)
        if first_nonce:
            print(f"Round {round_number} nonce received from {source}")

        if self._is_submitter(round_number):
            if first_nonce:
                self.broadcast_round_state(round_number, force=True)
            self.maybe_submit_round(round_number)
        else:
            self.send_signature_to_submitter(
                round_number,
                force=first_nonce or own_signature_created,
            )

        if self.state not in (State.SUCCESS, State.RUNNING):
            self.state = State.RUNNING

    def remember_nonce(self, round_number: int, nonce: bytes) -> bool | None:
        existing = self.nonces.get(round_number)
        if existing is not None:
            if existing != nonce:
                print(f"Ignoring conflicting nonce for round {round_number}")
                return None
            return False

        self.nonces[round_number] = nonce
        self.signatures.setdefault(round_number, {})
        return True

    def ensure_own_signature(self, round_number: int, nonce: bytes) -> bool:
        round_sigs = self.signatures.setdefault(round_number, {})
        if self.node_id in round_sigs:
            return False

        round_sigs[self.node_id] = default_eccrypto.create_signature(self.private_key, nonce)
        return True

    def remember_signature(self, round_number: int, signer_id: int, signature: bytes) -> None:
        if signer_id < 0 or signer_id >= GROUP_SIZE or not signature:
            return

        round_sigs = self.signatures.setdefault(round_number, {})
        existing = round_sigs.get(signer_id)
        if existing is not None and existing != signature:
            print(f"Ignoring conflicting signature from member {signer_id} for round {round_number}")
            return

        round_sigs[signer_id] = signature

    def payload_for_round(self, round_number: int) -> SubmissionPayload | None:
        if self.group_id is None:
            return None

        round_sigs = self.signatures.setdefault(round_number, {})
        return SubmissionPayload(
            self.group_id,
            round_number,
            round_sigs.get(0, b""),
            round_sigs.get(1, b""),
            round_sigs.get(2, b""),
        )

    def send_round_state(self, peer: Peer, round_number: int) -> None:
        nonce = self.nonces.get(round_number)
        payload = self.payload_for_round(round_number)
        if nonce is None or payload is None:
            return

        self.ez_send(peer, InternalSubmissionPayload(nonce=nonce, payload=payload))

    def send_signature_to_submitter(self, round_number: int, *, force: bool = False) -> None:
        submitter_id = self._submitter_for_round(round_number)
        if submitter_id == self.node_id:
            return

        submitter = self.peers.get(submitter_id)
        if submitter is None:
            return

        now = time.monotonic()
        last_sent = self.last_signature_share_at.get(round_number, 0.0)
        if not force and now - last_sent < SIGNATURE_RETRY_SECONDS:
            return

        self.send_round_state(submitter, round_number)
        self.last_signature_share_at[round_number] = now

    def broadcast_round_state(self, round_number: int, *, force: bool = False) -> None:
        now = time.monotonic()
        last_sent = self.last_round_broadcast_at.get(round_number, 0.0)
        if not force and now - last_sent < ROUND_BROADCAST_RETRY_SECONDS:
            return

        for peer in self.peers.values():
            self.send_round_state(peer, round_number)
        self.last_round_broadcast_at[round_number] = now

    def maybe_submit_round(self, round_number: int, *, force: bool = False) -> None:
        if self.boss is None or not self._is_submitter(round_number):
            return
        if round_number <= self.rounds_completed:
            return

        payload = self.payload_for_round(round_number)
        if payload is None:
            return

        if not all((payload.sig1, payload.sig2, payload.sig3)):
            return

        now = time.monotonic()
        last_sent = self.last_submission_at.get(round_number, 0.0)
        if not force and last_sent > 0.0 and now - last_sent < SUBMISSION_RETRY_SECONDS:
            return

        print(f"Submitting round {round_number} as member {self.node_id}")
        self.ez_send(self.boss, payload)
        self.submitted_rounds.add(round_number)
        self.last_submission_at[round_number] = now

    def broadcast_round_done(self, round_number: int, rounds_completed: int, message: str) -> None:
        payload = InternalRoundDonePayload(round_number, rounds_completed, message)
        for peer in self.peers.values():
            self.ez_send(peer, payload)

    def mark_round_done(self, round_number: int, rounds_completed: int, message: str) -> None:
        if rounds_completed > self.rounds_completed:
            print(message)
        self.rounds_completed = max(self.rounds_completed, rounds_completed)

    def mark_success(self) -> None:
        if self.state != State.SUCCESS:
            print("All rounds completed")
        self.state = State.SUCCESS
        self.stop_at = time.monotonic() + SHUTDOWN_GRACE_SECONDS

    def tick(self) -> None:
        if self.state == State.SUCCESS:
            if self.stop_at is not None and time.monotonic() >= self.stop_at:
                self.done = True
            return

        if self.challenge_driver_round is not None:
            self.request_challenge()

        active_round = self.rounds_completed + 1
        if not self._valid_round(active_round) or active_round not in self.nonces:
            return

        if self._is_submitter(active_round):
            self.broadcast_round_state(active_round)
            self.maybe_submit_round(active_round)
            if active_round in self.submitted_rounds:
                self.request_challenge()
        else:
            self.send_signature_to_submitter(active_round)


async def start_ipv8(node_id: int) -> None:
    builder = ConfigBuilder()
    builder.clear_keys()
    builder.clear_overlays()

    builder.add_key(
        "hetpeer",
        "curve25519",
        KEY_FILE,
    )

    builder.add_overlay(
        "HetCommunity",
        "hetpeer",
        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
        default_bootstrap_defs,
        {"node_id": node_id},
        [],
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"HetCommunity": HetCommunity})
    await ipv8.start()

    community = ipv8.get_overlay(HetCommunity)

    print("IPv8 started, searching for peers")
    try:
        while not community.done:
            match community.state:
                case State.FIND_PEERS:
                    if community.find_peers():
                        print("Server and teammates discovered")
                        community.state = State.REGISTER
                    else:
                        await asyncio.sleep(0.2)
                case State.REGISTER:
                    community.register_group()
                    await asyncio.sleep(0.05)
                case State.READY:
                    community.begin_if_ready()
                    await asyncio.sleep(0.05)
                case State.RUNNING | State.SUCCESS:
                    community.tick()
                    await asyncio.sleep(0.01)

        await asyncio.sleep(0.1)
    finally:
        await ipv8.stop()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IPv8 coordinated group signing client")
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
