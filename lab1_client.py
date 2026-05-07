from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import multiprocessing
import os
import re
import signal
import struct
import sys
import time
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from queue import Empty
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.messaging.interfaces.udp.endpoint import Address
from ipv8.messaging.payload_dataclass import DataClassPayload, convert_to_payload
from ipv8.messaging.payload_headers import BinMemberAuthenticationPayload
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver
from ipv8_service import IPv8


COMMUNITY_ID_HEX = "2c1cc6e35ff484f99ebdfb6108477783c0102881"
SERVER_PUBLIC_KEY_HEX = (
    "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc"
    "8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"
)
DEFAULT_EMAIL = "cyakisir@tudelft.nl"
DEFAULT_GITHUB_URL = "https://github.com/cenkeryak/blockchain-engineering-assignment1"
DEFAULT_DIFFICULTY = 28
MAX_NONCE = (1 << 63) - 1
KEY_ALIAS = "lab1 identity"


@dataclass
class SubmissionPayload(DataClassPayload[1]):
    email: str
    github_url: str
    nonce: int


@dataclass
class ServerResponsePayload(DataClassPayload[2]):
    success: bool
    message: str


convert_to_payload(SubmissionPayload, 1)
convert_to_payload(ServerResponsePayload, 2)


@dataclass(frozen=True)
class ServerResponse:
    success: bool
    message: str
    peer_public_key_hex: str


class Lab1Settings(CommunitySettings):
    email: str
    github_url: str
    nonce: int
    server_public_key: bytes
    response_future: asyncio.Future[ServerResponse]
    retry_interval: float


class Lab1Community(Community, PeerObserver):
    community_id = bytes.fromhex(COMMUNITY_ID_HEX)
    settings_class = Lab1Settings

    def __init__(self, settings: Lab1Settings) -> None:
        super().__init__(settings)
        self.email = settings.email
        self.github_url = settings.github_url
        self.nonce = settings.nonce
        self.server_public_key = settings.server_public_key
        self.response_future = settings.response_future
        self.retry_interval = settings.retry_interval
        self.last_submit_at = 0.0
        self.submit_attempts = 0

        self.add_message_handler(ServerResponsePayload, self.on_server_response)

    def on_packet(self, packet: tuple[Address, bytes], warn_unknown: bool = True) -> None:
        source_address, data = packet
        probable_peer = self.network.get_verified_by_address(source_address)
        if probable_peer:
            probable_peer.last_response = time.time()
        if self._prefix != data[:22] or len(data) <= 22:
            return

        msg_id = data[22]
        handler = self.decode_map[msg_id]
        if handler is not None:
            try:
                result = handler(source_address, data)
                if asyncio.iscoroutine(result):
                    self.register_anonymous_task("on_packet", asyncio.ensure_future(result), ignore=(Exception,))
            except UnsupportedAlgorithm:
                return
            except Exception:
                self.logger.exception("Exception occurred while handling packet")
        elif warn_unknown:
            self.logger.warning("Received unknown message: %d from (%s, %d)", msg_id, *source_address)

    def started(self) -> None:
        self.network.add_peer_observer(self)
        self.register_task("submit_when_server_is_known", self.try_submit, interval=1.0, delay=0.0)

    async def unload(self) -> None:
        self.network.remove_peer_observer(self)
        await super().unload()

    def on_peer_added(self, peer: Peer) -> None:
        if self.is_server(peer):
            print(f"Discovered lab server at {peer.address}; public key matched.", flush=True)
            self.try_submit()

    def on_peer_removed(self, peer: Peer) -> None:
        if self.is_server(peer):
            print("Lab server peer was removed from the local peer graph.", flush=True)

    def is_server(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin() == self.server_public_key

    def find_server_peer(self) -> Peer | None:
        peer = self.network.get_verified_by_public_key_bin(self.server_public_key)
        if peer is not None:
            return peer
        for candidate in self.get_peers():
            if self.is_server(candidate):
                return candidate
        return None

    def try_submit(self) -> None:
        if self.response_future.done():
            self.cancel_pending_task("submit_when_server_is_known")
            return

        server_peer = self.find_server_peer()
        if server_peer is None:
            return

        now = time.monotonic()
        if self.submit_attempts and now - self.last_submit_at < self.retry_interval:
            return

        self.submit_attempts += 1
        self.last_submit_at = now
        print(
            f"Sending submission attempt {self.submit_attempts} to {server_peer.address} "
            f"with nonce {self.nonce}.",
            flush=True,
        )
        self.ez_send(server_peer, SubmissionPayload(self.email, self.github_url, self.nonce))

    def on_server_response(self, source_address: Address, data: bytes) -> None:
        try:
            auth, _ = self.serializer.unpack_serializable(BinMemberAuthenticationPayload, data, offset=23)
        except Exception:
            return

        if auth.public_key_bin != self.server_public_key:
            return

        signature_valid, remainder = self._verify_signature(auth, data)
        if not signature_valid:
            print("Ignored lab server response with an invalid IPv8 signature.", flush=True)
            return

        payload = self.serializer.unpack_serializable_list([ServerResponsePayload], remainder, offset=23)[0]
        peer = self.network.verified_by_public_key_bin.get(auth.public_key_bin)
        if peer is not None:
            peer.add_address(source_address)
        else:
            peer = Peer(auth.public_key_bin, source_address)

        if not self.is_server(peer):
            print(
                "Ignored response from non-server peer "
                f"{peer.public_key.key_to_bin().hex()[:32]}...",
                flush=True,
            )
            return

        response = ServerResponse(payload.success, payload.message, peer.public_key.key_to_bin().hex())
        print(f"Server response: success={payload.success} message={payload.message!r}", flush=True)
        if not self.response_future.done():
            self.response_future.set_result(response)


def canonicalize_email(email: str) -> str:
    return unicodedata.normalize("NFC", email).strip().lower()


def validate_email(email: str) -> None:
    encoded = email.encode("utf-8")
    if not encoded or len(encoded) > 254:
        raise ValueError("email must be non-empty and at most 254 UTF-8 bytes")
    if "\n" in email or "\r" in email:
        raise ValueError("email may not contain newlines")
    if not re.fullmatch(r"[^@\s]+@(?:student\.)?tudelft\.nl", email):
        raise ValueError("email must be a well-formed @tudelft.nl or @student.tudelft.nl address")


def validate_github_url(github_url: str) -> None:
    encoded = github_url.encode("utf-8")
    if not encoded or len(encoded) > 512:
        raise ValueError("github_url must be non-empty and at most 512 UTF-8 bytes")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in github_url):
        raise ValueError("github_url may not contain whitespace or control characters")


def validate_nonce(nonce: int) -> None:
    if nonce < 0 or nonce > MAX_NONCE:
        raise ValueError("nonce must be a non-negative integer that fits in signed int64")


def pow_prefix(email: str, github_url: str) -> bytes:
    return email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"


def pow_digest(email: str, github_url: str, nonce: int) -> bytes:
    validate_nonce(nonce)
    return hashlib.sha256(pow_prefix(email, github_url) + struct.pack(">Q", nonce)).digest()


def has_leading_zero_bits(digest: bytes, difficulty: int = DEFAULT_DIFFICULTY) -> bool:
    if difficulty < 0 or difficulty > len(digest) * 8:
        raise ValueError("difficulty must be between 0 and the digest bit length")
    full_zero_bytes, remaining_bits = divmod(difficulty, 8)
    if digest[:full_zero_bytes] != b"\x00" * full_zero_bytes:
        return False
    if remaining_bits == 0:
        return True
    return digest[full_zero_bytes] < (1 << (8 - remaining_bits))


def is_valid_pow(email: str, github_url: str, nonce: int, difficulty: int = DEFAULT_DIFFICULTY) -> bool:
    return has_leading_zero_bits(pow_digest(email, github_url, nonce), difficulty)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(path)


def _load_existing_solution(progress_file: Path, email: str, github_url: str, difficulty: int) -> int | None:
    data = _read_json(progress_file)
    if not data:
        return None
    if data.get("email") != email or data.get("github_url") != github_url or data.get("difficulty") != difficulty:
        return None
    nonce = data.get("solution", {}).get("nonce")
    if isinstance(nonce, int) and is_valid_pow(email, github_url, nonce, difficulty):
        return nonce
    return None


def _load_worker_starts(
    progress_file: Path,
    email: str,
    github_url: str,
    difficulty: int,
    workers: int,
    requested_start: int,
) -> list[int]:
    data = _read_json(progress_file)
    if not data:
        return [requested_start + worker_id for worker_id in range(workers)]
    if data.get("email") != email or data.get("github_url") != github_url or data.get("difficulty") != difficulty:
        return [requested_start + worker_id for worker_id in range(workers)]

    positions = data.get("worker_positions", {})
    if not isinstance(positions, dict) or not positions:
        return [requested_start + worker_id for worker_id in range(workers)]

    saved_workers = data.get("workers")
    if saved_workers == workers and all(str(worker_id) in positions for worker_id in range(workers)):
        starts = [max(int(positions[str(worker_id)]), 0) for worker_id in range(workers)]
        print(f"Resuming mining from {progress_file} with {workers} saved worker positions.", flush=True)
        return starts

    fallback_start = max(min(int(value) for value in positions.values()), requested_start)
    print(
        f"Resuming mining from nonce {fallback_start:,}; worker count changed, so some overlap is possible.",
        flush=True,
    )
    return [fallback_start + worker_id for worker_id in range(workers)]


def _save_progress(
    progress_file: Path,
    email: str,
    github_url: str,
    difficulty: int,
    workers: int,
    worker_positions: dict[int, int],
) -> None:
    _write_json_atomic(
        progress_file,
        {
            "email": email,
            "github_url": github_url,
            "difficulty": difficulty,
            "workers": workers,
            "updated_at": _utc_now(),
            "worker_positions": {str(k): v for k, v in sorted(worker_positions.items())},
        },
    )


def _save_solution(
    progress_file: Path,
    email: str,
    github_url: str,
    difficulty: int,
    nonce: int,
    digest_hex: str,
    workers: int,
    worker_positions: dict[int, int],
) -> None:
    _write_json_atomic(
        progress_file,
        {
            "email": email,
            "github_url": github_url,
            "difficulty": difficulty,
            "workers": workers,
            "updated_at": _utc_now(),
            "worker_positions": {str(k): v for k, v in sorted(worker_positions.items())},
            "solution": {"nonce": nonce, "sha256": digest_hex},
        },
    )


def _pow_worker(
    worker_id: int,
    prefix: bytes,
    difficulty: int,
    start_nonce: int,
    step: int,
    stop_event: multiprocessing.synchronize.Event,
    result_queue: multiprocessing.Queue,
    progress_queue: multiprocessing.Queue,
    progress_interval: float,
) -> None:
    batch_size = 8192
    full_zero_bytes, remaining_bits = divmod(difficulty, 8)
    zero_prefix = b"\x00" * full_zero_bytes
    threshold = 1 << (8 - remaining_bits) if remaining_bits else 256
    pack_nonce = struct.Struct(">Q").pack
    base_hash = hashlib.sha256(prefix)
    nonce = start_nonce
    checked = 0
    last_progress_at = time.monotonic()

    while nonce <= MAX_NONCE:
        for _ in range(batch_size):
            candidate = base_hash.copy()
            candidate.update(pack_nonce(nonce))
            digest = candidate.digest()
            if digest[:full_zero_bytes] == zero_prefix and (remaining_bits == 0 or digest[full_zero_bytes] < threshold):
                result_queue.put((worker_id, nonce, digest.hex(), checked + 1))
                stop_event.set()
                return

            nonce += step
            checked += 1
            if nonce > MAX_NONCE:
                break

        if stop_event.is_set():
            break

        now = time.monotonic()
        if now - last_progress_at >= progress_interval:
            progress_queue.put((worker_id, nonce, checked))
            last_progress_at = now

    progress_queue.put((worker_id, nonce, checked))


def mine_pow(
    email: str,
    github_url: str,
    difficulty: int = DEFAULT_DIFFICULTY,
    workers: int | None = None,
    start_nonce: int = 0,
    progress_file: Path | None = None,
    progress_interval: float = 5.0,
) -> tuple[int, str]:
    validate_email(email)
    validate_github_url(github_url)
    validate_nonce(start_nonce)
    if difficulty < 0 or difficulty > 256:
        raise ValueError("difficulty must be between 0 and 256")

    if progress_file is not None:
        existing = _load_existing_solution(progress_file, email, github_url, difficulty)
        if existing is not None:
            digest_hex = pow_digest(email, github_url, existing).hex()
            print(f"Reusing saved valid nonce {existing} from {progress_file}.", flush=True)
            return existing, digest_hex

    worker_count = workers or max((os.cpu_count() or 1) - 1, 1)
    worker_count = max(worker_count, 1)
    starts = (
        _load_worker_starts(progress_file, email, github_url, difficulty, worker_count, start_nonce)
        if progress_file is not None
        else [start_nonce + worker_id for worker_id in range(worker_count)]
    )
    worker_positions = {worker_id: starts[worker_id] for worker_id in range(worker_count)}
    checked_by_worker = {worker_id: 0 for worker_id in range(worker_count)}

    print(
        f"Mining PoW for {email} and {github_url} at difficulty {difficulty} "
        f"with {worker_count} worker(s).",
        flush=True,
    )

    ctx = multiprocessing.get_context("spawn")
    stop_event = ctx.Event()
    result_queue = ctx.Queue()
    progress_queue = ctx.Queue()
    processes = [
        ctx.Process(
            target=_pow_worker,
            args=(
                worker_id,
                pow_prefix(email, github_url),
                difficulty,
                starts[worker_id],
                worker_count,
                stop_event,
                result_queue,
                progress_queue,
                max(progress_interval, 0.5),
            ),
        )
        for worker_id in range(worker_count)
    ]

    started_at = time.monotonic()
    last_report_at = started_at
    for process in processes:
        process.start()

    try:
        while any(process.is_alive() for process in processes):
            try:
                worker_id, nonce, digest_hex, checked = result_queue.get(timeout=0.2)
                worker_positions[worker_id] = nonce
                checked_by_worker[worker_id] = checked
                if progress_file is not None:
                    _save_solution(
                        progress_file,
                        email,
                        github_url,
                        difficulty,
                        nonce,
                        digest_hex,
                        worker_count,
                        worker_positions,
                    )
                print(f"Found nonce {nonce} with SHA256 {digest_hex}.", flush=True)
                return nonce, digest_hex
            except Empty:
                pass

            while True:
                try:
                    worker_id, nonce, checked = progress_queue.get_nowait()
                except Empty:
                    break
                worker_positions[worker_id] = nonce
                checked_by_worker[worker_id] = checked

            now = time.monotonic()
            if now - last_report_at >= progress_interval:
                total_checked = sum(checked_by_worker.values())
                elapsed = max(now - started_at, 0.001)
                rate = total_checked / elapsed
                print(f"Mining... checked {total_checked:,} nonces at {rate:,.0f} H/s.", flush=True)
                if progress_file is not None:
                    _save_progress(progress_file, email, github_url, difficulty, worker_count, worker_positions)
                last_report_at = now

        while True:
            try:
                worker_id, nonce, digest_hex, checked = result_queue.get_nowait()
                worker_positions[worker_id] = nonce
                checked_by_worker[worker_id] = checked
                if progress_file is not None:
                    _save_solution(
                        progress_file,
                        email,
                        github_url,
                        difficulty,
                        nonce,
                        digest_hex,
                        worker_count,
                        worker_positions,
                    )
                return nonce, digest_hex
            except Empty:
                break
        raise RuntimeError("PoW search ended without finding a valid nonce")
    except KeyboardInterrupt:
        if progress_file is not None:
            _save_progress(progress_file, email, github_url, difficulty, worker_count, worker_positions)
            print(f"Saved mining progress to {progress_file}.", flush=True)
        raise
    finally:
        stop_event.set()
        for process in processes:
            process.join(timeout=1.0)
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=1.0)


def ensure_private_key(key_file: Path) -> str:
    key_file.parent.mkdir(parents=True, exist_ok=True)
    if key_file.exists():
        private_bin = key_file.read_bytes()
        if not default_eccrypto.is_valid_private_bin(private_bin):
            raise RuntimeError(f"{key_file} exists but does not contain a valid IPv8 private key")
        key = default_eccrypto.key_from_private_bin(private_bin)
        print(f"Loaded IPv8 private key from {key_file}.", flush=True)
    else:
        key = default_eccrypto.generate_key("curve25519")
        key_file.write_bytes(key.key_to_bin())
        try:
            key_file.chmod(0o600)
        except OSError:
            pass
        print(f"Generated and saved new IPv8 private key at {key_file}. Keep this file safe.", flush=True)

    public_key_hex = key.pub().key_to_bin().hex()
    print(f"Your IPv8 public key: {public_key_hex}", flush=True)
    return public_key_hex


async def submit_solution(args: argparse.Namespace, email: str, github_url: str, nonce: int) -> ServerResponse:
    community_id = bytes.fromhex(args.community_id)
    server_public_key = bytes.fromhex(args.server_public_key)
    if len(community_id) != 20:
        raise ValueError("community id must be 20 bytes / 40 hex characters")
    if not default_eccrypto.is_valid_public_bin(server_public_key):
        raise ValueError("server public key is not a valid IPv8 public key")

    Lab1Community.community_id = community_id
    response_future: asyncio.Future[ServerResponse] = asyncio.get_running_loop().create_future()

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(args.port)
    builder.set_log_level(args.log_level)
    builder.add_key(KEY_ALIAS, "curve25519", str(args.key_file))
    builder.add_overlay(
        "Lab1Community",
        KEY_ALIAS,
        [WalkerDefinition(Strategy.RandomWalk, args.target_peers, {"timeout": args.walk_timeout})],
        default_bootstrap_defs,
        {
            "email": email,
            "github_url": github_url,
            "nonce": nonce,
            "server_public_key": server_public_key,
            "response_future": response_future,
            "retry_interval": args.retry_interval,
        },
        [("started",)],
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab1Community": Lab1Community})
    await ipv8.start()
    overlay = ipv8.get_overlay(Lab1Community)
    print(f"IPv8 started on {ipv8.endpoint.get_address()}; searching for the lab server.", flush=True)
    print(f"Community ID: {community_id.hex()}", flush=True)
    print(f"Server public key: {server_public_key.hex()}", flush=True)

    if overlay is not None:
        overlay.try_submit()

    try:
        return await asyncio.wait_for(response_future, timeout=args.network_timeout)
    finally:
        await ipv8.stop()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TU Delft Blockchain Engineering Lab 1 IPv8 PoW client")
    parser.add_argument("--email", default=DEFAULT_EMAIL, help="TU Delft email address to submit")
    parser.add_argument("--github-url", default=DEFAULT_GITHUB_URL, help="public GitHub repository URL")
    parser.add_argument("--nonce", type=int, help="use an existing nonce instead of mining")
    parser.add_argument("--difficulty", type=int, default=DEFAULT_DIFFICULTY, help="PoW leading-zero-bit difficulty")
    parser.add_argument("--workers", type=int, help="number of local mining worker processes")
    parser.add_argument("--start-nonce", type=int, default=0, help="starting nonce when mining from scratch")
    parser.add_argument("--progress-file", type=Path, default=Path("pow_progress.json"), help="mining checkpoint file")
    parser.add_argument("--key-file", type=Path, default=Path("lab1_identity.pem"), help="IPv8 private key file")
    parser.add_argument("--mine-only", action="store_true", help="mine/verify a nonce but do not contact IPv8")
    parser.add_argument("--community-id", default=COMMUNITY_ID_HEX, help="IPv8 community id as hex")
    parser.add_argument("--server-public-key", default=SERVER_PUBLIC_KEY_HEX, help="lab server public key as hex")
    parser.add_argument("--port", type=int, default=0, help="local UDP port; 0 lets the OS pick one")
    parser.add_argument("--target-peers", type=int, default=20, help="RandomWalk target peer count")
    parser.add_argument("--walk-timeout", type=float, default=3.0, help="IPv8 RandomWalk timeout")
    parser.add_argument("--retry-interval", type=float, default=5.0, help="seconds between submission retries")
    parser.add_argument("--network-timeout", type=float, default=300.0, help="seconds to wait for an accepted/rejected reply")
    parser.add_argument("--progress-interval", type=float, default=5.0, help="seconds between mining progress reports")
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"],
        help="IPv8 logging level",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.email = canonicalize_email(args.email)

    try:
        validate_email(args.email)
        validate_github_url(args.github_url)
        validate_nonce(args.start_nonce)
        ensure_private_key(args.key_file)

        if args.nonce is None:
            nonce, digest_hex = mine_pow(
                args.email,
                args.github_url,
                args.difficulty,
                workers=args.workers,
                start_nonce=args.start_nonce,
                progress_file=args.progress_file,
                progress_interval=args.progress_interval,
            )
        else:
            validate_nonce(args.nonce)
            nonce = args.nonce
            digest_hex = pow_digest(args.email, args.github_url, nonce).hex()
            if not has_leading_zero_bits(bytes.fromhex(digest_hex), args.difficulty):
                raise ValueError(f"nonce {nonce} does not satisfy difficulty {args.difficulty}")
            print(f"Using supplied nonce {nonce} with SHA256 {digest_hex}.", flush=True)

        print(f"PoW is valid locally: nonce={nonce} sha256={digest_hex}", flush=True)
        if args.mine_only:
            return 0

        if args.difficulty != DEFAULT_DIFFICULTY:
            print(
                f"Warning: submitting with local difficulty {args.difficulty}; "
                f"the course server still requires {DEFAULT_DIFFICULTY}.",
                flush=True,
            )

        response = asyncio.run(submit_solution(args, args.email, args.github_url, nonce))
        return 0 if response.success else 2
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except asyncio.TimeoutError:
        print("Timed out before receiving a response from the verified lab server.", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    raise SystemExit(main())
