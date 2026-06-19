"""Registration community: announce our blockchain's community id to the Lab 3 server."""

from __future__ import annotations

import asyncio

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.peer import Peer

from src.payloads import RegisterBlockchain, RegisterResponse

REGISTRATION_COMMUNITY_ID = bytes.fromhex("4c616233426c6f636b636861696e323032365057")
SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d24"
    "6344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6"
)
REGISTER_RETRY_SECONDS = 5.0


class RegistrationSettings(CommunitySettings):
    group_id: str = ""
    blockchain_community_id: bytes = b""


class RegistrationCommunity(Community):
    community_id = REGISTRATION_COMMUNITY_ID
    settings_class = RegistrationSettings

    def __init__(self, settings: RegistrationSettings) -> None:
        super().__init__(settings)
        self.group_id = settings.group_id
        self.blockchain_community_id = settings.blockchain_community_id
        self.registered = False
        self.add_message_handler(RegisterResponse, self.on_register_response)
        self.register_task("register", self.register_loop)

    async def register_loop(self) -> None:
        """Keep sending RegisterBlockchain to the server until it confirms."""
        while not self.registered:
            server = next((p for p in self.get_peers()
                           if p.public_key.key_to_bin() == SERVER_PUBLIC_KEY), None)
            if server is not None:
                print(f"[register] registering group {self.group_id!r} with community "
                      f"{self.blockchain_community_id.hex()}")
                self.ez_send(server, RegisterBlockchain(self.group_id, self.blockchain_community_id))
            else:
                print(f"[register] waiting for server peer ({len(self.get_peers())} peers seen)")
            await asyncio.sleep(REGISTER_RETRY_SECONDS)

    @lazy_wrapper(RegisterResponse)
    def on_register_response(self, peer: Peer, payload: RegisterResponse) -> None:
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        print(f"[register] success={payload.success}: {payload.message}")
        if payload.success:
            self.registered = True
