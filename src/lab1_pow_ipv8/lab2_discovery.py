"""IPv8 community for Lab 2 endpoint discovery and exchange."""

from __future__ import annotations

import asyncio
import logging
from cryptography.exceptions import UnsupportedAlgorithm
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer

from .constants import LAB2_COMMUNITY_ID_HEX

LOGGER = logging.getLogger("lab2_discovery")


@vp_compile
class EndpointAnnouncementPayload(VariablePayload):
    """Announce UDP endpoint to other group members."""

    msg_id = 10
    format_list = [
        "varlenHutf8",
        "q",
    ]  # host_port (e.g. "192.168.1.1:5000"), port as int
    names = ["host_port", "port"]


@vp_compile
class EndpointRequestPayload(VariablePayload):
    """Request endpoints from known peers."""

    msg_id = 11
    format_list = []
    names = []


def build_lab2_discovery_community():
    """Build IPv8 community for endpoint discovery."""

    class Lab2DiscoveryCommunity(Community):
        community_id = bytes.fromhex(LAB2_COMMUNITY_ID_HEX)

        def __init__(self, settings: CommunitySettings) -> None:
            super().__init__(settings)
            self.add_message_handler(
                EndpointAnnouncementPayload, self.on_endpoint_announcement
            )
            self.add_message_handler(EndpointRequestPayload, self.on_endpoint_request)

            self.local_endpoint: tuple[str, int] | None = None  # (host, port)
            self.peer_endpoints: dict[bytes, tuple[str, int]] = (
                {}
            )  # pubkey_bin -> (host, port)
            self.endpoint_event = asyncio.Event()
            self.target_pubkeys: set[bytes] = set()

        def _verify_signature(self, auth, data: bytes):  # type: ignore[override]
            try:
                return super()._verify_signature(auth, data)
            except UnsupportedAlgorithm as exc:
                self.logger.debug(
                    "Dropping packet with unsupported public-key curve: %s", exc,
                )
                return False, data

        def set_target_pubkeys(self, pubkeys: list[bytes]) -> None:
            self.target_pubkeys = set(pubkeys)

        def started(self) -> None:
            """Called when community starts."""
            async def announce_to_team() -> None:
                if not self.local_endpoint:
                    return
                if self.target_pubkeys and self.target_pubkeys.issubset(self.peer_endpoints):
                    self.cancel_pending_task("announce_to_team")
                    return
                host, port = self.local_endpoint
                host_port_str = f"{host}:{port}"
                for peer in self.get_peers():
                    peer_pubkey = peer.public_key.key_to_bin()
                    if (
                        peer_pubkey in self.target_pubkeys
                        and peer_pubkey not in self.peer_endpoints
                    ):
                        try:
                            self.ez_send(
                                peer,
                                EndpointAnnouncementPayload(host_port_str, port),
                            )
                        except Exception as exc:
                            self.logger.debug("Failed to proactively announce to peer: %s", exc)

            self.register_task("announce_to_team", announce_to_team, interval=1.0, delay=0.1)

        def set_local_endpoint(self, host: str, port: int) -> None:
            """Set this node's UDP endpoint."""
            self.local_endpoint = (host, port)
            LOGGER.info(f"Local endpoint set to {host}:{port}")

        def announce_endpoint_to_peers(self, peers: list[Peer]) -> None:
            """Announce our endpoint to specific peers."""
            if not self.local_endpoint:
                LOGGER.warning("Cannot announce endpoint: not set yet")
                return

            host, port = self.local_endpoint
            host_port_str = f"{host}:{port}"

            for peer in peers:
                try:
                    self.ez_send(
                        peer,
                        EndpointAnnouncementPayload(host_port_str, port),
                    )
                    LOGGER.debug(
                        f"Announced endpoint to {peer.public_key.key_to_bin().hex()[:16]}"
                    )
                except Exception as exc:
                    LOGGER.warning(f"Failed to announce endpoint to peer: {exc}")

        @lazy_wrapper(EndpointAnnouncementPayload)
        def on_endpoint_announcement(
            self, peer: Peer, payload: EndpointAnnouncementPayload
        ) -> None:
            """Receive endpoint announcement from another peer."""
            peer_pubkey = peer.public_key.key_to_bin()
            host_port_str = str(payload.host_port)
            port = int(payload.port)

            # Parse host from host:port string
            if ":" in host_port_str:
                host, _ = host_port_str.rsplit(":", 1)
            else:
                host = host_port_str

            self.peer_endpoints[peer_pubkey] = (host, port)
            LOGGER.info(
                f"Discovered endpoint: ...{peer_pubkey.hex()[-16:]} @ {host}:{port}"
            )
            self.endpoint_event.set()

        @lazy_wrapper(EndpointRequestPayload)
        def on_endpoint_request(
            self, peer: Peer, payload: EndpointRequestPayload
        ) -> None:
            """Respond to endpoint request."""
            if self.local_endpoint:
                host, port = self.local_endpoint
                host_port_str = f"{host}:{port}"
                self.ez_send(
                    peer,
                    EndpointAnnouncementPayload(host_port_str, port),
                )

        async def wait_for_endpoints(
            self,
            target_pubkeys: list[bytes],
            timeout: float = 5.0,
        ) -> dict[bytes, tuple[str, int]]:
            """
            Wait for endpoints from specific peers.

            Returns a dict: pubkey_bin -> (host, port)
            """
            start_time = asyncio.get_event_loop().time()

            while asyncio.get_event_loop().time() - start_time < timeout:
                # Check if we have all endpoints
                found_all = all(pk in self.peer_endpoints for pk in target_pubkeys)
                if found_all:
                    return {pk: self.peer_endpoints[pk] for pk in target_pubkeys}

                # Send requests to peers we're missing
                for peer in self.get_peers():
                    peer_pubkey = peer.public_key.key_to_bin()
                    if (
                        peer_pubkey in target_pubkeys
                        and peer_pubkey not in self.peer_endpoints
                    ):
                        try:
                            self.ez_send(peer, EndpointRequestPayload())
                        except Exception:
                            pass

                # Wait a bit before retrying
                await asyncio.sleep(0.1)

            # Return what we have so far
            return {
                pk: self.peer_endpoints[pk]
                for pk in target_pubkeys
                if pk in self.peer_endpoints
            }

    return Lab2DiscoveryCommunity
