"""IPv8 community for Lab 2 endpoint discovery and exchange."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.messaging.payload_headers import BinMemberAuthenticationPayload
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
            self._unsupported_curve_packets_seen: set[tuple[str, int, str]] = set()
            self._wrap_handlers_to_ignore_unsupported_curves()

            self.local_endpoint: tuple[str, int] | None = None  # (host, port)
            self.peer_endpoints: dict[bytes, tuple[str, int]] = (
                {}
            )  # pubkey_bin -> (host, port)
            self.endpoint_event = asyncio.Event()

        def _wrap_handlers_to_ignore_unsupported_curves(self) -> None:
            """Drop IPv8 packets whose legacy public-key curve is unsupported."""
            for msg_id, handler in enumerate(self.decode_map):
                if handler is not None:
                    self.decode_map[msg_id] = self._ignore_unsupported_curve(
                        msg_id, handler
                    )

        def _ignore_unsupported_curve(
            self,
            msg_id: int,
            handler: Callable[[Any, bytes], Any],
        ) -> Callable[[Any, bytes], Any]:
            def wrapper(source_address: Any, data: bytes) -> Any:
                try:
                    return handler(source_address, data)
                except UnsupportedAlgorithm as exc:
                    self._log_unsupported_curve_packet(
                        msg_id, source_address, data, exc
                    )
                    return None

            return wrapper

        def _log_unsupported_curve_packet(
            self,
            msg_id: int,
            source_address: Any,
            data: bytes,
            exc: UnsupportedAlgorithm,
        ) -> None:
            pubkey_prefix = self._auth_pubkey_prefix(data)
            source = repr(source_address)
            error = str(exc)
            key = (source, msg_id, error)
            pubkey_suffix = (
                f" (auth pubkey prefix {pubkey_prefix})" if pubkey_prefix else ""
            )
            message = (
                "Ignoring IPv8 message %d from %s with unsupported legacy "
                "public-key curve: %s%s"
            )

            if key in self._unsupported_curve_packets_seen:
                self.logger.debug(message, msg_id, source, error, pubkey_suffix)
                return

            self._unsupported_curve_packets_seen.add(key)
            self.logger.warning(message, msg_id, source, error, pubkey_suffix)

        def _auth_pubkey_prefix(self, data: bytes) -> str | None:
            try:
                auth, _ = self.serializer.unpack_serializable(
                    BinMemberAuthenticationPayload,
                    data,
                    offset=23,
                )
            except Exception:
                return None

            return auth.public_key_bin.hex()[:24]

        def started(self) -> None:
            """Called when community starts."""
            return

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
                f"Discovered endpoint: {peer_pubkey.hex()[:16]}... @ {host}:{port}"
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
            target_pubkeys_set = set(target_pubkeys)
            announced_to: set[bytes] = set()
            last_request_sent: dict[bytes, float] = {}

            while asyncio.get_event_loop().time() - start_time < timeout:
                # Check if we have all endpoints
                found_all = all(pk in self.peer_endpoints for pk in target_pubkeys)
                if found_all:
                    return {pk: self.peer_endpoints[pk] for pk in target_pubkeys}

                # Send our endpoint and request theirs once IPv8 has found a target peer.
                now = asyncio.get_event_loop().time()
                for peer in self.get_peers():
                    peer_pubkey = peer.public_key.key_to_bin()
                    if peer_pubkey not in target_pubkeys_set:
                        continue

                    if peer_pubkey not in announced_to:
                        self.announce_endpoint_to_peers([peer])
                        announced_to.add(peer_pubkey)

                    if peer_pubkey in self.peer_endpoints:
                        continue

                    if now - last_request_sent.get(peer_pubkey, 0.0) < 0.5:
                        continue

                    try:
                        self.ez_send(peer, EndpointRequestPayload())
                        last_request_sent[peer_pubkey] = now
                    except Exception as exc:
                        LOGGER.debug(
                            "Failed to request endpoint from %s...: %s",
                            peer_pubkey.hex()[:16],
                            exc,
                        )

                # Wait a bit before retrying
                await asyncio.sleep(0.1)

            # Return what we have so far
            return {
                pk: self.peer_endpoints[pk]
                for pk in target_pubkeys
                if pk in self.peer_endpoints
            }

    return Lab2DiscoveryCommunity
