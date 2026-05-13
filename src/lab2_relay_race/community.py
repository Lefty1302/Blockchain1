"""IPv8 community for Lab 2 server messages and endpoint discovery."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from time import time
from typing import Any, cast

from cryptography.exceptions import UnsupportedAlgorithm
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import PacketDecodingError, lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.messaging.payload_headers import BinMemberAuthenticationPayload
from ipv8.messaging.serialization import PackError
from ipv8.peer import Peer

from lab1_pow_ipv8.constants import LAB2_COMMUNITY_ID_HEX, LAB2_SERVER_PUBLIC_KEY_HEX
from .ids import (
    ENDPOINT_ANNOUNCEMENT,
    ENDPOINT_GOSSIP,
    ENDPOINT_REQUEST,
    SERVER_CHALLENGE_REQUEST,
    SERVER_CHALLENGE_RESPONSE,
    SERVER_GROUP_REGISTER,
    SERVER_GROUP_REGISTER_RESPONSE,
    SERVER_ROUND_RESULT,
    SERVER_SIGNATURE_BUNDLE,
)

LOGGER = logging.getLogger("lab2_community")


@dataclass(frozen=True)
class GroupRegistrationResult:
    success: bool
    group_id: str
    message: str


@dataclass(frozen=True)
class Challenge:
    nonce: bytes
    round_number: int
    deadline: float


@dataclass(frozen=True)
class RoundResult:
    success: bool
    round_number: int
    rounds_completed: int
    message: str


@vp_compile
class GroupRegisterPayload(VariablePayload):
    """Register the three Lab 2 public keys with the server."""

    msg_id = SERVER_GROUP_REGISTER
    format_list = ["varlenH", "varlenH", "varlenH"]
    names = ["member1_key", "member2_key", "member3_key"]


@vp_compile
class GroupRegisterResponsePayload(VariablePayload):
    """Server response for Lab 2 group registration."""

    msg_id = SERVER_GROUP_REGISTER_RESPONSE
    format_list = ["?", "varlenHutf8", "varlenHutf8"]
    names = ["success", "group_id", "message"]


@vp_compile
class ChallengeRequestPayload(VariablePayload):
    """Request the active challenge for a registered group."""

    msg_id = SERVER_CHALLENGE_REQUEST
    format_list = ["varlenHutf8"]
    names = ["group_id"]


@vp_compile
class ChallengeResponsePayload(VariablePayload):
    """Server challenge response containing the nonce for the current round."""

    msg_id = SERVER_CHALLENGE_RESPONSE
    format_list = ["varlenH", "q", "d"]
    names = ["nonce", "round_number", "deadline"]


@vp_compile
class SignatureBundlePayload(VariablePayload):
    """Submit the ordered three-signature bundle for a round."""

    msg_id = SERVER_SIGNATURE_BUNDLE
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]
    names = ["group_id", "round_number", "sig1", "sig2", "sig3"]


@vp_compile
class RoundResultPayload(VariablePayload):
    """Server round result for bundle submissions and request rejections."""

    msg_id = SERVER_ROUND_RESULT
    format_list = ["?", "q", "q", "varlenHutf8"]
    names = ["success", "round_number", "rounds_completed", "message"]


@vp_compile
class EndpointAnnouncementPayload(VariablePayload):
    """Announce UDP endpoint to other group members."""

    msg_id = ENDPOINT_ANNOUNCEMENT
    format_list = ["varlenHutf8", "q"]
    names = ["host_port", "port"]


@vp_compile
class EndpointRequestPayload(VariablePayload):
    """Request UDP endpoints from known teammates."""

    msg_id = ENDPOINT_REQUEST
    format_list: list[str] = []
    names: list[str] = []


@vp_compile
class EndpointGossipPayload(VariablePayload):
    """Tell a teammate about another teammate's endpoint."""

    msg_id = ENDPOINT_GOSSIP
    format_list = ["varlenH", "varlenHutf8", "H"]
    names = ["target_pubkey", "host", "port"]


def build_lab2_community():
    """Build the combined Lab 2 IPv8 community."""

    class Lab2Community(Community):
        community_id = bytes.fromhex(LAB2_COMMUNITY_ID_HEX)
        server_public_key = bytes.fromhex(LAB2_SERVER_PUBLIC_KEY_HEX)

        def __init__(self, settings: CommunitySettings) -> None:
            super().__init__(settings)
            self.add_message_handler(
                GroupRegisterResponsePayload, self.on_group_register_response
            )
            self.add_message_handler(ChallengeResponsePayload, self.on_challenge)
            self.add_message_handler(RoundResultPayload, self.on_round_result)
            self.add_message_handler(
                EndpointAnnouncementPayload, self.on_endpoint_announcement
            )
            self.add_message_handler(EndpointRequestPayload, self.on_endpoint_request)
            self.add_message_handler(EndpointGossipPayload, self.on_endpoint_gossip)
            self._unsupported_curve_packets_seen: set[tuple[str, int, str]] = set()
            self._wrap_handlers_to_ignore_unsupported_curves()

            self.local_endpoint: tuple[str, int] | None = None
            self.peer_endpoints: dict[bytes, tuple[str, int]] = {}
            self.endpoint_event = asyncio.Event()
            self.target_pubkeys: set[bytes] = set()
            self._registration_results: asyncio.Queue[GroupRegistrationResult] = (
                asyncio.Queue()
            )
            self._challenges: asyncio.Queue[Challenge] = asyncio.Queue()
            self._round_results: asyncio.Queue[RoundResult] = asyncio.Queue()

        def _verify_signature(self, auth, data: bytes):  # type: ignore[override]
            try:
                return super()._verify_signature(auth, data)
            except UnsupportedAlgorithm as exc:
                self.logger.debug(
                    "Dropping packet with unsupported public-key curve: %s",
                    exc,
                )
                return False, data

        def on_packet(self, packet, warn_unknown: bool = True) -> None:  # type: ignore[override]
            source_address, data = packet
            probable_peer = self.network.get_verified_by_address(source_address)
            if probable_peer:
                probable_peer.last_response = time()
            if self._prefix != data[:22]:
                return
            msg_id = data[22]
            handler = self.decode_map[msg_id]
            if handler is not None:
                try:
                    result = handler(source_address, data)
                    if asyncio.iscoroutine(result):
                        self.register_anonymous_task(
                            "on_packet",
                            asyncio.ensure_future(result),
                            ignore=(Exception,),
                        )
                except (PacketDecodingError, PackError) as exc:
                    self.logger.debug("Dropping invalid Lab 2 packet: %s", exc)
                except Exception:
                    self.logger.exception("Exception occurred while handling packet!")
            elif warn_unknown:
                self.logger.warning(
                    "Received unknown message: %d from (%s, %d)",
                    msg_id,
                    *source_address,
                )

        def set_target_pubkeys(self, pubkeys: list[bytes]) -> None:
            self.target_pubkeys = set(pubkeys)

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
            """Start periodic teammate endpoint announcements."""

            async def announce_to_team() -> None:
                if not self.local_endpoint:
                    return
                if self.target_pubkeys and self.target_pubkeys.issubset(
                    self.peer_endpoints
                ):
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
                            self.logger.debug(
                                "Failed to proactively announce endpoint: %s", exc
                            )

            self.register_task(
                "announce_to_team", announce_to_team, interval=1.0, delay=0.1
            )

        def set_local_endpoint(self, host: str, port: int) -> None:
            self.local_endpoint = (host, port)
            LOGGER.info("Local endpoint set to %s:%s", host, port)

        def find_server_peer(self) -> Peer | None:
            for peer in self.get_peers():
                if peer.public_key.key_to_bin() == self.server_public_key:
                    return peer
            return None

        async def wait_for_server_peer(self, timeout: float) -> Peer | None:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout
            while loop.time() < deadline:
                server_peer = self.find_server_peer()
                if server_peer is not None:
                    return server_peer
                await asyncio.sleep(0.1)
            return None

        def send_group_register(
            self, server_peer: Peer, member_pubkeys: list[bytes]
        ) -> None:
            if len(member_pubkeys) != 3:
                raise ValueError("Group registration requires exactly three keys")
            self.ez_send(server_peer, GroupRegisterPayload(*member_pubkeys))

        def send_challenge_request(self, server_peer: Peer, group_id: str) -> None:
            self.ez_send(server_peer, ChallengeRequestPayload(group_id))

        def send_signature_bundle(
            self,
            server_peer: Peer,
            group_id: str,
            round_number: int,
            signatures: list[bytes],
        ) -> None:
            if len(signatures) != 3:
                raise ValueError("Signature bundle requires exactly three signatures")
            self.ez_send(
                server_peer,
                SignatureBundlePayload(group_id, round_number, *signatures),
            )

        @lazy_wrapper(GroupRegisterResponsePayload)
        def on_group_register_response(
            self, peer: Peer, payload: GroupRegisterResponsePayload
        ) -> None:
            if not self._is_server(peer):
                return
            payload_obj = cast(Any, payload)
            self._registration_results.put_nowait(
                GroupRegistrationResult(
                    success=bool(payload_obj.success),
                    group_id=str(payload_obj.group_id),
                    message=str(payload_obj.message),
                )
            )

        @lazy_wrapper(ChallengeResponsePayload)
        def on_challenge(self, peer: Peer, payload: ChallengeResponsePayload) -> None:
            if not self._is_server(peer):
                return
            payload_obj = cast(Any, payload)
            self._challenges.put_nowait(
                Challenge(
                    nonce=bytes(payload_obj.nonce),
                    round_number=int(payload_obj.round_number),
                    deadline=float(payload_obj.deadline),
                )
            )

        @lazy_wrapper(RoundResultPayload)
        def on_round_result(self, peer: Peer, payload: RoundResultPayload) -> None:
            if not self._is_server(peer):
                return
            payload_obj = cast(Any, payload)
            self._round_results.put_nowait(
                RoundResult(
                    success=bool(payload_obj.success),
                    round_number=int(payload_obj.round_number),
                    rounds_completed=int(payload_obj.rounds_completed),
                    message=str(payload_obj.message),
                )
            )

        async def wait_for_registration_result(
            self, timeout: float
        ) -> GroupRegistrationResult | None:
            return await _queue_get_or_none(self._registration_results, timeout)

        async def wait_for_challenge(self, timeout: float) -> Challenge | None:
            return await _queue_get_or_none(self._challenges, timeout)

        async def wait_for_round_result(self, timeout: float) -> RoundResult | None:
            return await _queue_get_or_none(self._round_results, timeout)

        @lazy_wrapper(EndpointAnnouncementPayload)
        def on_endpoint_announcement(
            self, peer: Peer, payload: EndpointAnnouncementPayload
        ) -> None:
            peer_pubkey = peer.public_key.key_to_bin()
            if peer_pubkey not in self.target_pubkeys:
                LOGGER.debug(
                    "Ignoring endpoint announcement from non-teammate %s",
                    peer_pubkey.hex()[:16],
                )
                return

            host_port_str = str(payload.host_port)
            port = int(payload.port)
            host = (
                host_port_str.rsplit(":", 1)[0]
                if ":" in host_port_str
                else host_port_str
            )
            is_new = peer_pubkey not in self.peer_endpoints
            self.peer_endpoints[peer_pubkey] = (host, port)
            LOGGER.info(
                "Discovered endpoint: ...%s @ %s:%s",
                peer_pubkey.hex()[-16:],
                host,
                port,
            )
            self.endpoint_event.set()
            if is_new:
                self._gossip_known_endpoints(peer_pubkey)

        @lazy_wrapper(EndpointRequestPayload)
        def on_endpoint_request(
            self, peer: Peer, payload: EndpointRequestPayload
        ) -> None:
            peer_pubkey = peer.public_key.key_to_bin()
            if peer_pubkey not in self.target_pubkeys or not self.local_endpoint:
                return
            host, port = self.local_endpoint
            self.ez_send(peer, EndpointAnnouncementPayload(f"{host}:{port}", port))

        def _peer_for_pubkey(self, pubkey_bin: bytes) -> Peer | None:
            for p in self.get_peers():
                if p.public_key.key_to_bin() == pubkey_bin:
                    return p
            return None

        def _gossip_known_endpoints(self, newly_learned_pubkey: bytes) -> None:
            if newly_learned_pubkey not in self.peer_endpoints:
                return
            new_host, new_port = self.peer_endpoints[newly_learned_pubkey]
            for other_pubkey, (other_host, other_port) in list(
                self.peer_endpoints.items()
            ):
                if other_pubkey == newly_learned_pubkey:
                    continue
                # Tell the other peer about the newcomer
                other_peer = self._peer_for_pubkey(other_pubkey)
                if other_peer is not None:
                    try:
                        self.ez_send(
                            other_peer,
                            EndpointGossipPayload(
                                newly_learned_pubkey, new_host, new_port
                            ),
                        )
                        LOGGER.debug(
                            "Gossip: told ...%s about ...%s @ %s:%d",
                            other_pubkey.hex()[-8:],
                            newly_learned_pubkey.hex()[-8:],
                            new_host,
                            new_port,
                        )
                    except Exception as exc:
                        LOGGER.debug("Gossip send failed: %s", exc)
                # Tell the newcomer about this other peer
                new_peer = self._peer_for_pubkey(newly_learned_pubkey)
                if new_peer is not None:
                    try:
                        self.ez_send(
                            new_peer,
                            EndpointGossipPayload(
                                other_pubkey, other_host, other_port
                            ),
                        )
                        LOGGER.debug(
                            "Gossip: told ...%s about ...%s @ %s:%d",
                            newly_learned_pubkey.hex()[-8:],
                            other_pubkey.hex()[-8:],
                            other_host,
                            other_port,
                        )
                    except Exception as exc:
                        LOGGER.debug("Gossip send failed: %s", exc)

        @lazy_wrapper(EndpointGossipPayload)
        def on_endpoint_gossip(
            self, peer: Peer, payload: EndpointGossipPayload
        ) -> None:
            sender_pk = peer.public_key.key_to_bin()
            if self.target_pubkeys and sender_pk not in self.target_pubkeys:
                return
            target_pk = bytes(payload.target_pubkey)
            if self.target_pubkeys and target_pk not in self.target_pubkeys:
                return
            if target_pk in self.peer_endpoints:
                return
            host = str(payload.host)
            if ":" in host:
                host, _ = host.rsplit(":", 1)
            port = int(payload.port)
            LOGGER.info(
                "Gossip received: ...%s -> ...%s @ %s:%d (walking)",
                sender_pk.hex()[-8:],
                target_pk.hex()[-8:],
                host,
                port,
            )
            try:
                self.walk_to((host, port))
            except Exception as exc:
                LOGGER.debug("walk_to from gossip failed: %s", exc)

        def introduction_response_callback(self, peer, dist, payload) -> None:  # type: ignore[override]
            super().introduction_response_callback(peer, dist, payload)
            pk = peer.public_key.key_to_bin()
            if not self.target_pubkeys or pk not in self.target_pubkeys:
                return
            if pk in self.peer_endpoints:
                return
            try:
                self.ez_send(peer, EndpointRequestPayload())
            except Exception as exc:
                LOGGER.debug("Immediate endpoint request failed: %s", exc)
            if self.local_endpoint:
                host, port = self.local_endpoint
                try:
                    self.ez_send(
                        peer,
                        EndpointAnnouncementPayload(f"{host}:{port}", port),
                    )
                except Exception as exc:
                    LOGGER.debug("Immediate endpoint announce failed: %s", exc)

        async def wait_for_endpoints(
            self,
            target_pubkeys: list[bytes],
            timeout: float = 5.0,
        ) -> dict[bytes, tuple[str, int]]:
            start_time = asyncio.get_running_loop().time()
            while asyncio.get_running_loop().time() - start_time < timeout:
                if all(pk in self.peer_endpoints for pk in target_pubkeys):
                    return {pk: self.peer_endpoints[pk] for pk in target_pubkeys}

                for peer in self.get_peers():
                    peer_pubkey = peer.public_key.key_to_bin()
                    if (
                        peer_pubkey in target_pubkeys
                        and peer_pubkey not in self.peer_endpoints
                    ):
                        try:
                            self.ez_send(peer, EndpointRequestPayload())
                        except Exception as exc:
                            self.logger.debug("Failed endpoint request: %s", exc)

                await asyncio.sleep(0.1)

            return {
                pk: self.peer_endpoints[pk]
                for pk in target_pubkeys
                if pk in self.peer_endpoints
            }

        def _is_server(self, peer: Peer) -> bool:
            if peer.public_key.key_to_bin() == self.server_public_key:
                return True
            LOGGER.debug(
                "Ignoring server-path payload from non-server peer %s",
                peer.public_key.key_to_bin().hex()[:16],
            )
            return False

    return Lab2Community


async def _queue_get_or_none(queue: asyncio.Queue, timeout: float):
    try:
        return await asyncio.wait_for(queue.get(), timeout=timeout)
    except asyncio.TimeoutError:
        return None
