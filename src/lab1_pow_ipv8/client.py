"""IPv8 client overlay and submit flow for Lab 1."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, cast

from cryptography.exceptions import UnsupportedAlgorithm

from .libsodium_bootstrap import ensure_libsodium

from .constants import COMMUNITY_ID_HEX, SERVER_PUBLIC_KEY_HEX
from .protocol import SubmissionPayload, SubmissionResponsePayload
from .validation import validate_email, validate_github_url, validate_nonce

LOGGER = logging.getLogger("lab1_pow_ipv8")


@dataclass(frozen=True)
class SubmissionResult:
    success: bool
    message: str


def build_lab_pow_community():
    ensure_libsodium()

    from ipv8.community import Community, CommunitySettings
    from ipv8.lazy_community import PacketDecodingError, lazy_wrapper
    from ipv8.peer import Peer
    from time import time

    class LabPowCommunity(Community):
        community_id = bytes.fromhex(COMMUNITY_ID_HEX)
        server_public_key = bytes.fromhex(SERVER_PUBLIC_KEY_HEX)

        def __init__(self, settings: CommunitySettings) -> None:
            super().__init__(settings)
            self.add_message_handler(SubmissionResponsePayload, self.on_response)

            self.email: str | None = None
            self.github_url: str | None = None
            self.nonce: int | None = None

            self._submit_started = False
            self._response: SubmissionResult | None = None
            self._response_event = asyncio.Event()
            self._debug_peers = False

        def started(self) -> None:
            # Submission is configured after IPv8 starts via configure_submission.
            return

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
                except PacketDecodingError as exc:
                    self.logger.debug("Dropping packet with invalid signature: %s", exc)
                except Exception:
                    self.logger.exception("Exception occurred while handling packet!")
            elif warn_unknown:
                self.logger.warning(
                    "Received unknown message: %d from (%s, %d)",
                    msg_id,
                    *source_address,
                )

        def configure_submission(
            self,
            email: str,
            github_url: str,
            nonce: int,
            debug_peers: bool = False,
            bootstrap_addrs: list[tuple[str, int]] | None = None,
        ) -> None:
            validate_email(email)
            validate_github_url(github_url)
            validate_nonce(nonce)

            self.email = email
            self.github_url = github_url
            self.nonce = nonce
            self._debug_peers = debug_peers

            if bootstrap_addrs:
                for addr in bootstrap_addrs:
                    LOGGER.info("Bootstrapping via %s:%s", addr[0], addr[1])
                    self.walk_to(addr)

            async def submit_when_found() -> None:
                if self._response_event.is_set():
                    self.cancel_pending_task("submit_when_found")
                    return

                if self._debug_peers:
                    self._log_known_peers()

                server_peer = self.find_server_peer()
                if server_peer is None:
                    LOGGER.info("No matching server peer discovered yet; retrying...")
                    return

                if not self._submit_started:
                    self._submit_started = True
                    LOGGER.info("Discovered server peer, submitting PoW...")
                    self.ez_send(
                        server_peer,
                        SubmissionPayload(self.email, self.github_url, self.nonce),
                    )

            self.register_task(
                "submit_when_found",
                submit_when_found,
                interval=2.0,
                delay=0.1,
            )

        def _log_known_peers(self) -> None:
            peers = self.get_peers()
            if not peers:
                LOGGER.info("Known peers: none yet")
                return
            for peer in peers:
                LOGGER.info(
                    "Known peer: %s",
                    peer.public_key.key_to_bin().hex(),
                )

        def find_server_peer(self) -> Peer | None:
            for peer in self.get_peers():
                if peer.public_key.key_to_bin() == self.server_public_key:
                    return peer
            return None

        @lazy_wrapper(SubmissionResponsePayload)
        def on_response(self, peer: Peer, payload: SubmissionResponsePayload) -> None:
            if peer.public_key.key_to_bin() != self.server_public_key:
                LOGGER.warning(
                    "Ignoring response from non-server peer: %s",
                    peer.public_key.key_to_bin().hex(),
                )
                return

            payload_obj = cast(Any, payload)
            self._response = SubmissionResult(
                success=bool(payload_obj.success),
                message=str(payload_obj.message),
            )
            self._response_event.set()
            self.cancel_pending_task("submit_when_found")

        async def wait_for_response(
            self, timeout_seconds: float
        ) -> SubmissionResult | None:
            try:
                await asyncio.wait_for(
                    self._response_event.wait(), timeout=timeout_seconds
                )
            except TimeoutError:
                return None
            return self._response

    return LabPowCommunity


async def submit_pow(
    email: str,
    github_url: str,
    nonce: int,
    key_file: str,
    timeout_seconds: float = 60.0,
    debug_peers: bool = False,
    bootstrap_addrs: list[tuple[str, int]] | None = None,
    walk_peers: int = 30,
    walk_timeout: float = 3.0,
) -> SubmissionResult:
    ensure_libsodium()

    from ipv8.configuration import (
        ConfigBuilder,
        Strategy,
        WalkerDefinition,
        default_bootstrap_defs,
    )
    from ipv8_service import IPv8

    validate_email(email)
    validate_github_url(github_url)
    validate_nonce(nonce)

    LabPowCommunity = build_lab_pow_community()

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("lab1", "curve25519", key_file)
    builder.add_overlay(
        "LabPowCommunity",
        "lab1",
        [WalkerDefinition(Strategy.RandomWalk, walk_peers, {"timeout": walk_timeout})],
        default_bootstrap_defs,
        {},
        [("started",)],
    )

    ipv8 = IPv8(
        builder.finalize(), extra_communities={"LabPowCommunity": LabPowCommunity}
    )
    await ipv8.start()

    try:
        overlay = next(o for o in ipv8.overlays if isinstance(o, LabPowCommunity))
        overlay.configure_submission(
            email,
            github_url,
            nonce,
            debug_peers=debug_peers,
            bootstrap_addrs=bootstrap_addrs,
        )
        result = await overlay.wait_for_response(timeout_seconds)
        if result is None:
            raise TimeoutError(
                "No authenticated response from server before timeout. "
                "Make sure server peer was discovered and submission was signed."
            )
        return result
    finally:
        await ipv8.stop()
