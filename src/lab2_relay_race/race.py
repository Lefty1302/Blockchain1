"""Relay race orchestration for Lab 2."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from ipv8.configuration import (
    ConfigBuilder,
    Strategy,
    WalkerDefinition,
    default_bootstrap_defs,
)
from ipv8_service import IPv8

from lab1_pow_ipv8.libsodium_bootstrap import ensure_libsodium
from .community import Challenge, RoundResult, build_lab2_community
from .ids import (
    UDP_ACK,
    UDP_BATON_PASS,
    UDP_GROUP_READY,
    UDP_NONCE_BROADCAST,
    UDP_SIGNATURE_REPLY,
)
from .keyutil import (
    extract_public_key_hex,
    load_private_key,
    sign_bytes,
    verify_signature,
)
from .team import TeamConfig, TeamMember
from .udp_prep import PeerEndpoint, get_primary_outbound_ip
from .udp_protocol import (
    body_bytes,
    body_int,
    body_str,
    build_ack_body,
    build_baton_pass_body,
    build_group_ready_body,
    build_nonce_broadcast_body,
    build_signature_reply_body,
)
from .udp_runtime import SignedUdpNode

LOGGER = logging.getLogger("lab2_race")


@dataclass(frozen=True)
class RaceSettings:
    key_file: str
    udp_port: int
    team_config: TeamConfig
    discovery_timeout: float = 300.0
    server_peer_timeout: float = 30.0
    registration_timeout: float = 30.0
    group_ready_timeout: float = 30.0
    request_retry_interval: float = 0.35
    signature_retry_interval: float = 0.25
    baton_timeout: float = 2.0
    round_timeout: float = 10.0
    walk_peers: int = 200
    walk_timeout: float = 3.0


@dataclass(frozen=True)
class RaceOutcome:
    group_id: str
    local_role: str
    final_result: RoundResult | None


def build_ordered_signature_list(
    team_config: TeamConfig,
    signatures_by_pubkey: dict[str, bytes],
) -> list[bytes]:
    missing = [
        member.name
        for member in team_config.members
        if member.pubkey_hex not in signatures_by_pubkey
    ]
    if missing:
        raise ValueError(f"Missing signatures from: {', '.join(missing)}")
    return [signatures_by_pubkey[member.pubkey_hex] for member in team_config.members]


async def run_relay_race(settings: RaceSettings) -> RaceOutcome:
    ensure_libsodium()
    local_pubkey = extract_public_key_hex(settings.key_file)
    private_key = load_private_key(settings.key_file)
    team = settings.team_config
    local_member = team.local_member(local_pubkey)
    teammate_members = team.teammates(local_pubkey)
    teammate_pubkeys = [member.pubkey_hex for member in teammate_members]

    udp_node = SignedUdpNode(
        local_private_key=private_key,
        local_pubkey_hex=local_pubkey,
        allowed_pubkeys=team.pubkey_set,
    )
    await udp_node.start(settings.udp_port)

    Lab2Community = build_lab2_community()
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("lab2", "curve25519", settings.key_file)
    builder.add_overlay(
        "Lab2Community",
        "lab2",
        [
            WalkerDefinition(
                Strategy.RandomWalk,
                settings.walk_peers,
                {"timeout": settings.walk_timeout},
            )
        ],
        default_bootstrap_defs,
        {},
        [("started",)],
    )
    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab2Community": Lab2Community})
    await ipv8.start()

    try:
        overlay = next(o for o in ipv8.overlays if isinstance(o, Lab2Community))
        overlay.set_local_endpoint(get_primary_outbound_ip(), settings.udp_port)
        overlay.set_target_pubkeys(
            [bytes.fromhex(pubkey) for pubkey in teammate_pubkeys]
        )

        peer_map = await _discover_team_endpoints(
            overlay,
            teammate_members,
            settings.discovery_timeout,
        )
        udp_node.set_peers(peer_map)

        server_peer = await overlay.wait_for_server_peer(settings.server_peer_timeout)
        if server_peer is None:
            raise TimeoutError("Lab 2 server peer was not discovered")

        runner = _RelayRaceSession(
            settings=settings,
            local_member=local_member,
            private_key=private_key,
            overlay=overlay,
            server_peer=server_peer,
            udp_node=udp_node,
        )
        return await runner.run()
    finally:
        await udp_node.stop()
        await ipv8.stop()


async def _discover_team_endpoints(
    overlay,
    teammate_members: list[TeamMember],
    timeout: float,
) -> dict[str, PeerEndpoint]:
    target_pubkeys = [member.pubkey for member in teammate_members]
    LOGGER.info("Discovering %d teammate UDP endpoint(s)", len(target_pubkeys))
    endpoints = await overlay.wait_for_endpoints(target_pubkeys, timeout=timeout)
    missing = [
        member.name for member in teammate_members if member.pubkey not in endpoints
    ]
    if missing:
        raise TimeoutError(f"Missing teammate endpoint(s): {', '.join(missing)}")

    peers: dict[str, PeerEndpoint] = {}
    for member in teammate_members:
        host, port = endpoints[member.pubkey]
        peers[member.pubkey_hex] = PeerEndpoint(member.pubkey_hex, host, port)
        LOGGER.info(
            "Discovered Node %s (%s) at %s:%s", member.role, member.name, host, port
        )
    return peers


class _RelayRaceSession:
    def __init__(
        self,
        *,
        settings: RaceSettings,
        local_member: TeamMember,
        private_key,
        overlay,
        server_peer,
        udp_node: SignedUdpNode,
    ) -> None:
        self.settings = settings
        self.team = settings.team_config
        self.local_member = local_member
        self.private_key = private_key
        self.overlay = overlay
        self.server_peer = server_peer
        self.udp = udp_node
        self.group_id: str | None = None
        self.signed_rounds: dict[int, tuple[bytes, bytes]] = {}
        self.local_round = {"A": 1, "B": 2, "C": 3}[self.local_member.role]

    async def run(self) -> RaceOutcome:
        if self.local_member.role == "A":
            group_id = await self._register_group()
            await self._send_group_ready(group_id)
        else:
            group_id = await self._wait_for_group_ready()
        self.group_id = group_id

        for round_number in range(1, self.local_round):
            await self._follow_round(round_number)

        if self.local_round > 1:
            await self._wait_for_baton_or_fallback(self.local_round)

        final_result = await self._lead_round(self.local_round)
        return RaceOutcome(
            group_id=group_id,
            local_role=self.local_member.role,
            final_result=final_result,
        )

    async def _register_group(self) -> str:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.settings.registration_timeout
        while loop.time() < deadline:
            self.overlay.send_group_register(
                self.server_peer,
                self.team.registration_pubkey_bytes,
            )
            result = await self.overlay.wait_for_registration_result(
                self.settings.request_retry_interval
            )
            if result is None:
                continue
            LOGGER.info("Registration response: %s", result.message)
            if result.success:
                return result.group_id
            raise RuntimeError(result.message)
        raise TimeoutError("Timed out registering Lab 2 group")

    async def _send_group_ready(self, group_id: str) -> None:
        missing = {
            member.pubkey_hex
            for member in self.team.teammates(self.local_member.pubkey_hex)
        }
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.settings.group_ready_timeout
        while missing and loop.time() < deadline:
            for pubkey_hex in list(missing):
                self.udp.send(
                    pubkey_hex, UDP_GROUP_READY, build_group_ready_body(group_id)
                )
            message = await self.udp.wait_for(
                lambda msg: (
                    msg.message_id == UDP_ACK
                    and msg.sender_pubkey_hex in missing
                    and body_int(msg.body, "ack_message_id") == UDP_GROUP_READY
                ),
                timeout=self.settings.request_retry_interval,
            )
            if message is not None:
                missing.discard(message.sender_pubkey_hex)
        if missing:
            raise TimeoutError("Timed out waiting for GroupReady ACKs")

    async def _wait_for_group_ready(self) -> str:
        node_a = self.team.members[0]
        message = await self.udp.wait_for(
            lambda msg: (
                msg.message_id == UDP_GROUP_READY
                and msg.sender_pubkey_hex == node_a.pubkey_hex
            ),
            timeout=self.settings.group_ready_timeout,
        )
        if message is None:
            raise TimeoutError("Timed out waiting for GroupReady from Node A")
        group_id = body_str(message.body, "group_id")
        self.udp.send(
            node_a.pubkey_hex,
            UDP_ACK,
            build_ack_body(UDP_GROUP_READY),
        )
        LOGGER.info("Group ready: %s", group_id)
        return group_id

    async def _follow_round(self, round_number: int) -> None:
        leader = self.team.submitter_for_round(round_number)
        while True:
            message = await self.udp.receive(timeout=self.settings.round_timeout)
            if message is None:
                raise TimeoutError(f"Timed out waiting for round {round_number} nonce")
            if self._handle_common_message(message):
                continue
            if (
                message.message_id == UDP_NONCE_BROADCAST
                and message.sender_pubkey_hex == leader.pubkey_hex
                and body_int(message.body, "round_number") == round_number
            ):
                self._reply_to_nonce_broadcast(message)
                return

    async def _wait_for_baton_or_fallback(self, expected_round: int) -> None:
        previous_leader = self.team.submitter_for_round(expected_round - 1)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.settings.baton_timeout
        while loop.time() < deadline:
            message = await self.udp.receive(timeout=max(0.0, deadline - loop.time()))
            if message is None:
                break
            if message.message_id == UDP_GROUP_READY and self._handle_common_message(
                message
            ):
                continue
            if message.message_id == UDP_NONCE_BROADCAST:
                self._reply_to_nonce_broadcast(message)
                continue
            if (
                message.message_id == UDP_BATON_PASS
                and message.sender_pubkey_hex == previous_leader.pubkey_hex
                and body_int(message.body, "next_round_number") == expected_round
            ):
                self.udp.send(
                    previous_leader.pubkey_hex,
                    UDP_ACK,
                    build_ack_body(UDP_BATON_PASS, expected_round),
                )
                return

        LOGGER.warning("Baton missing for round %d; polling server", expected_round)
        await self._request_challenge_until(expected_round)

    async def _lead_round(self, round_number: int) -> RoundResult | None:
        challenge = await self._request_challenge_until(round_number)
        local_signature = sign_bytes(self.private_key, challenge.nonce)
        signatures = {self.local_member.pubkey_hex: local_signature}
        missing = {
            member.pubkey_hex
            for member in self.team.members
            if member.pubkey_hex != self.local_member.pubkey_hex
        }
        nonce_body = build_nonce_broadcast_body(round_number, challenge.nonce)

        while missing:
            for pubkey_hex in list(missing):
                self.udp.send(pubkey_hex, UDP_NONCE_BROADCAST, nonce_body)
            message = await self.udp.receive(
                timeout=self.settings.signature_retry_interval
            )
            if message is None:
                continue
            if self._handle_common_message(message):
                continue
            if (
                message.message_id == UDP_SIGNATURE_REPLY
                and message.sender_pubkey_hex in missing
                and body_int(message.body, "round_number") == round_number
            ):
                signature = body_bytes(message.body, "signature_hex")
                if verify_signature(
                    message.sender_pubkey_hex,
                    challenge.nonce,
                    signature,
                ):
                    signatures[message.sender_pubkey_hex] = signature
                    missing.remove(message.sender_pubkey_hex)
                else:
                    LOGGER.warning(
                        "Ignoring invalid nonce signature from %s",
                        message.sender_pubkey_hex[:16],
                    )
            elif message.message_id == UDP_NONCE_BROADCAST:
                self._reply_to_nonce_broadcast(message)

        ordered = build_ordered_signature_list(self.team, signatures)
        self.overlay.send_signature_bundle(
            self.server_peer,
            self._group_id,
            round_number,
            ordered,
        )

        baton_task = None
        if round_number < 3:
            next_member = self.team.submitter_for_round(round_number + 1)
            baton_task = asyncio.create_task(
                self._send_baton(next_member.pubkey_hex, round_number + 1)
            )

        result = await self.overlay.wait_for_round_result(2.0)
        if result is not None:
            LOGGER.info("Round result: %s", result.message)
        if baton_task is not None:
            await baton_task
        return result

    async def _send_baton(self, target_pubkey_hex: str, next_round_number: int) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.settings.baton_timeout
        body = build_baton_pass_body(next_round_number, self._group_id)
        while loop.time() < deadline:
            self.udp.send(target_pubkey_hex, UDP_BATON_PASS, body)
            message = await self.udp.wait_for(
                lambda msg: (
                    msg.message_id == UDP_ACK
                    and msg.sender_pubkey_hex == target_pubkey_hex
                    and body_int(msg.body, "ack_message_id") == UDP_BATON_PASS
                    and body_int(msg.body, "round_number") == next_round_number
                ),
                timeout=self.settings.signature_retry_interval,
            )
            if message is not None:
                return
        LOGGER.warning("No ACK for BatonPass to %s", target_pubkey_hex[:16])

    async def _request_challenge_until(self, expected_round: int) -> Challenge:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.settings.round_timeout
        while loop.time() < deadline:
            self.overlay.send_challenge_request(self.server_peer, self._group_id)
            challenge = await self.overlay.wait_for_challenge(
                self.settings.request_retry_interval
            )
            if challenge is None:
                continue
            if challenge.round_number == expected_round:
                LOGGER.info(
                    "Received round %d challenge; deadline %.3f",
                    challenge.round_number,
                    challenge.deadline,
                )
                return challenge
            LOGGER.info(
                "Server returned round %d while waiting for round %d",
                challenge.round_number,
                expected_round,
            )
        raise TimeoutError(f"Timed out waiting for round {expected_round} challenge")

    def _reply_to_nonce_broadcast(self, message) -> None:
        round_number = body_int(message.body, "round_number")
        leader = self.team.submitter_for_round(round_number)
        if message.sender_pubkey_hex != leader.pubkey_hex:
            return
        nonce = body_bytes(message.body, "nonce_hex")
        cached = self.signed_rounds.get(round_number)
        if cached is None or cached[0] != nonce:
            signature = sign_bytes(self.private_key, nonce)
            self.signed_rounds[round_number] = (nonce, signature)
        else:
            signature = cached[1]
        self.udp.send(
            leader.pubkey_hex,
            UDP_SIGNATURE_REPLY,
            build_signature_reply_body(round_number, signature),
        )

    def _handle_common_message(self, message) -> bool:
        node_a = self.team.members[0]
        if (
            message.message_id == UDP_GROUP_READY
            and message.sender_pubkey_hex == node_a.pubkey_hex
        ):
            self.group_id = body_str(message.body, "group_id")
            self.udp.send(node_a.pubkey_hex, UDP_ACK, build_ack_body(UDP_GROUP_READY))
            return True

        if self.local_round > 1 and message.message_id == UDP_BATON_PASS:
            previous_leader = self.team.submitter_for_round(self.local_round - 1)
            if (
                message.sender_pubkey_hex == previous_leader.pubkey_hex
                and body_int(message.body, "next_round_number") == self.local_round
            ):
                self.udp.send(
                    previous_leader.pubkey_hex,
                    UDP_ACK,
                    build_ack_body(UDP_BATON_PASS, self.local_round),
                )
                return True

        return False

    @property
    def _group_id(self) -> str:
        if self.group_id is None:
            raise RuntimeError("Group is not ready")
        return self.group_id
