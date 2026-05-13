"""UDP coordination prep phase for Lab 2 group signing."""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from dataclasses import dataclass
from typing import Optional

LOGGER = logging.getLogger("lab2_udp_prep")


def get_primary_outbound_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no traffic sent, just route lookup
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


@dataclass
class PeerEndpoint:
    """A teammate's UDP endpoint."""

    pubkey_hex: str
    host: str
    port: int

    def __str__(self) -> str:
        return f"{self.pubkey_hex[:8]}... @ {self.host}:{self.port}"


@dataclass
class PrepPhaseConfig:
    """Configuration for the prep phase."""

    local_port: int
    local_pubkey_hex: str
    peers: dict[str, PeerEndpoint]  # pubkey_hex -> PeerEndpoint
    timeout_seconds: float = 2.0


class UdpPrepServer:
    """
    UDP listener for receiving prep messages (pings, pongs, hellos).
    """

    def __init__(self, local_port: int, local_pubkey_hex: str):
        self.local_port = local_port
        self.local_pubkey_hex = local_pubkey_hex
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional[asyncio.DatagramProtocol] = None
        self.responses: dict[str, dict] = {}  # sender_pubkey -> latest response data
        self.response_events: dict[str, asyncio.Event] = {}  # sender_pubkey -> event

    async def start(self) -> None:
        """Start listening on the UDP port."""
        loop = asyncio.get_event_loop()
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: self._make_protocol(),
            local_addr=("0.0.0.0", self.local_port),
        )
        LOGGER.info(f"UDP listener started on port {self.local_port}")

    async def stop(self) -> None:
        """Stop the UDP listener."""
        if self.transport:
            self.transport.close()
        LOGGER.info("UDP listener stopped")

    def _make_protocol(self) -> asyncio.DatagramProtocol:
        """Create a minimal UDP protocol handler."""
        server = self

        class MinimalProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                try:
                    msg = json.loads(data.decode("utf-8"))
                    server._handle_message(msg, addr)
                except Exception as exc:
                    LOGGER.warning(f"Failed to parse UDP message from {addr}: {exc}")

            def connection_lost(self, exc: Optional[Exception]) -> None:
                if exc:
                    LOGGER.error(f"UDP connection lost: {exc}")

        return MinimalProtocol()

    def _handle_message(self, msg: dict, addr: tuple[str, int]) -> None:
        """Handle incoming UDP message."""
        msg_type = msg.get("type")
        sender_pubkey = msg.get("pubkey")

        if not sender_pubkey:
            LOGGER.debug(f"Ignoring message with no pubkey from {addr}")
            return

        if msg_type == "ping":
            self._handle_ping(msg, addr, sender_pubkey)
        elif msg_type == "pong":
            self._handle_pong(msg, sender_pubkey)
        elif msg_type == "hello":
            self._handle_hello(msg, sender_pubkey)
        else:
            LOGGER.debug(f"Unknown message type: {msg_type}")

    def _handle_ping(
        self, msg: dict, addr: tuple[str, int], sender_pubkey: str
    ) -> None:
        """Reply to a ping with pong."""
        LOGGER.debug(f"Received PING from {sender_pubkey[:8]}... ({addr[0]}:{addr[1]})")

        pong_msg = {
            "type": "pong",
            "pubkey": self.local_pubkey_hex,
            "timestamp": asyncio.get_event_loop().time(),
        }
        pong_data = json.dumps(pong_msg).encode("utf-8")

        if self.transport:
            self.transport.sendto(pong_data, addr)

    def _handle_pong(self, msg: dict, sender_pubkey: str) -> None:
        """Record a pong response."""
        LOGGER.debug(f"Received PONG from {sender_pubkey[:8]}...")

        self.responses[sender_pubkey] = msg
        if sender_pubkey not in self.response_events:
            self.response_events[sender_pubkey] = asyncio.Event()
        self.response_events[sender_pubkey].set()

    def _handle_hello(self, msg: dict, sender_pubkey: str) -> None:
        """Record a hello (endpoint announcement)."""
        host = msg.get("host")
        port = msg.get("port")
        LOGGER.debug(f"Received HELLO from {sender_pubkey[:8]}... ({host}:{port})")

        self.responses[sender_pubkey] = msg
        if sender_pubkey not in self.response_events:
            self.response_events[sender_pubkey] = asyncio.Event()
        self.response_events[sender_pubkey].set()

    async def wait_for_pong(self, pubkey: str, timeout: Optional[float] = None) -> bool:
        """Wait for a pong from a specific peer."""
        if timeout is None:
            timeout = 2.0

        if pubkey not in self.response_events:
            self.response_events[pubkey] = asyncio.Event()

        try:
            await asyncio.wait_for(
                self.response_events[pubkey].wait(),
                timeout=timeout,
            )
            return True
        except asyncio.TimeoutError:
            return False


async def send_ping(host: str, port: int, local_pubkey_hex: str) -> bool:
    """Send a single UDP ping and return True if we get a response."""
    try:
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            remote_addr=(host, port),
        )

        ping_msg = {
            "type": "ping",
            "pubkey": local_pubkey_hex,
            "timestamp": loop.time(),
        }
        ping_data = json.dumps(ping_msg).encode("utf-8")
        transport.sendto(ping_data)

        # Wait a bit for response (handled by main server)
        await asyncio.sleep(0.1)
        transport.close()
        return True
    except Exception as exc:
        LOGGER.debug(f"Failed to send ping to {host}:{port}: {exc}")
        return False


async def ensure_udp_connectivity(
    server: UdpPrepServer,
    peers: list[PeerEndpoint],
    local_pubkey_hex: str,
    *,
    retry_interval: float = 2.0,
    ping_timeout: float = 2.0,
) -> None:
    """Keep pinging peers until all respond at least once."""
    pending: dict[str, PeerEndpoint] = {p.pubkey_hex: p for p in peers}
    attempt = 0

    while pending:
        attempt += 1
        LOGGER.info(
            "UDP connectivity attempt %d: waiting on %d peer(s)",
            attempt,
            len(pending),
        )

        # Send pings to peers still pending
        await asyncio.gather(
            *[
                send_ping(peer.host, peer.port, local_pubkey_hex)
                for peer in pending.values()
            ]
        )

        # Wait for pongs (bounded by ping_timeout)
        results = await asyncio.gather(
            *[
                server.wait_for_pong(peer.pubkey_hex, timeout=ping_timeout)
                for peer in pending.values()
            ]
        )

        responded = [
            peer_key for peer_key, ok in zip(list(pending.keys()), results) if ok
        ]

        for key in responded:
            peer = pending.pop(key, None)
            if peer:
                LOGGER.info("✓ %s responded", peer.pubkey_hex[:16] + "...")

        if pending:
            waiting = ", ".join([k[:16] + "..." for k in pending.keys()])
            LOGGER.warning("Still waiting on %d peer(s): %s", len(pending), waiting)
            await asyncio.sleep(retry_interval)


async def announce_endpoint(
    host: str,
    port: int,
    peers: list[PeerEndpoint],
    local_pubkey_hex: str,
) -> None:
    """Announce this node's UDP endpoint to all peers."""
    hello_msg = {
        "type": "hello",
        "pubkey": local_pubkey_hex,
        "host": host,
        "port": port,
        "timestamp": asyncio.get_event_loop().time(),
    }
    hello_data = json.dumps(hello_msg).encode("utf-8")

    for peer in peers:
        try:
            loop = asyncio.get_event_loop()
            transport, _ = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol,
                remote_addr=(peer.host, peer.port),
            )
            transport.sendto(hello_data)
            transport.close()
            LOGGER.info(f"Announced endpoint to {peer}")
        except Exception as exc:
            LOGGER.warning(f"Failed to announce endpoint to {peer}: {exc}")


def compute_canonical_order(pubkeys: list[str]) -> list[str]:
    """
    Sort public keys lexicographically (bytewise).

    Returns the canonical order: [pubkey1, pubkey2, pubkey3].
    This order is used to determine submitter assignment per round.
    """
    # Convert hex to bytes for bytewise comparison, or use string as-is if not valid hex
    pubkey_bytes = []
    for pk in pubkeys:
        try:
            pubkey_bytes.append((pk, bytes.fromhex(pk)))
        except ValueError:
            # Not valid hex; treat as ASCII string for comparison
            pubkey_bytes.append((pk, pk.encode("utf-8")))

    pubkey_bytes.sort(key=lambda x: x[1])
    return [pk for pk, _ in pubkey_bytes]


def get_submitter_for_round(
    canonical_order: list[str],
    round_number: int,  # 1, 2, or 3
) -> str:
    """
    Get the designated submitter's public key for a given round.

    Round 1 -> canonical_order[0]
    Round 2 -> canonical_order[1]
    Round 3 -> canonical_order[2]
    """
    if round_number < 1 or round_number > 3:
        raise ValueError(f"round_number must be 1-3, got {round_number}")
    return canonical_order[round_number - 1]
