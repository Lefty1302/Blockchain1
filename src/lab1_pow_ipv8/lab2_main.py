"""CLI entrypoint for Lab 2 prep phase (UDP coordination)."""

from __future__ import annotations

import argparse
import asyncio
import logging
import socket
import sys

from .lab2_keyutil import extract_public_key_hex
from .lab2_udp_prep import (
    UdpPrepServer,
    PeerEndpoint,
    compute_canonical_order,
    send_ping,
    announce_endpoint,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lab 2: Coordinated Group Signing Prep Phase"
    )
    parser.add_argument(
        "--print-pubkey",
        action="store_true",
        help="Extract and print public key from PEM file, then exit",
    )
    parser.add_argument(
        "--pem",
        default="lab1_identity.pem",
        help="PEM file path for your IPv8 private key (default: lab1_identity.pem)",
    )
    parser.add_argument(
        "--udp-port",
        type=int,
        required=False,
        help="Local UDP port for team communication",
    )
    parser.add_argument(
        "--udp-host",
        default=None,
        help=(
            "Host/IP to advertise for UDP coordination "
            "(default: auto-detect a local LAN IPv4 address)"
        ),
    )
    parser.add_argument(
        "--peer-pubkey",
        action="append",
        dest="peer_pubkeys",
        default=[],
        help=(
            "Public key hex of a teammate (repeat once per teammate; "
            "1 allowed for two-person testing, 2 for the full group)"
        ),
    )
    parser.add_argument(
        "--peer",
        action="append",
        dest="peers",
        default=[],
        help="(Optional) Teammate endpoint as host:port for manual mode (bypasses IPv8 discovery)",
    )
    parser.add_argument(
        "--test-udp",
        action="store_true",
        help="Run UDP connectivity test after prep (ping/pong)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


def validate_peer_args(
    auto_discover: bool,
    peers: list[str],
    peer_pubkeys: list[str],
) -> str | None:
    """Return an error message if peer CLI arguments are inconsistent."""
    if auto_discover:
        if not peer_pubkeys or len(peer_pubkeys) not in (1, 2):
            return (
                "Error: provide 1 --peer-pubkey for two-person testing, "
                "or 2 --peer-pubkey values for the full group"
            )
    elif len(peers) != len(peer_pubkeys):
        return (
            "Error: --peer and --peer-pubkey must have the same count "
            f"({len(peers)} vs {len(peer_pubkeys)})"
        )

    if len(set(peer_pubkeys)) != len(peer_pubkeys):
        return (
            "Error: duplicate --peer-pubkey values are not useful; pass each "
            "teammate key once"
        )

    return None


def detect_udp_host() -> str:
    """Best-effort local IPv4 address to advertise to teammates."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            host = sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"

    return host or "127.0.0.1"


async def run_prep_phase(
    local_pubkey: str,
    local_host: str,
    local_port: int,
    peers: list[PeerEndpoint],
    test_udp: bool,
    auto_discover: bool = False,
    teammate_pubkeys: list[str] | None = None,
    key_file: str = "lab1_identity.pem",
) -> int:
    """
    Run the prep phase:
    1. Start the UDP listener so peers can ping us whenever they are ready.
    2. If auto_discover: use IPv8 to discover teammate UDP endpoints.
    3. Announce endpoint to peers.
    4. Optionally run UDP connectivity test.
    5. Report canonical order and peer map.
    """
    server = UdpPrepServer(local_port, local_pubkey)
    await server.start()

    try:
        if auto_discover:
            if not teammate_pubkeys:
                LOGGER.error("--auto-discover requires --peer-pubkey arguments")
                return 1

            # Use IPv8 discovery to get teammate endpoints
            from .libsodium_bootstrap import ensure_libsodium
            from .lab2_discovery import build_lab2_discovery_community
            from ipv8.configuration import (
                ConfigBuilder,
                Strategy,
                WalkerDefinition,
                default_bootstrap_defs,
            )
            from ipv8_service import IPv8

            ensure_libsodium()
            LOGGER.info("Starting IPv8 discovery for teammate endpoints...")

            Lab2DiscoveryCommunity = build_lab2_discovery_community()
            builder = ConfigBuilder().clear_keys().clear_overlays()
            builder.add_key("lab2", "curve25519", key_file)
            builder.add_overlay(
                "Lab2DiscoveryCommunity",
                "lab2",
                [WalkerDefinition(Strategy.RandomWalk, 30, {"timeout": 3.0})],
                default_bootstrap_defs,
                {},
                [("started",)],
            )

            ipv8 = IPv8(
                builder.finalize(),
                extra_communities={"Lab2DiscoveryCommunity": Lab2DiscoveryCommunity},
            )
            await ipv8.start()

            try:
                overlay = next(
                    o for o in ipv8.overlays if isinstance(o, Lab2DiscoveryCommunity)
                )
                overlay.set_local_endpoint(local_host, local_port)

                # Convert teammate pubkey strings to bytes
                teammate_pubkeys_bin = [bytes.fromhex(pk) for pk in teammate_pubkeys]

                # Request endpoints from teammates
                LOGGER.info(
                    f"Waiting for {len(teammate_pubkeys_bin)} teammate(s) to announce endpoints..."
                )
                discovered_endpoints = await overlay.wait_for_endpoints(
                    teammate_pubkeys_bin, timeout=10.0
                )

                if len(discovered_endpoints) < len(teammate_pubkeys_bin):
                    LOGGER.warning(
                        f"Only discovered {len(discovered_endpoints)}/{len(teammate_pubkeys_bin)} endpoints"
                    )

                # Convert discovered endpoints to PeerEndpoint objects
                peers = []
                missing_pubkeys = []
                for pubkey_hex in teammate_pubkeys:
                    pubkey_bin = bytes.fromhex(pubkey_hex)
                    if pubkey_bin in discovered_endpoints:
                        host, port = discovered_endpoints[pubkey_bin]
                        peers.append(PeerEndpoint(pubkey_hex, host, port))
                        LOGGER.info(f"Discovered {pubkey_hex[:16]}... @ {host}:{port}")
                    else:
                        missing_pubkeys.append(pubkey_hex)

                for pubkey_hex in missing_pubkeys:
                    LOGGER.warning(
                        "Failed to discover endpoint for %s...; skipping UDP packets "
                        "to that peer",
                        pubkey_hex[:16],
                    )

                if not peers:
                    LOGGER.error(
                        "No peer endpoints discovered; cannot send UDP packets"
                    )
                    return 1

            finally:
                await ipv8.stop()

        # Announce our endpoint to all known peers
        LOGGER.info(f"Announcing endpoint to {len(peers)} peer(s)")
        await announce_endpoint(
            local_host,
            local_port,
            peers,
            local_pubkey,
        )

        if test_udp:
            LOGGER.info("Running UDP connectivity test (ping/pong)...")
            await run_udp_test(server, peers, local_pubkey)

        # Compute canonical order (lexicographic by pubkey)
        all_pubkeys = [local_pubkey] + [p.pubkey_hex for p in peers]
        canonical_order = compute_canonical_order(all_pubkeys)
        full_group = len(canonical_order) == 3

        if not full_group:
            LOGGER.warning(
                "Two-person test mode: canonical order contains %d participant(s); "
                "the full Lab 2 flow still requires 3 registered keys",
                len(canonical_order),
            )

        LOGGER.info("=" * 60)
        LOGGER.info("Prep Phase Complete")
        LOGGER.info("=" * 60)
        LOGGER.info(f"Local pubkey: {local_pubkey[:16]}...")
        if full_group:
            LOGGER.info("Canonical order (submitter per round):")
        else:
            LOGGER.info("Canonical order (available participants):")
        for i, pk in enumerate(canonical_order, 1):
            label = f"Round {i}" if full_group else f"Participant {i}"
            is_me = " <- YOU" if pk == local_pubkey else ""
            LOGGER.info(f"  {label}: {pk[:16]}...{is_me}")

        LOGGER.info("\nPeer map:")
        for peer in peers:
            LOGGER.info(f"  {peer.pubkey_hex[:16]}... -> {peer.host}:{peer.port}")
        LOGGER.info("=" * 60)

        return 0

    finally:
        await server.stop()


async def run_udp_test(
    server: UdpPrepServer,
    peers: list[PeerEndpoint],
    local_pubkey: str,
) -> None:
    """Test UDP connectivity by sending pings to all peers."""
    LOGGER.info(f"Pinging {len(peers)} peer(s)...")

    # Send pings
    tasks = [send_ping(p.host, p.port, local_pubkey) for p in peers]
    results = await asyncio.gather(*tasks)

    # Wait for responses
    timeout = 2.0
    responses = []
    for peer in peers:
        got_response = await server.wait_for_pong(peer.pubkey_hex, timeout=timeout)
        if got_response:
            LOGGER.info(f"✓ {peer.pubkey_hex[:16]}... responded")
            responses.append(True)
        else:
            LOGGER.warning(
                f"✗ {peer.pubkey_hex[:16]}... no response (timeout {timeout}s)"
            )
            responses.append(False)

    success_count = sum(responses)
    total_count = len(peers)
    LOGGER.info(f"UDP test: {success_count}/{total_count} peers reachable")


def main() -> int:
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    globals()["LOGGER"] = logging.getLogger("lab2_prep")

    # Handle --print-pubkey
    if args.print_pubkey:
        try:
            pubkey = extract_public_key_hex(args.pem)
            print(pubkey)
            return 0
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    # For full prep, --udp-port is required
    if args.udp_port is None:
        print("Error: --udp-port is required", file=sys.stderr)
        return 1

    # Default to auto-discovery unless manual --peer is provided
    auto_discover = len(args.peers) == 0

    peer_args_error = validate_peer_args(
        auto_discover,
        args.peers,
        args.peer_pubkeys,
    )
    if peer_args_error:
        print(peer_args_error, file=sys.stderr)
        return 1

    # Load local public key
    try:
        local_pubkey = extract_public_key_hex(args.pem)
        LOGGER.info(f"Local public key: {local_pubkey[:16]}...")
    except Exception as exc:
        print(f"Error loading public key: {exc}", file=sys.stderr)
        return 1

    # Parse peer endpoints (manual mode only)
    peers = []
    if not auto_discover:
        for endpoint_str, pubkey_hex in zip(args.peers, args.peer_pubkeys):
            if ":" not in endpoint_str:
                print(
                    f"Error: peer endpoint must be 'host:port', got '{endpoint_str}'",
                    file=sys.stderr,
                )
                return 1
            host, port_str = endpoint_str.rsplit(":", 1)
            try:
                port = int(port_str)
                peers.append(PeerEndpoint(pubkey_hex, host, port))
            except ValueError:
                print(f"Error: invalid port '{port_str}'", file=sys.stderr)
                return 1

    local_host = args.udp_host or detect_udp_host()
    LOGGER.info(f"Advertising UDP endpoint as {local_host}:{args.udp_port}")

    # Run prep phase
    try:
        return asyncio.run(
            run_prep_phase(
                local_pubkey,
                local_host,
                args.udp_port,
                peers,
                test_udp=args.test_udp,
                auto_discover=auto_discover,
                teammate_pubkeys=args.peer_pubkeys if auto_discover else None,
                key_file=args.pem,
            )
        )
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


# Global logger reference (set in main)
LOGGER = logging.getLogger("lab2_prep")


if __name__ == "__main__":
    raise SystemExit(main())
