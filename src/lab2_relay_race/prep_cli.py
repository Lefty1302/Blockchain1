"""CLI entrypoint for Lab 2 prep phase (UDP coordination)."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .keyutil import (
    extract_public_key_hex,
    fmt_peer,
    load_pubkey_name_map,
)
from .team import TeamConfig, load_team_config
from .udp_prep import (
    UdpPrepServer,
    PeerEndpoint,
    get_primary_outbound_ip,
    send_ping,
    announce_endpoint,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lab 2: UDP discovery test")
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
        "--team-config",
        default="lab2_team.json",
        help="Lab 2 team config with explicit A/B/C role order",
    )
    parser.add_argument(
        "--udp-port",
        type=int,
        required=False,
        help="Local UDP port for team communication",
    )
    parser.add_argument(
        "--peer-pubkey",
        action="append",
        dest="peer_pubkeys",
        default=[],
        help="Public key hex of a teammate from the team config; can be repeated",
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

    parser.add_argument(
        "--timeout",
        type=int,
        required=False,
        help="Seconds to timeout after (default is 300s = 5 min)",
    )
    return parser.parse_args()


async def run_prep_phase(
    local_pubkey: str,
    local_port: int,
    peers: list[PeerEndpoint],
    test_udp: bool,
    timeout: int,
    name_map: dict[str, str],
    team_config: TeamConfig,
    auto_discover: bool = False,
    teammate_pubkeys: list[str] | None = None,
    key_file: str = "lab1_identity.pem",
) -> int:
    """
    Run the prep phase:
    1. If auto_discover: use IPv8 to discover teammate endpoints, then start UDP listener.
    2. Otherwise: start UDP listener directly.
    3. Announce endpoint to peers.
    4. Optionally run UDP connectivity test.
    5. Report configured role order and peer map.
    """
    if auto_discover:
        if not teammate_pubkeys:
            LOGGER.error("--auto-discover requires --peer-pubkey arguments")
            return 1

    server = UdpPrepServer(local_port, local_pubkey)
    await server.start()
    if auto_discover:
        assert teammate_pubkeys is not None
        # Use IPv8 discovery to get teammate endpoints
        from lab1_pow_ipv8.libsodium_bootstrap import ensure_libsodium
        from .community import build_lab2_community
        from ipv8.configuration import (
            ConfigBuilder,
            Strategy,
            WalkerDefinition,
            default_bootstrap_defs,
        )
        from ipv8_service import IPv8

        ensure_libsodium()
        LOGGER.info("Starting IPv8 discovery for teammate endpoints...")

        Lab2Community = build_lab2_community()
        builder = ConfigBuilder().clear_keys().clear_overlays()
        builder.add_key("lab2", "curve25519", key_file)
        builder.add_overlay(
            "Lab2Community",
            "lab2",
            [WalkerDefinition(Strategy.RandomWalk, 30, {"timeout": 3.0})],
            default_bootstrap_defs,
            {},
            [("started",)],
        )

        ipv8 = IPv8(
            builder.finalize(),
            extra_communities={"Lab2Community": Lab2Community},
        )
        await ipv8.start()

        try:
            overlay = next(o for o in ipv8.overlays if isinstance(o, Lab2Community))
            local_ip = get_primary_outbound_ip()
            overlay.set_local_endpoint(local_ip, local_port)

            # Convert teammate pubkey strings to bytes
            teammate_pubkeys_bin = [bytes.fromhex(pk) for pk in teammate_pubkeys]
            overlay.set_target_pubkeys(teammate_pubkeys_bin)

            LOGGER.info(
                f"Waiting for {len(teammate_pubkeys_bin)} teammate(s) to announce endpoints..."
            )
            discovered_endpoints = await overlay.wait_for_endpoints(
                teammate_pubkeys_bin, timeout=float(timeout)
            )

            discovered_peers: dict[str, PeerEndpoint] = {}
            while len(discovered_peers) < len(teammate_pubkeys_bin):
                discovered_endpoints = await overlay.wait_for_endpoints(
                    teammate_pubkeys_bin, timeout=300.0
                )
                new_peers: list[PeerEndpoint] = []
                for pubkey_hex in teammate_pubkeys:
                    pubkey_bin = bytes.fromhex(pubkey_hex)
                    if (
                        pubkey_bin in discovered_endpoints
                        and pubkey_hex not in discovered_peers
                    ):
                        host, port = discovered_endpoints[pubkey_bin]
                        peer = PeerEndpoint(pubkey_hex, host, port)
                        discovered_peers[pubkey_hex] = peer
                        new_peers.append(peer)
                        LOGGER.info(
                            "Discovered %s... @ %s:%s",
                            pubkey_hex[:16],
                            host,
                            port,
                        )

            # Convert discovered endpoints to PeerEndpoint objects
            peers = []
            for pubkey_hex in teammate_pubkeys:
                pubkey_bin = bytes.fromhex(pubkey_hex)
                if pubkey_bin in discovered_endpoints:
                    host, port = discovered_endpoints[pubkey_bin]
                    peers.append(PeerEndpoint(pubkey_hex, host, port))
                    LOGGER.info(
                        f"Discovered {fmt_peer(pubkey_hex, name_map)} @ {host}:{port}"
                    )
                else:
                    LOGGER.error(
                        f"Failed to discover endpoint for {fmt_peer(pubkey_hex, name_map)}"
                    )

                if len(discovered_peers) < len(teammate_pubkeys_bin):
                    remaining = len(teammate_pubkeys_bin) - len(discovered_peers)
                    LOGGER.info("Waiting on %d more teammate endpoint(s)...", remaining)
                    await asyncio.sleep(1.0)

            peers = list(discovered_peers.values())

        finally:
            await ipv8.stop()

    try:
        # Announce our endpoint to all known peers
        LOGGER.info(f"Announcing endpoint to {len(peers)} peer(s)")
        await announce_endpoint(
            get_primary_outbound_ip(),
            local_port,
            peers,
            local_pubkey,
        )

        if test_udp:
            LOGGER.info("Running UDP connectivity test (ping/pong)...")
            await run_udp_test(server, peers, local_pubkey, name_map)

        LOGGER.info("=" * 60)
        LOGGER.info("Prep Phase Complete")
        LOGGER.info("=" * 60)
        LOGGER.info(f"Local pubkey: {fmt_peer(local_pubkey, name_map)}")
        LOGGER.info("Configured order (submitter per round):")
        for round_number, member in enumerate(team_config.members, 1):
            is_me = " <- YOU" if member.pubkey_hex == local_pubkey else ""
            LOGGER.info(
                "  Round %d / Node %s: %s%s",
                round_number,
                member.role,
                fmt_peer(member.pubkey_hex, name_map),
                is_me,
            )

        LOGGER.info("\nPeer map:")
        for peer in peers:
            LOGGER.info(
                f"  {fmt_peer(peer.pubkey_hex, name_map)} -> {peer.host}:{peer.port}"
            )
        LOGGER.info("=" * 60)

        return 0

    finally:
        await server.stop()


async def run_udp_test(
    server: UdpPrepServer,
    peers: list[PeerEndpoint],
    local_pubkey: str,
    name_map: dict[str, str],
) -> None:
    """Test UDP connectivity by sending pings to all peers."""
    if not peers:
        LOGGER.warning("No peers provided for UDP test")
        return

    # Send pings
    tasks = [send_ping(p.host, p.port, local_pubkey) for p in peers]
    results = await asyncio.gather(*tasks)

    # Wait for responses
    timeout = 2.0
    responses = []
    for peer in peers:
        got_response = await server.wait_for_pong(peer.pubkey_hex, timeout=timeout)
        if got_response:
            LOGGER.info(f"OK {fmt_peer(peer.pubkey_hex, name_map)} responded")
            responses.append(True)
        else:
            LOGGER.warning(
                f"FAIL {fmt_peer(peer.pubkey_hex, name_map)} no response (timeout {timeout}s)"
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
    logging.getLogger("ipv8.community").setLevel(logging.CRITICAL)
    globals()["LOGGER"] = logging.getLogger("lab2_prep")

    name_map = load_pubkey_name_map()
    timeout = 300 if args.timeout is None else args.timeout

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

    # Load local public key
    try:
        local_pubkey = extract_public_key_hex(args.pem)
        LOGGER.info(f"Local public key: {fmt_peer(local_pubkey, name_map)}")
    except Exception as exc:
        print(f"Error loading public key: {exc}", file=sys.stderr)
        return 1

    try:
        team_config = load_team_config(args.team_config)
        local_member = team_config.local_member(local_pubkey)
        LOGGER.info(
            "Local Lab 2 role: Node %s (%s)", local_member.role, local_member.name
        )
    except Exception as exc:
        print(f"Error loading team config: {exc}", file=sys.stderr)
        return 1

    # Default to auto-discovery unless manual --peer is provided.
    auto_discover = len(args.peers) == 0
    expected_teammates = [
        member.pubkey_hex for member in team_config.teammates(local_pubkey)
    ]
    if args.peer_pubkeys:
        if not (1 <= len(args.peer_pubkeys) <= 2):
            print("Error: pass 1 or 2 --peer-pubkey values", file=sys.stderr)
            return 1
    else:
        args.peer_pubkeys = expected_teammates

    if not set(args.peer_pubkeys).issubset(set(expected_teammates)):
        print(
            "Error: --peer-pubkey values must be teammates from the team config",
            file=sys.stderr,
        )
        return 1

    if not auto_discover and len(args.peers) != len(args.peer_pubkeys):
        print(
            f"Error: --peer and --peer-pubkey must have the same count "
            f"({len(args.peers)} vs {len(args.peer_pubkeys)})",
            file=sys.stderr,
        )
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

    # Run prep phase
    try:
        return asyncio.run(
            asyncio.wait_for(
                run_prep_phase(
                    local_pubkey,
                    args.udp_port,
                    peers,
                    test_udp=args.test_udp,
                    timeout=timeout,
                    name_map=name_map,
                    team_config=team_config,
                    auto_discover=auto_discover,
                    teammate_pubkeys=args.peer_pubkeys if auto_discover else None,
                    key_file=args.pem,
                ),
                timeout=timeout,
            )
        )
    except asyncio.TimeoutError:
        print(f"Error: timed out after {timeout}s", file=sys.stderr)
        return 1
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
