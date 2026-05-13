"""CLI entrypoint for the Lab 2 relay race."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .race import RaceSettings, run_relay_race
from .team import load_team_config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lab 2: Relay race client")
    parser.add_argument(
        "--pem",
        default="lab1_identity.pem",
        help="PEM file path for your IPv8 private key",
    )
    parser.add_argument(
        "--team-config",
        default="lab2_team.json",
        help="Lab 2 team config with explicit A/B/C role order",
    )
    parser.add_argument(
        "--udp-port",
        type=int,
        required=True,
        help="Local UDP port for teammate relay traffic",
    )
    parser.add_argument(
        "--discovery-timeout",
        type=float,
        default=300.0,
        help="Seconds to wait for teammate endpoint discovery",
    )
    parser.add_argument(
        "--server-timeout",
        type=float,
        default=30.0,
        help="Seconds to wait for Lab 2 server discovery",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logging.getLogger("ipv8.community").setLevel(logging.CRITICAL)

    try:
        team_config = load_team_config(args.team_config)
        outcome = asyncio.run(
            run_relay_race(
                RaceSettings(
                    key_file=args.pem,
                    udp_port=args.udp_port,
                    team_config=team_config,
                    discovery_timeout=args.discovery_timeout,
                    server_peer_timeout=args.server_timeout,
                )
            )
        )
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if outcome.final_result is None:
        print(
            f"[lab2] Node {outcome.local_role}: submitted round, no result before timeout"
        )
        return 0
    status = "ACCEPTED" if outcome.final_result.success else "REJECTED"
    print(f"[lab2] Node {outcome.local_role}: {status}: {outcome.final_result.message}")
    return 0 if outcome.final_result.success else 2


if __name__ == "__main__":
    raise SystemExit(main())
