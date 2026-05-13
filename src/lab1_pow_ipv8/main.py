"""CLI entrypoint for Lab 1 PoW over IPv8."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .client import submit_pow
from .constants import DEFAULT_DIFFICULTY
from .pow import PowSolution, is_valid_pow, mine_pow
from .validation import (
    canonicalize_email,
    validate_email,
    validate_github_url,
    validate_nonce,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lab 1: Proof of Work over IPv8")
    parser.add_argument("--email", required=True, help="Your TU Delft email")
    parser.add_argument("--github-url", required=True, help="Public GitHub repo URL")
    parser.add_argument(
        "--key-file",
        default="lab1_identity.pem",
        help="PEM file path for your persistent IPv8 private key",
    )
    parser.add_argument(
        "--difficulty",
        type=int,
        default=DEFAULT_DIFFICULTY,
        help=f"PoW difficulty in leading zero bits (default: {DEFAULT_DIFFICULTY})",
    )
    parser.add_argument(
        "--nonce",
        type=int,
        default=None,
        help="Provide an existing nonce (skip mining)",
    )
    parser.add_argument(
        "--mine-only",
        action="store_true",
        help="Only mine and print a valid nonce, do not submit",
    )
    parser.add_argument(
        "--submit-only",
        action="store_true",
        help="Skip mining and submit provided --nonce",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Seconds to wait for server response after submission",
    )
    parser.add_argument(
        "--debug-peers",
        action="store_true",
        help="Log discovered peers and their public keys while searching for server",
    )
    parser.add_argument(
        "--bootstrap",
        action="append",
        default=[],
        help="Optional bootstrap address in host:port form (can be repeated)",
    )
    parser.add_argument(
        "--walk-peers",
        type=int,
        default=30,
        help="Random-walk target peers for discovery (default: 30)",
    )
    parser.add_argument(
        "--walk-timeout",
        type=float,
        default=3.0,
        help="Random-walk timeout seconds (default: 3.0)",
    )
    parser.add_argument(
        "--no-canonicalize-email",
        action="store_true",
        help="Use the email exactly as provided for hashing/submission",
    )
    return parser.parse_args()


def print_mining_progress(attempts: int, nonce: int, hashrate: float) -> None:
    print(
        f"[mining] attempts={attempts:,} nonce={nonce:,} "
        f"hashrate={hashrate:,.0f} H/s"
    )


def mine_or_use_nonce(
    email: str,
    github_url: str,
    difficulty: int,
    forced_nonce: int | None,
    submit_only: bool,
) -> PowSolution:
    if submit_only:
        if forced_nonce is None:
            raise ValueError("--submit-only requires --nonce")
        validate_nonce(forced_nonce)
        if not is_valid_pow(email, github_url, forced_nonce, difficulty):
            raise ValueError(
                "Provided --nonce does not satisfy the required PoW difficulty"
            )
        return PowSolution(
            nonce=forced_nonce,
            digest_hex="(precomputed)",
            attempts=0,
            elapsed_seconds=0.0,
        )

    print("[mining] searching for a valid nonce...")
    solution = mine_pow(
        email=email,
        github_url=github_url,
        difficulty=difficulty,
        start_nonce=forced_nonce or 0,
        progress_every=1_000_000,
        progress_callback=print_mining_progress,
    )
    print(
        "[mining] found nonce="
        f"{solution.nonce} after {solution.attempts:,} attempts "
        f"in {solution.elapsed_seconds:.2f}s"
    )
    print(f"[mining] digest={solution.digest_hex}")
    return solution


def main() -> int:
    args = parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    email = args.email if args.no_canonicalize_email else canonicalize_email(args.email)
    github_url = args.github_url

    validate_email(email)
    validate_github_url(github_url)

    solution = mine_or_use_nonce(
        email=email,
        github_url=github_url,
        difficulty=args.difficulty,
        forced_nonce=args.nonce,
        submit_only=args.submit_only,
    )

    if args.mine_only:
        return 0

    bootstrap_addrs = []
    for item in args.bootstrap:
        if ":" not in item:
            raise ValueError("--bootstrap must be in host:port form")
        host, port_str = item.rsplit(":", 1)
        bootstrap_addrs.append((host, int(port_str)))

    result = asyncio.run(
        submit_pow(
            email=email,
            github_url=github_url,
            nonce=solution.nonce,
            key_file=args.key_file,
            timeout_seconds=args.timeout,
            debug_peers=args.debug_peers,
            bootstrap_addrs=bootstrap_addrs or None,
            walk_peers=args.walk_peers,
            walk_timeout=args.walk_timeout,
        )
    )
    status = "ACCEPTED" if result.success else "REJECTED"
    print(f"[server] {status}: {result.message}")
    return 0 if result.success else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
