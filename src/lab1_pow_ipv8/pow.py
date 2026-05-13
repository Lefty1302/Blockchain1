"""Proof-of-work logic for Lab 1."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from time import perf_counter
from typing import Callable

from .constants import MAX_NONCE
from .validation import validate_nonce


@dataclass(frozen=True)
class PowSolution:
    nonce: int
    digest_hex: str
    attempts: int
    elapsed_seconds: float


def build_pow_input(email: str, github_url: str, nonce: int) -> bytes:
    """
    Build exact preimage:
    SHA256(email_utf8 || "\n" || github_url_utf8 || "\n" || nonce_u64_be).
    """
    validate_nonce(nonce)
    return (
        email.encode("utf-8")
        + b"\n"
        + github_url.encode("utf-8")
        + b"\n"
        + nonce.to_bytes(8, byteorder="big", signed=False)
    )


def pow_digest(email: str, github_url: str, nonce: int) -> bytes:
    return sha256(build_pow_input(email, github_url, nonce)).digest()


def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + (8 - byte.bit_length())
    return bits


def is_valid_pow(email: str, github_url: str, nonce: int, difficulty: int) -> bool:
    return leading_zero_bits(pow_digest(email, github_url, nonce)) >= difficulty


def mine_pow(
    email: str,
    github_url: str,
    difficulty: int,
    start_nonce: int = 0,
    max_nonce: int = MAX_NONCE,
    progress_every: int = 1_000_000,
    progress_callback: Callable[[int, int, float], None] | None = None,
) -> PowSolution:
    """
    Search nonce in [start_nonce, max_nonce] for difficulty leading zero bits.
    """
    validate_nonce(start_nonce)
    validate_nonce(max_nonce)
    if start_nonce > max_nonce:
        raise ValueError("start_nonce must be <= max_nonce")

    prefix = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"
    attempts = 0
    started = perf_counter()

    for nonce in range(start_nonce, max_nonce + 1):
        digest = sha256(
            prefix + nonce.to_bytes(8, byteorder="big", signed=False)
        ).digest()
        attempts += 1

        if leading_zero_bits(digest) >= difficulty:
            elapsed = perf_counter() - started
            return PowSolution(
                nonce=nonce,
                digest_hex=digest.hex(),
                attempts=attempts,
                elapsed_seconds=elapsed,
            )

        if progress_callback and progress_every > 0 and attempts % progress_every == 0:
            elapsed = perf_counter() - started
            hashrate = attempts / elapsed if elapsed > 0 else 0.0
            progress_callback(attempts, nonce, hashrate)

    raise RuntimeError("No nonce found in provided search range")
