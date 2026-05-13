from hashlib import sha256

from lab1_pow_ipv8.pow import (
    build_pow_input,
    is_valid_pow,
    leading_zero_bits,
    mine_pow,
    pow_digest,
)
from lab1_pow_ipv8.validation import (
    canonicalize_email,
    validate_email,
    validate_github_url,
)


def test_build_pow_input_exact_layout() -> None:
    email = "alice@student.tudelft.nl"
    url = "https://github.com/alice/bitconnect-lab1"
    nonce = 42

    expected = (
        email.encode("utf-8")
        + b"\n"
        + url.encode("utf-8")
        + b"\n"
        + (42).to_bytes(8, byteorder="big", signed=False)
    )
    assert build_pow_input(email, url, nonce) == expected


def test_pow_digest_matches_sha256() -> None:
    email = "bob@tudelft.nl"
    url = "https://github.com/bob/lab1"
    nonce = 123456
    assert (
        pow_digest(email, url, nonce)
        == sha256(build_pow_input(email, url, nonce)).digest()
    )


def test_leading_zero_bits_counts_correctly() -> None:
    assert leading_zero_bits(bytes.fromhex("0000000f")) == 28
    assert leading_zero_bits(bytes.fromhex("00000010")) == 27
    assert leading_zero_bits(bytes.fromhex("00ff")) == 8


def test_mine_pow_finds_solution_for_small_difficulty() -> None:
    email = "carol@student.tudelft.nl"
    url = "https://github.com/carol/lab1"
    difficulty = 12
    solution = mine_pow(email, url, difficulty, max_nonce=2_000_000)
    assert is_valid_pow(email, url, solution.nonce, difficulty)


def test_email_and_url_validation() -> None:
    assert (
        canonicalize_email("  ALICE@STUDENT.TUDELFT.NL ") == "alice@student.tudelft.nl"
    )
    validate_email("x@student.tudelft.nl")
    validate_github_url("https://github.com/org/repo")
