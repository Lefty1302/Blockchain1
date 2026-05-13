"""Tests for Lab 2 prep phase."""

from __future__ import annotations

import pytest
from lab1_pow_ipv8.lab2_udp_prep import (
    compute_canonical_order,
    get_submitter_for_round,
    PeerEndpoint,
)
from lab1_pow_ipv8.lab2_main import validate_peer_args
from lab1_pow_ipv8.lab2_discovery import build_lab2_discovery_community


def test_compute_canonical_order():
    """Test lexicographic ordering of public keys using non-hex strings."""
    pubkeys = [
        "zebra",
        "apple",
        "middle",
    ]
    ordered = compute_canonical_order(pubkeys)
    assert ordered == ["apple", "middle", "zebra"]


def test_compute_canonical_order_hex():
    """Test with actual hex public keys."""
    pubkeys = [
        "4c69624e61434c504b3ab351c3190f1f80f0eafa4ed9351e26ad91bc45261d290bdd4e8132bb730f5d01ede43a99d8ae9befae4e06f9085c114becee92d28e906d196b47bee0c7d43168",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ]
    ordered = compute_canonical_order(pubkeys)
    # First should be the all-zeros, last should be all-fs
    assert ordered[0] == pubkeys[1]  # all zeros
    assert ordered[2] == pubkeys[2]  # all fs


def test_get_submitter_for_round():
    """Test submitter assignment per round."""
    pubkeys = ["A", "B", "C"]
    canonical = compute_canonical_order(pubkeys)

    assert get_submitter_for_round(canonical, 1) == canonical[0]
    assert get_submitter_for_round(canonical, 2) == canonical[1]
    assert get_submitter_for_round(canonical, 3) == canonical[2]


def test_get_submitter_for_round_invalid():
    """Test that invalid round numbers raise ValueError."""
    canonical = ["A", "B", "C"]

    with pytest.raises(ValueError):
        get_submitter_for_round(canonical, 0)

    with pytest.raises(ValueError):
        get_submitter_for_round(canonical, 4)


def test_peer_endpoint_str():
    """Test PeerEndpoint string representation."""
    peer = PeerEndpoint("AAAA1234BBBB5678", "192.168.1.1", 5000)
    s = str(peer)
    assert "AAAA12" in s
    assert "192.168.1.1" in s
    assert "5000" in s


def test_validate_peer_args_allows_two_person_auto_discovery():
    """Auto-discovery supports one teammate key for two-person testing."""
    assert validate_peer_args(True, [], ["peer-a"]) is None


def test_validate_peer_args_rejects_duplicate_pubkeys():
    """Duplicate peer keys should not be treated as two teammates."""
    error = validate_peer_args(True, [], ["peer-a", "peer-a"])
    assert error is not None
    assert "duplicate" in error


def test_lab2_discovery_uses_lab2_community_id():
    """Lab 2 discovery should not accidentally join the Lab 1 community."""
    community = build_lab2_discovery_community()
    assert community.community_id.hex() == "4c61623247726f75705369676e696e6732303236"
