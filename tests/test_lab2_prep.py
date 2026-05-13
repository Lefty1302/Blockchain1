"""Tests for Lab 2 prep utilities."""

from __future__ import annotations

from lab2_relay_race.prep_cli import validate_peer_args
from lab2_relay_race.udp_prep import PeerEndpoint


def test_peer_endpoint_str():
    peer = PeerEndpoint("AAAA1234BBBB5678", "192.168.1.1", 5000)
    value = str(peer)

    assert "AAAA12" in value
    assert "192.168.1.1" in value
    assert "5000" in value


def test_validate_peer_args_allows_two_person_auto_discovery():
    assert validate_peer_args(True, [], ["peer-a"]) is None


def test_validate_peer_args_rejects_duplicate_pubkeys():
    error = validate_peer_args(True, [], ["peer-a", "peer-a"])

    assert error is not None
    assert "duplicate" in error
