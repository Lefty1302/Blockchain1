from __future__ import annotations

import pytest

from lab1_pow_ipv8.lab2.race import build_ordered_signature_list
from lab1_pow_ipv8.lab2.team import load_team_config


def test_build_ordered_signature_list_uses_registration_order():
    team = load_team_config("lab2_team.json")
    signatures = {
        team.members[2].pubkey_hex: b"sig-c",
        team.members[0].pubkey_hex: b"sig-a",
        team.members[1].pubkey_hex: b"sig-b",
    }

    assert build_ordered_signature_list(team, signatures) == [
        b"sig-a",
        b"sig-b",
        b"sig-c",
    ]


def test_build_ordered_signature_list_requires_all_members():
    team = load_team_config("lab2_team.json")

    with pytest.raises(ValueError, match="Missing signatures"):
        build_ordered_signature_list(team, {team.members[0].pubkey_hex: b"sig-a"})
