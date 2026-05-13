from __future__ import annotations

from pathlib import Path

from lab2_relay_race.ids import (
    CUSTOM_MESSAGE_IDS,
    SERVER_MESSAGE_IDS,
    ENDPOINT_ANNOUNCEMENT,
    ENDPOINT_REQUEST,
    UDP_ACK,
    UDP_BATON_PASS,
    UDP_GROUP_READY,
    UDP_NONCE_BROADCAST,
    UDP_SIGNATURE_REPLY,
)
from lab2_relay_race.team import load_team_config


def test_lab2_message_ids_do_not_conflict():
    assert SERVER_MESSAGE_IDS == {1, 2, 3, 4, 5, 6}
    assert CUSTOM_MESSAGE_IDS.isdisjoint(SERVER_MESSAGE_IDS)
    assert all(message_id >= 200 for message_id in CUSTOM_MESSAGE_IDS)
    assert {
        ENDPOINT_ANNOUNCEMENT,
        ENDPOINT_REQUEST,
        UDP_GROUP_READY,
        UDP_NONCE_BROADCAST,
        UDP_SIGNATURE_REPLY,
        UDP_BATON_PASS,
        UDP_ACK,
    } == CUSTOM_MESSAGE_IDS


def test_lab2_team_config_uses_explicit_role_order():
    team = load_team_config("lab2_team.json")

    assert [member.role for member in team.members] == ["A", "B", "C"]
    assert [member.name for member in team.members] == ["vesk", "miro", "dany"]
    assert team.registration_pubkeys == [
        Path("pubkeys/vesk.txt").read_text(encoding="utf-8").strip(),
        Path("pubkeys/miro.txt").read_text(encoding="utf-8").strip(),
        Path("pubkeys/dany.txt").read_text(encoding="utf-8").strip(),
    ]
    assert team.submitter_for_round(1).name == "vesk"
    assert team.submitter_for_round(2).name == "miro"
    assert team.submitter_for_round(3).name == "dany"
