from __future__ import annotations

import json

import pytest
from ipv8.keyvault.crypto import default_eccrypto

from lab2_relay_race.ids import UDP_GROUP_READY
from lab2_relay_race.udp_protocol import (
    DuplicateMessageError,
    SignedUdpCodec,
    UdpProtocolError,
    UnknownSenderError,
    build_group_ready_body,
)
from lab1_pow_ipv8.libsodium_bootstrap import ensure_libsodium


def _key_pair():
    ensure_libsodium()
    key = default_eccrypto.generate_key("curve25519")
    return key, key.pub().key_to_bin().hex()


def test_signed_udp_roundtrip():
    private_key, pubkey_hex = _key_pair()
    sender = SignedUdpCodec(
        local_private_key=private_key,
        local_pubkey_hex=pubkey_hex,
        allowed_pubkeys={pubkey_hex},
    )
    receiver = SignedUdpCodec(allowed_pubkeys={pubkey_hex})

    datagram = sender.encode(UDP_GROUP_READY, 1, build_group_ready_body("group-1"))
    message = receiver.decode(datagram)

    assert message.sender_pubkey_hex == pubkey_hex
    assert message.message_id == UDP_GROUP_READY
    assert message.sequence == 1
    assert message.body == {"group_id": "group-1"}


def test_signed_udp_rejects_tampering():
    private_key, pubkey_hex = _key_pair()
    sender = SignedUdpCodec(
        local_private_key=private_key,
        local_pubkey_hex=pubkey_hex,
        allowed_pubkeys={pubkey_hex},
    )
    receiver = SignedUdpCodec(allowed_pubkeys={pubkey_hex})

    raw = json.loads(
        sender.encode(UDP_GROUP_READY, 1, build_group_ready_body("group-1")).decode(
            "utf-8"
        )
    )
    raw["body"]["group_id"] = "group-2"
    tampered = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")

    with pytest.raises(UdpProtocolError):
        receiver.decode(tampered)


def test_signed_udp_rejects_unknown_sender():
    private_key, pubkey_hex = _key_pair()
    sender = SignedUdpCodec(
        local_private_key=private_key,
        local_pubkey_hex=pubkey_hex,
        allowed_pubkeys={pubkey_hex},
    )
    receiver = SignedUdpCodec(allowed_pubkeys=set())

    datagram = sender.encode(UDP_GROUP_READY, 1, build_group_ready_body("group-1"))

    with pytest.raises(UnknownSenderError):
        receiver.decode(datagram)


def test_signed_udp_rejects_duplicate_sequence():
    private_key, pubkey_hex = _key_pair()
    sender = SignedUdpCodec(
        local_private_key=private_key,
        local_pubkey_hex=pubkey_hex,
        allowed_pubkeys={pubkey_hex},
    )
    receiver = SignedUdpCodec(allowed_pubkeys={pubkey_hex})

    datagram = sender.encode(UDP_GROUP_READY, 1, build_group_ready_body("group-1"))
    receiver.decode(datagram)

    with pytest.raises(DuplicateMessageError):
        receiver.decode(datagram)
