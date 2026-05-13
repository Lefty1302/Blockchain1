"""Signed direct-UDP protocol helpers for Lab 2 teammate messages."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from .ids import UDP_MESSAGE_IDS
from .keyutil import sign_bytes, verify_signature

UDP_MAGIC = "LAB2UDP"
UDP_VERSION = 1


class UdpProtocolError(ValueError):
    """Base class for invalid signed UDP packets."""


class UnknownSenderError(UdpProtocolError):
    """Raised when a packet is signed by a key outside the configured team."""


class DuplicateMessageError(UdpProtocolError):
    """Raised when a sender reuses a previously accepted sequence number."""


@dataclass(frozen=True)
class SignedUdpMessage:
    sender_pubkey_hex: str
    message_id: int
    sequence: int
    body: dict[str, Any]


class SignedUdpCodec:
    """Encode and verify signed JSON datagrams for teammate UDP traffic."""

    def __init__(
        self,
        *,
        local_private_key=None,
        local_pubkey_hex: str | None = None,
        allowed_pubkeys: set[str] | frozenset[str],
        enforce_replay: bool = True,
    ) -> None:
        self.local_private_key = local_private_key
        self.local_pubkey_hex = local_pubkey_hex
        self.allowed_pubkeys = set(allowed_pubkeys)
        self.enforce_replay = enforce_replay
        self._seen_sequences: dict[str, set[int]] = {}

    def encode(self, message_id: int, sequence: int, body: Mapping[str, Any]) -> bytes:
        if self.local_private_key is None or self.local_pubkey_hex is None:
            raise UdpProtocolError("Cannot encode without a local private key")
        if message_id not in UDP_MESSAGE_IDS:
            raise UdpProtocolError(f"Unknown UDP message id: {message_id}")
        if sequence < 0:
            raise UdpProtocolError("UDP sequence must be non-negative")

        body_dict = dict(body)
        unsigned = _unsigned_envelope(
            self.local_pubkey_hex,
            message_id,
            sequence,
            body_dict,
        )
        signature = sign_bytes(self.local_private_key, _canonical_json(unsigned))
        signed = {**unsigned, "signature": signature.hex()}
        return _canonical_json(signed)

    def decode(self, data: bytes) -> SignedUdpMessage:
        try:
            raw = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UdpProtocolError("UDP datagram is not valid JSON") from exc

        if not isinstance(raw, dict):
            raise UdpProtocolError("UDP datagram root must be an object")
        if raw.get("magic") != UDP_MAGIC or raw.get("version") != UDP_VERSION:
            raise UdpProtocolError("UDP datagram has wrong magic or version")

        sender = _require_str(raw, "sender")
        if sender not in self.allowed_pubkeys:
            raise UnknownSenderError(sender)

        message_id = _require_int(raw, "message_id")
        if message_id not in UDP_MESSAGE_IDS:
            raise UdpProtocolError(f"Unknown UDP message id: {message_id}")

        sequence = _require_int(raw, "sequence")
        if sequence < 0:
            raise UdpProtocolError("UDP sequence must be non-negative")

        body = raw.get("body")
        if not isinstance(body, dict):
            raise UdpProtocolError("UDP body must be an object")

        signature_hex = _require_str(raw, "signature")
        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError as exc:
            raise UdpProtocolError("UDP signature is not hex") from exc

        unsigned = _unsigned_envelope(sender, message_id, sequence, body)
        if not verify_signature(sender, _canonical_json(unsigned), signature):
            raise UdpProtocolError("UDP signature verification failed")

        if self.enforce_replay:
            sender_sequences = self._seen_sequences.setdefault(sender, set())
            if sequence in sender_sequences:
                raise DuplicateMessageError(f"{sender}:{sequence}")
            sender_sequences.add(sequence)

        return SignedUdpMessage(
            sender_pubkey_hex=sender,
            message_id=message_id,
            sequence=sequence,
            body=body,
        )


def build_group_ready_body(group_id: str) -> dict[str, Any]:
    return {"group_id": group_id}


def build_nonce_broadcast_body(round_number: int, nonce: bytes) -> dict[str, Any]:
    return {"round_number": round_number, "nonce_hex": nonce.hex()}


def build_signature_reply_body(round_number: int, signature: bytes) -> dict[str, Any]:
    return {"round_number": round_number, "signature_hex": signature.hex()}


def build_baton_pass_body(next_round_number: int, group_id: str) -> dict[str, Any]:
    return {"next_round_number": next_round_number, "group_id": group_id}


def build_ack_body(
    ack_message_id: int, round_number: int | None = None
) -> dict[str, Any]:
    body: dict[str, Any] = {"ack_message_id": ack_message_id}
    if round_number is not None:
        body["round_number"] = round_number
    return body


def body_bytes(body: Mapping[str, Any], field: str) -> bytes:
    value = body.get(field)
    if not isinstance(value, str):
        raise UdpProtocolError(f"Missing hex field: {field}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise UdpProtocolError(f"Invalid hex field: {field}") from exc


def body_int(body: Mapping[str, Any], field: str) -> int:
    value = body.get(field)
    if not isinstance(value, int):
        raise UdpProtocolError(f"Missing integer field: {field}")
    return value


def body_str(body: Mapping[str, Any], field: str) -> str:
    value = body.get(field)
    if not isinstance(value, str):
        raise UdpProtocolError(f"Missing string field: {field}")
    return value


def _unsigned_envelope(
    sender: str,
    message_id: int,
    sequence: int,
    body: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "magic": UDP_MAGIC,
        "version": UDP_VERSION,
        "sender": sender,
        "message_id": message_id,
        "sequence": sequence,
        "body": dict(body),
    }


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _require_str(raw: Mapping[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise UdpProtocolError(f"Missing string field: {key}")
    return value


def _require_int(raw: Mapping[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int):
        raise UdpProtocolError(f"Missing integer field: {key}")
    return value
