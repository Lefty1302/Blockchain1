"""Explicit Lab 2 team configuration."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EXPECTED_ROLES = ("A", "B", "C")


@dataclass(frozen=True)
class TeamMember:
    role: str
    name: str
    pubkey_hex: str

    @property
    def pubkey(self) -> bytes:
        return bytes.fromhex(self.pubkey_hex)


@dataclass(frozen=True)
class TeamConfig:
    members: tuple[TeamMember, TeamMember, TeamMember]

    @property
    def registration_pubkeys(self) -> list[str]:
        return [member.pubkey_hex for member in self.members]

    @property
    def registration_pubkey_bytes(self) -> list[bytes]:
        return [member.pubkey for member in self.members]

    @property
    def pubkey_set(self) -> set[str]:
        return set(self.registration_pubkeys)

    def local_member(self, local_pubkey_hex: str) -> TeamMember:
        for member in self.members:
            if member.pubkey_hex == local_pubkey_hex:
                return member
        raise ValueError("Local public key is not present in the Lab 2 team config")

    def teammates(self, local_pubkey_hex: str) -> list[TeamMember]:
        return [
            member for member in self.members if member.pubkey_hex != local_pubkey_hex
        ]

    def submitter_for_round(self, round_number: int) -> TeamMember:
        if round_number < 1 or round_number > len(self.members):
            raise ValueError(f"round_number must be 1-3, got {round_number}")
        return self.members[round_number - 1]

    def member_by_pubkey(self, pubkey_hex: str) -> TeamMember:
        for member in self.members:
            if member.pubkey_hex == pubkey_hex:
                return member
        raise KeyError(pubkey_hex)


def load_team_config(path: str | Path = "lab2_team.json") -> TeamConfig:
    config_path = Path(path)
    data = json.loads(config_path.read_text(encoding="utf-8"))
    raw_members = data.get("members")
    if not isinstance(raw_members, list) or len(raw_members) != 3:
        raise ValueError("Lab 2 team config must contain exactly three members")

    members = tuple(
        _parse_member(config_path, raw_member) for raw_member in raw_members
    )
    roles = tuple(member.role for member in members)
    if roles != EXPECTED_ROLES:
        raise ValueError("Lab 2 team roles must be exactly A, B, C in order")

    pubkeys = [member.pubkey_hex for member in members]
    if len(set(pubkeys)) != 3:
        raise ValueError("Lab 2 team config contains duplicate public keys")

    return TeamConfig(members)  # type: ignore[arg-type]


def _parse_member(config_path: Path, raw_member: Any) -> TeamMember:
    if not isinstance(raw_member, dict):
        raise ValueError("Each Lab 2 team member must be an object")

    role = str(raw_member.get("role", "")).strip()
    name = str(raw_member.get("name", "")).strip()
    pubkey_hex = _load_member_pubkey(config_path, raw_member)
    if not role or not name:
        raise ValueError("Each Lab 2 team member needs a role and name")

    try:
        bytes.fromhex(pubkey_hex)
    except ValueError as exc:
        raise ValueError(f"Invalid public key hex for member {role}") from exc

    return TeamMember(role=role, name=name, pubkey_hex=pubkey_hex)


def _load_member_pubkey(config_path: Path, raw_member: dict[str, Any]) -> str:
    if "pubkey_hex" in raw_member:
        return str(raw_member["pubkey_hex"]).strip()

    pubkey_file = raw_member.get("pubkey_file")
    if not pubkey_file:
        raise ValueError("Each Lab 2 team member needs pubkey_hex or pubkey_file")

    pubkey_path = Path(pubkey_file)
    if not pubkey_path.is_absolute():
        pubkey_path = config_path.parent / pubkey_path
    return pubkey_path.read_text(encoding="utf-8").strip()
