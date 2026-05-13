"""Utility to extract public keys from PEM files."""

from __future__ import annotations

import glob
import os
import sys

from lab1_pow_ipv8.libsodium_bootstrap import ensure_libsodium


def extract_public_key_hex(pem_path: str) -> str:
    """
    Extract the Ed25519 public key from a PEM file and return it as hex.

    This is useful for sharing your public key with teammates.
    Requires libsodium to be available.
    """
    ensure_libsodium()

    from ipv8.keyvault.crypto import default_eccrypto

    try:
        with open(pem_path, "rb") as f:
            pem_data = f.read()
        key = default_eccrypto.key_from_private_bin(pem_data)
        pub_key_bin = key.pub().key_to_bin()
        return pub_key_bin.hex()
    except Exception as exc:
        raise ValueError(
            f"Failed to extract public key from '{pem_path}': {exc}"
        ) from exc


def load_private_key(pem_path: str):
    """Load an IPv8 private key from a PEM file."""
    ensure_libsodium()

    from ipv8.keyvault.crypto import default_eccrypto

    try:
        with open(pem_path, "rb") as f:
            pem_data = f.read()
        return default_eccrypto.key_from_private_bin(pem_data)
    except Exception as exc:
        raise ValueError(
            f"Failed to load private key from '{pem_path}': {exc}"
        ) from exc


def sign_bytes(private_key, data: bytes) -> bytes:
    """Sign raw bytes with an IPv8 private key."""
    ensure_libsodium()

    from ipv8.keyvault.crypto import default_eccrypto

    return default_eccrypto.create_signature(private_key, data)


def verify_signature(pubkey_hex: str, data: bytes, signature: bytes) -> bool:
    """Verify a signature against an IPv8 public key."""
    ensure_libsodium()

    from ipv8.keyvault.crypto import default_eccrypto

    try:
        public_key = default_eccrypto.key_from_public_bin(bytes.fromhex(pubkey_hex))
        return bool(default_eccrypto.is_valid_signature(public_key, data, signature))
    except Exception:
        return False


def load_pubkey_name_map(pubkeys_dir: str = "pubkeys") -> dict[str, str]:
    """Return {pubkey_hex: name} built from the stem of each pubkeys/*.txt filename."""
    result: dict[str, str] = {}
    if not os.path.isdir(pubkeys_dir):
        return result
    for path in glob.glob(os.path.join(pubkeys_dir, "*.txt")):
        name = os.path.splitext(os.path.basename(path))[0]
        with open(path) as f:
            content = f.read().strip()
        if content:
            result[content] = name
    return result


def fmt_peer(pubkey_hex: str, name_map: dict[str, str]) -> str:
    """Format a pubkey as '[name] hex[:16]...' or 'hex[:16]...' when name is unknown."""
    name = name_map.get(pubkey_hex)
    prefix = f"[{name}] " if name else ""
    return f"{prefix}{pubkey_hex[:16]}..."


def print_public_key(pem_path: str) -> int:
    """CLI command to print public key from PEM file."""
    try:
        pubkey_hex = extract_public_key_hex(pem_path)
        print(pubkey_hex)
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
