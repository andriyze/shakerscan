"""Lease-scoped encryption for worker-private broker inputs.

The broker control plane may deliver credential or exact-request material only
to the worker that owns a short-lived job lease.  Queue payloads, action plans,
logs, receipts, and public manifests remain secret-free; this module protects
the one in-memory HTTPS response field that carries the private material.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from typing import Any, Mapping

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.exceptions import InvalidTag
except ModuleNotFoundError:  # lightweight host tests may omit image dependencies
    hashes = serialization = X25519PrivateKey = X25519PublicKey = None
    ChaCha20Poly1305 = HKDF = None
    InvalidTag = ValueError


SEALED_INPUT_SCHEMA = "broker-private-input-envelope/v1"
MAX_SEALED_INPUT_PLAINTEXT_BYTES = 16 * 1024 * 1024
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_HKDF_INFO = b"shakerscan/broker-private-input/v1"


class SealedInputError(ValueError):
    """A private-input key, authority, envelope, or plaintext is invalid."""


def _require_crypto() -> None:
    if X25519PrivateKey is None:
        raise SealedInputError(
            "sealed input encryption requires the cryptography runtime dependency"
        )


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            dict(value), sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SealedInputError("sealed input is not canonical JSON") from exc


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: Any, *, name: str, expected_size: int | None = None) -> bytes:
    text = str(value or "")
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SealedInputError(f"{name} is invalid base64") from exc
    if expected_size is not None and len(raw) != expected_size:
        raise SealedInputError(f"{name} has the wrong size")
    return raw


def _authority_bytes(authority: Mapping[str, Any]) -> bytes:
    raw = _canonical_json(authority)
    if not raw or len(raw) > 16_384:
        raise SealedInputError("sealed input authority is invalid")
    return raw


def generate_sealed_input_keypair() -> tuple[str, str]:
    """Return a one-use X25519 private/public key pair as base64 raw bytes."""
    _require_crypto()
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64encode(private_raw), _b64encode(public_raw)


def validate_sealed_input_public_key(value: Any) -> str:
    _require_crypto()
    raw = _b64decode(value, name="sealed input public key", expected_size=32)
    try:
        X25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise SealedInputError("sealed input public key is invalid") from exc
    return _b64encode(raw)


def _derive_key(
    shared_secret: bytes, *, salt: bytes, authority_digest: str,
) -> bytes:
    _require_crypto()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_HKDF_INFO + bytes.fromhex(authority_digest),
    ).derive(shared_secret)


def seal_private_input(
    payload: Mapping[str, Any],
    *,
    recipient_public_key: Any,
    authority: Mapping[str, Any],
) -> dict[str, Any]:
    """Encrypt one canonical JSON object for a lease worker's one-use key."""
    _require_crypto()
    plaintext = _canonical_json(payload)
    if not plaintext or len(plaintext) > MAX_SEALED_INPUT_PLAINTEXT_BYTES:
        raise SealedInputError("sealed input plaintext exceeds its size limit")
    authority_raw = _authority_bytes(authority)
    authority_digest = hashlib.sha256(authority_raw).hexdigest()
    recipient_raw = _b64decode(
        validate_sealed_input_public_key(recipient_public_key),
        name="sealed input public key", expected_size=32,
    )
    recipient = X25519PublicKey.from_public_bytes(recipient_raw)
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    salt = os.urandom(32)
    nonce = os.urandom(12)
    key = _derive_key(
        ephemeral.exchange(recipient),
        salt=salt,
        authority_digest=authority_digest,
    )
    ciphertext = ChaCha20Poly1305(key).encrypt(
        nonce, plaintext, authority_raw,
    )
    return {
        "schema_version": SEALED_INPUT_SCHEMA,
        "ephemeral_public_key": _b64encode(ephemeral_public),
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
        "authority_digest": authority_digest,
        "content_sha256": hashlib.sha256(plaintext).hexdigest(),
        "plaintext_bytes": len(plaintext),
    }


def open_private_input(
    envelope: Mapping[str, Any],
    *,
    recipient_private_key: Any,
    authority: Mapping[str, Any],
) -> dict[str, Any]:
    """Authenticate and decrypt one lease-bound private-input envelope."""
    _require_crypto()
    if not isinstance(envelope, Mapping) or set(envelope) != {
        "schema_version", "ephemeral_public_key", "salt", "nonce",
        "ciphertext", "authority_digest", "content_sha256", "plaintext_bytes",
    }:
        raise SealedInputError("sealed input envelope shape is invalid")
    if envelope.get("schema_version") != SEALED_INPUT_SCHEMA:
        raise SealedInputError("sealed input envelope schema is invalid")
    try:
        plaintext_bytes = int(envelope.get("plaintext_bytes"))
    except (TypeError, ValueError) as exc:
        raise SealedInputError("sealed input plaintext size is invalid") from exc
    if not 1 <= plaintext_bytes <= MAX_SEALED_INPUT_PLAINTEXT_BYTES:
        raise SealedInputError("sealed input plaintext size is invalid")
    authority_raw = _authority_bytes(authority)
    authority_digest = hashlib.sha256(authority_raw).hexdigest()
    if (
        not _HEX_64_RE.fullmatch(str(envelope.get("authority_digest") or ""))
        or envelope.get("authority_digest") != authority_digest
    ):
        raise SealedInputError("sealed input authority does not match")
    content_digest = str(envelope.get("content_sha256") or "")
    if not _HEX_64_RE.fullmatch(content_digest):
        raise SealedInputError("sealed input content digest is invalid")
    private_raw = _b64decode(
        recipient_private_key,
        name="sealed input private key", expected_size=32,
    )
    ephemeral_raw = _b64decode(
        envelope.get("ephemeral_public_key"),
        name="sealed input ephemeral public key", expected_size=32,
    )
    salt = _b64decode(
        envelope.get("salt"), name="sealed input salt", expected_size=32,
    )
    nonce = _b64decode(
        envelope.get("nonce"), name="sealed input nonce", expected_size=12,
    )
    ciphertext = _b64decode(
        envelope.get("ciphertext"), name="sealed input ciphertext",
    )
    if len(ciphertext) != plaintext_bytes + 16:
        raise SealedInputError("sealed input ciphertext size is invalid")
    try:
        private = X25519PrivateKey.from_private_bytes(private_raw)
        ephemeral = X25519PublicKey.from_public_bytes(ephemeral_raw)
        key = _derive_key(
            private.exchange(ephemeral),
            salt=salt,
            authority_digest=authority_digest,
        )
        plaintext = ChaCha20Poly1305(key).decrypt(
            nonce, ciphertext, authority_raw,
        )
    except (InvalidTag, ValueError, TypeError) as exc:
        raise SealedInputError("sealed input authentication failed") from exc
    if (
        len(plaintext) != plaintext_bytes
        or hashlib.sha256(plaintext).hexdigest() != content_digest
    ):
        raise SealedInputError("sealed input digest or size mismatch")
    try:
        payload = json.loads(plaintext)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SealedInputError("sealed input plaintext is invalid JSON") from exc
    if not isinstance(payload, dict) or _canonical_json(payload) != plaintext:
        raise SealedInputError("sealed input plaintext is not canonical JSON")
    return payload


__all__ = [
    "MAX_SEALED_INPUT_PLAINTEXT_BYTES",
    "SEALED_INPUT_SCHEMA",
    "SealedInputError",
    "generate_sealed_input_keypair",
    "open_private_input",
    "seal_private_input",
    "validate_sealed_input_public_key",
]
