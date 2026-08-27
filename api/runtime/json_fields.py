"""Strict JSON field decoding for database and queue boundaries."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


def _decode_json_field(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            value = bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return None
    return value


def json_object_field(value: Any) -> dict[str, Any]:
    """Return a detached object for native or serialized JSON object fields."""
    decoded = _decode_json_field(value)
    return dict(decoded) if isinstance(decoded, Mapping) else {}


def json_array_field(value: Any) -> list[Any]:
    """Return a detached array for native or serialized JSON array fields."""
    decoded = _decode_json_field(value)
    return list(decoded) if isinstance(decoded, list) else []


def strip_null_bytes(value: Any) -> Any:
    """Recursively remove NUL from strings bound for PostgreSQL.

    PostgreSQL text and jsonb cannot store ``\u0000``: asyncpg raises
    ``UntranslatableCharacterError`` and the whole statement fails. NUL reaches
    these boundaries whenever a capability captures binary content -- a probe
    that reads a ``.pyc`` or ``.bak`` from an exposed directory, for instance --
    and one such byte failed an entire batch action, discarding every attempt it
    had already completed rather than the single observation carrying it.
    """
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, Mapping):
        return {key: strip_null_bytes(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [strip_null_bytes(item) for item in value]
    return value
