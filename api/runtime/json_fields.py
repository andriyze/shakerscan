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
