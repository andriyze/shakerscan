"""Shared row, JSON, and value-coercion helpers for the API layer.

These pure helpers convert asyncpg records and JSON/JSONB column values into
JSON-serializable Python objects. They were defined inside the api.py monolith
and used by hundreds of route handlers; extracting them here lets each router
that is peeled off the monolith import them from a shared module instead of
reaching back into ``api.api``. Behavior is identical to the originals.
"""

from __future__ import annotations

from datetime import datetime
import json
from typing import Any, Mapping
import uuid


def row_to_dict(row) -> dict:
    """Convert asyncpg Record to JSON-serializable dict."""
    d = dict(row)
    for k, v in d.items():
        if isinstance(v, uuid.UUID):
            d[k] = str(v)
        elif isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


def _decode_json_value(value: Any) -> Any:
    """Decode JSON strings returned from JSON/JSONB columns when needed."""
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return value
    return value


def _json_object(value: Any) -> dict[str, Any]:
    decoded = _decode_json_value(value)
    return dict(decoded) if isinstance(decoded, Mapping) else {}


def _decode_jsonb_scalar(value: Any) -> Any:
    """Decode a JSONB column value that may be a SCALAR (number/bool/quoted string) as well as an
    object/array. asyncpg returns jsonb as raw text; the general :func:`_decode_json_value` only parses
    objects/arrays, so a numeric invariant bound (jsonb ``3``) would come back as the string ``"3"`` and
    fail the ordered-operator numeric check — no field_constraint contract with a numeric bound could
    be approved. Non-JSON text is returned unchanged."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return value
    return value


def _str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


__all__ = [
    "row_to_dict",
    "_str_list",
    "_decode_json_value",
    "_json_object",
    "_decode_jsonb_scalar",
]
