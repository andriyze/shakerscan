"""Shared request/value helpers used across the API layer.

Pure identifier, coercion, and hashing helpers extracted verbatim from the
api.py monolith. They are used by hundreds of route handlers across every
domain, so they live here rather than inside any one domain package; a router
peeled off the monolith imports them from here instead of from ``api.api``.

Only side-effect-free helpers belong here. Anything a test monkeypatches to
intercept IO must stay where its callers resolve it, or move together with
those callers — a helper whose patch point moves out from under a caller can
turn a stubbed test into real IO.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
import uuid

from fastapi import HTTPException

try:
    from serialization import _decode_json_value, row_to_dict
except ModuleNotFoundError:  # package import in host-side tests
    from .serialization import _decode_json_value, row_to_dict

def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _row_value(row: Any, key: str, default: Any = None) -> Any:
    if isinstance(row, dict):
        return row.get(key, default)
    try:
        return row[key]
    except Exception:
        return default


def _iso_or_none(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _content_free_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _uuid_or_400(value: str, label: str = "id") -> uuid.UUID:
    """Parse a path/query value as a UUID, returning HTTP 400 (not a 500) on garbage.
    A bad id is a client error — and a GET to a POST-only path like /targets/dedupe
    that falls through to /targets/{target_id} should 400, not crash."""
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: {value!r}")


def _json_safe_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    return _decode_json_value(payload) if isinstance(payload, dict) else payload


def _direct_query_value(value: Any) -> Any:
    """Unwrap FastAPI parameter defaults for trusted in-process endpoint calls."""
    # Avoid coupling this module (and isolated test harnesses) to FastAPI's
    # private Param base class while still recognizing Query/Header subclasses.
    value_type = type(value)
    if value_type.__module__ == "fastapi.params" and hasattr(value, "default"):
        return value.default
    return value


def _optional_uuid(value: str | uuid.UUID | None) -> uuid.UUID | None:
    value = _direct_query_value(value)
    if not value:
        return None
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


def _clean_string_list(values: list[Any] | None, *, max_items: int = 50) -> list[str]:
    cleaned: list[str] = []
    for value in values or []:
        item = str(value or "").strip()
        if item:
            cleaned.append(item)
        if len(cleaned) >= max_items:
            break
    return cleaned


__all__ = [
    "_clean_string_list",
    "_content_free_hash",
    "_direct_query_value",
    "_int_or_none",
    "_iso_or_none",
    "_json_safe_row",
    "_optional_uuid",
    "_row_value",
    "_uuid_or_400",
]
