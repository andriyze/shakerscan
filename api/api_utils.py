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
import urllib.parse
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
    "SEVERITY_ORDER",
    "extract_root_domain",
    "_clean_string_list",
    "_graph_get",
    "_graph_list",
    "_parse_graph_json",
    "_scan_completion_flags",
    "_severity_sort_value",
    "_short_url_label",
    "_content_free_hash",
    "_direct_query_value",
    "_int_or_none",
    "_iso_or_none",
    "_json_safe_row",
    "_optional_uuid",
    "_row_value",
    "_uuid_or_400",
]
def _severity_sort_value(value: Any) -> int:
    return SEVERITY_ORDER.get(str(value or "").lower(), 0)


def _parse_graph_json(value: Any) -> dict[str, Any]:
    decoded = _decode_json_value(value)
    return decoded if isinstance(decoded, dict) else {}


def _short_url_label(value: str | None) -> str:
    if not value:
        return "unknown"
    try:
        parsed = urllib.parse.urlparse(value if "://" in value else f"https://{value}")
        host = parsed.hostname or parsed.path
        path = parsed.path if parsed.netloc else ""
        label = f"{host}{path}" if path and path != "/" else host
        return label[:90] if label else value[:90]
    except Exception:
        return str(value)[:90]


def _graph_list(value: Any) -> list[Any]:
    decoded = _decode_json_value(value)
    if isinstance(decoded, list):
        return decoded
    if isinstance(decoded, tuple):
        return list(decoded)
    return []


def _scan_completion_flags(completion_status: Any, top_coverage_status: Any = None) -> dict[str, Any]:
    """Build scan-coverage flags from the small ``scan_completion_status`` object.

    Callers extract only that sub-object (and the top-level coverage string) in
    SQL so the multi-hundred-KB scan ``result`` blob is never shipped per asset.
    """
    status = _parse_graph_json(completion_status)
    complete = status.get("complete")
    limited = bool(status.get("limited") or status.get("budget_exhausted"))
    return {
        "scan_complete": complete if complete is not None else (False if limited else None),
        "scan_limited": limited,
        "coverage_status": status.get("coverage_status") or top_coverage_status,
        "skipped_modules_count": len(status.get("skipped_modules") or []) if isinstance(status.get("skipped_modules"), list) else 0,
        "capped_lists_count": len(status.get("capped_lists") or {}) if isinstance(status.get("capped_lists"), dict) else 0,
    }
SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}
def extract_root_domain(url: str) -> str:
    """Extract root domain from URL."""
    from urllib.parse import urlparse
    import ipaddress
    try:
        parsed = urlparse(url if '://' in url else f'https://{url}')
        host = parsed.hostname or parsed.netloc or parsed.path.split('/')[0]
        # Note: parsed.hostname already strips ports and IPv6 brackets
        # Return IPs as-is (no root domain)
        try:
            ipaddress.ip_address(host.strip("[]"))
            return host.strip("[]")
        except ValueError:
            pass
        # Get root domain (last 2 parts)
        parts = host.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return host
    except Exception:
        return url
def _graph_get(container: dict[str, Any], *path: str) -> Any:
    cursor: Any = container
    for key in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(key)
    return cursor
