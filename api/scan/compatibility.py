"""Bounded, content-free telemetry for deprecated Scan API boundaries."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


RAW_SECRET_COMPATIBILITY_SUNSET = datetime(
    2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc,
)
RAW_SECRET_COMPATIBILITY_SUNSET_HTTP = "Thu, 31 Dec 2026 23:59:59 GMT"
COMPATIBILITY_METRIC_KEY = "shakerscan:v2:legacy_compatibility"
COMPATIBILITY_CALLS = frozenset({
    "cli_alias",
    "cli_v1_status",
    "cli_v1_submit",
    "raw_secret_batch",
    "raw_secret_scan",
})


class CompatibilitySunsetError(RuntimeError):
    """A removed compatibility boundary was invoked after its deadline."""


def _utc(value: datetime | None) -> datetime:
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def require_raw_secret_compatibility(*, now: datetime | None = None) -> None:
    """Fail closed once the documented raw-secret bridge expires."""
    if _utc(now) >= RAW_SECRET_COMPATIBILITY_SUNSET:
        raise CompatibilitySunsetError(
            "inline authentication compatibility was removed; use encrypted "
            "credential profiles and submit only credential_profile_ids"
        )


def record_compatibility_call(redis_client: Any, call: str) -> bool:
    """Increment one allowlisted content-free counter without affecting admission."""
    name = str(call or "").strip().lower()
    if name not in COMPATIBILITY_CALLS:
        raise ValueError("unsupported compatibility telemetry counter")
    try:
        redis_client.hincrby(COMPATIBILITY_METRIC_KEY, name, 1)
        return True
    except Exception:
        return False


def compatibility_snapshot(
    redis_client: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return only aggregate counters; never retain request or target data."""
    try:
        raw = redis_client.hgetall(COMPATIBILITY_METRIC_KEY) or {}
        decoded = {
            (key.decode("utf-8", "replace") if isinstance(key, bytes) else str(key)):
            int(value.decode("ascii") if isinstance(value, bytes) else value)
            for key, value in raw.items()
        }
        available = True
    except Exception:
        decoded = {}
        available = False
    calls = {name: max(0, int(decoded.get(name, 0))) for name in sorted(COMPATIBILITY_CALLS)}
    return {
        "schema_version": "scan-compatibility-metrics/v1",
        "available": available,
        "sunset": RAW_SECRET_COMPATIBILITY_SUNSET.isoformat().replace("+00:00", "Z"),
        "sunset_reached": _utc(now) >= RAW_SECRET_COMPATIBILITY_SUNSET,
        "total_calls": sum(calls.values()),
        "calls": calls,
        "content_free": True,
    }


__all__ = [
    "COMPATIBILITY_METRIC_KEY",
    "CompatibilitySunsetError",
    "RAW_SECRET_COMPATIBILITY_SUNSET",
    "RAW_SECRET_COMPATIBILITY_SUNSET_HTTP",
    "compatibility_snapshot",
    "record_compatibility_call",
    "require_raw_secret_compatibility",
]
