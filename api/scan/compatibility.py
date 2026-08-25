"""Bounded, content-free telemetry for removed Scan API boundaries."""

from __future__ import annotations

from typing import Any


COMPATIBILITY_METRIC_KEY = "shakerscan:v2:legacy_compatibility"
COMPATIBILITY_CALLS = frozenset({
    "cli_alias",
    "cli_v1_status",
    "cli_v1_submit",
    "raw_secret_batch",
    "raw_secret_scan",
})


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
        "schema_version": "scan-compatibility-metrics/v2",
        "available": available,
        "write_surface": "removed",
        "total_calls": sum(calls.values()),
        "calls": calls,
        "content_free": True,
    }


__all__ = [
    "COMPATIBILITY_METRIC_KEY",
    "compatibility_snapshot",
    "record_compatibility_call",
]
