"""Operator opt-in for the optional advisory intelligence sources.

The snapshot can carry data beyond NVD's own analysis: marks from a third party's curated
vulnerability briefings (Cloudflare Radar Zero Wire) and affected ranges a CVE's publisher declared
before NVD analysed it. Neither is used until an operator enables it in Settings
(``PUT /settings/automation``). The choice is durable (``app_settings``) and read where service
intelligence is computed; a value that cannot be read counts as off.

Enabling a source fetches nothing: it only lets data already in the verified snapshot take part
in candidate matching and ranking. It grants no authority and changes no score.
"""
from __future__ import annotations

from typing import Any, Mapping

#: source name -> durable ``app_settings`` key.
SETTING_KEYS: Mapping[str, str] = {
    "curated_briefings": "intel_curated_briefings_enabled",
    "vendor_declared_ranges": "intel_vendor_declared_ranges_enabled",
}


def disabled() -> dict[str, bool]:
    return {name: False for name in SETTING_KEYS}


async def _read(conn: Any) -> dict[str, bool]:
    sources = disabled()
    for name, key in SETTING_KEYS.items():
        value = await conn.fetchval("SELECT value FROM app_settings WHERE key = $1", key)
        sources[name] = str(value or "").strip().lower() == "true"
    return sources


async def load_intel_sources(conn: Any) -> dict[str, bool]:
    """Which optional sources the operator enabled. Off when unset or unreadable.

    Callers read this inside their own transaction. A failed statement would abort that
    transaction, so the read runs in a savepoint: a failure here costs the caller nothing.
    """
    try:
        in_transaction = getattr(conn, "is_in_transaction", None)
        if callable(in_transaction) and in_transaction():
            async with conn.transaction():
                return await _read(conn)
        return await _read(conn)
    except Exception:
        return disabled()


__all__ = ["SETTING_KEYS", "disabled", "load_intel_sources"]
