"""Fail-closed policy for inventory-only discovery execution."""

from __future__ import annotations

from typing import Any


PASSIVE_DISCOVERY_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def passive_http_methods_for_scan(
    *, discovery_manifest_only: bool, public_only: bool,
) -> frozenset[str] | None:
    """Return the non-overridable target method ceiling for passive execution."""
    if discovery_manifest_only or public_only:
        return PASSIVE_DISCOVERY_HTTP_METHODS
    return None


def enforce_discovery_manifest_safety(args: Any) -> bool:
    """Remove every active authority flag from a discovery-only scanner plan."""
    if not bool(getattr(args, "discovery_manifest_only", False)):
        return False
    for field in (
        "active",
        "xss",
        "sqli",
        "network_discovery",
        "active_enforced",
    ):
        setattr(args, field, False)
    setattr(args, "check_family", None)
    return True
