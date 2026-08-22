"""Fail-closed policy for inventory-only discovery execution."""

from __future__ import annotations

from typing import Any


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
