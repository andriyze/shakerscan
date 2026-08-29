"""Canonical target cohort labels used by inventory and executive read models."""

from __future__ import annotations

import ipaddress
from typing import Any, Mapping
from urllib.parse import urlsplit


TARGET_COHORTS = (
    "production", "staging", "lab", "demo", "calibration", "internal",
)


def target_exposure_class(url: Any) -> str:
    """Return one canonical public/internal classification for web targets."""
    try:
        host = (urlsplit(str(url)).hostname or "").lower().rstrip(".")
    except ValueError:
        host = ""
    raw_locator = str(url or "").strip().lower()
    if not host and "://" not in raw_locator:
        authority = raw_locator.split("/", 1)[0].rsplit("@", 1)[-1]
        host = authority.rsplit(":", 1)[0].strip("[]").rstrip(".")
    if not host:
        return "unknown"
    if host in {"localhost", "host.docker.internal"} or host.endswith(
        (".local", ".localhost", ".internal", ".test")
    ):
        return "internal"
    if "." not in host and ":" not in host:
        return "internal"
    try:
        address = ipaddress.ip_address(host)
        if not address.is_global:
            return "internal"
    except ValueError:
        pass
    return "public"


def normalize_target_cohort(value: Any, *, allow_unclassified: bool = True) -> str:
    cohort = str(value or "").strip().lower()
    cohort = {"development": "lab", "test": "lab"}.get(cohort, cohort)
    allowed = {*TARGET_COHORTS, "unclassified"} if allow_unclassified else set(TARGET_COHORTS)
    if cohort not in allowed:
        raise ValueError(f"cohort must be one of: {', '.join(TARGET_COHORTS)}")
    return cohort


def target_cohort(
    *,
    url: Any,
    name: Any = None,
    discovery_source: Any = None,
    metadata: Mapping[str, Any] | None = None,
    exposure_class: Any = None,
) -> str:
    meta = metadata or {}
    explicit = meta.get("cohort")
    if explicit:
        try:
            return normalize_target_cohort(explicit)
        except ValueError:
            return "unclassified"
    environment = str(meta.get("environment") or "").strip().lower()
    if environment in {*TARGET_COHORTS, "development", "test"}:
        return normalize_target_cohort(environment)

    if str(exposure_class or "").lower() == "internal":
        return "internal"
    if target_exposure_class(url) == "internal":
        return "internal"
    # Excluding an asset from the operational executive view requires explicit
    # metadata. Human-readable names and host labels are not environment authority.
    return "unclassified"
