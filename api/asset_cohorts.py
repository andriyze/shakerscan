"""Canonical target cohort labels used by inventory and executive read models."""

from __future__ import annotations

import ipaddress
from typing import Any, Mapping
from urllib.parse import urlsplit


TARGET_COHORTS = (
    "production", "staging", "lab", "demo", "calibration", "internal",
)


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

    text = " ".join(str(item or "").lower() for item in (url, name, discovery_source))
    if any(token in text for token in ("calibration", "benchmark-receipt", "receipt-validation")):
        return "calibration"
    if any(token in text for token in ("juice-shop", "juiceshop", "crapi", "webgoat", "dvwa", "demo.")):
        return "demo"
    if str(exposure_class or "").lower() == "internal":
        return "internal"
    try:
        host = (urlsplit(str(url)).hostname or "").lower()
    except ValueError:
        host = ""
    raw_locator = str(url or "").strip().lower()
    if not host and "://" not in raw_locator:
        authority = raw_locator.split("/", 1)[0].rsplit("@", 1)[-1]
        host = authority.rsplit(":", 1)[0].strip("[]")
    if host in {"localhost", "host.docker.internal"} or host.endswith((".local", ".localhost", ".internal", ".test")) or host.isdigit():
        return "internal"
    if host and "." not in host and ":" not in host:
        return "internal"
    try:
        if host and ipaddress.ip_address(host).is_private:
            return "internal"
    except ValueError:
        pass
    if any(token in text for token in ("honey", "sandbox", "testbed", "lab.")):
        return "lab"
    return "unclassified"
