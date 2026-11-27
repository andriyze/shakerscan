"""Canonical target cohort labels used by inventory and executive read models."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

try:
    from scope.psl import SHARED_DNS_SUFFIXES
except ModuleNotFoundError:  # package import layout
    from .scope.psl import SHARED_DNS_SUFFIXES


TARGET_COHORTS = (
    "production", "staging", "lab", "demo", "calibration", "internal",
)


_OCTET = re.compile(r"^[0-9]{1,3}$")
_DNS_LABEL = re.compile(r"^[a-z0-9-]{1,63}$")


def wildcard_dns_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address a wildcard-DNS name resolves to, read from the name; None for any other name.

    Every name under a ``SHARED_DNS_SUFFIXES`` service resolves to the address written in the
    labels just before the suffix, with dots or dashes: ``app.10.0.0.5.nip.io``,
    ``10-0-0-5.sslip.io`` and ``billing.shop-10-0-0-5.sslip.io`` are 10.0.0.5. sslip.io also
    takes an IPv6 address with dashes for colons as the label before it (``--1.sslip.io`` is
    ::1). ``host`` is lowercase without a trailing dot; a name that is not a valid DNS name
    (a label over 63 characters, over 253 in all) is not read.
    """
    suffix = next((s for s in SHARED_DNS_SUFFIXES if host.endswith("." + s)), None)
    if suffix is None or len(host) > 253:
        return None
    labels = host[: -len(suffix) - 1].split(".")
    if not all(_DNS_LABEL.match(label) for label in labels):
        return None
    tokens = re.split(r"[.-]", ".".join(labels))[-4:]
    if len(tokens) == 4 and all(_OCTET.match(token) for token in tokens):
        try:
            return ipaddress.IPv4Address(".".join(tokens))
        except ValueError:  # an octet over 255 or with a leading zero
            pass
    if suffix == "sslip.io" and "-" in labels[-1]:
        try:
            return ipaddress.IPv6Address(labels[-1].replace("-", ":"))
        except ValueError:
            pass
    return None


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
    # A wildcard-DNS name resolves to the address written in it, so 10-0-0-5.sslip.io is as
    # internal as 10.0.0.5.
    encoded = wildcard_dns_address(host)
    if encoded is not None and not encoded.is_global:
        return "internal"
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
