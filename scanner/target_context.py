"""Target context helpers for scan reporting and grading."""

from __future__ import annotations

import ipaddress
import urllib.parse


LOCAL_LAB_HOSTNAMES = {
    "localhost",
    "host.docker.internal",
    "gateway.docker.internal",
    "docker.for.mac.localhost",
    "docker.for.win.localhost",
}

LOCAL_LAB_SUFFIXES = (
    ".localhost",
    ".local",
    ".test",
    ".example",
    ".invalid",
)


def normalize_target_host(value: str | None) -> str:
    """Extract a normalized hostname from a host or URL-like value."""
    raw = (value or "").strip()
    if not raw:
        return ""

    parsed = urllib.parse.urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw.split("/", 1)[0].split(":", 1)[0]
    return host.strip("[]").rstrip(".").lower()


def is_local_or_private_scan_target(value: str | None) -> bool:
    """Return True for lab/private targets where public internet posture is not applicable."""
    host = normalize_target_host(value)
    if not host:
        return False

    if host in LOCAL_LAB_HOSTNAMES or host.endswith(LOCAL_LAB_SUFFIXES):
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
