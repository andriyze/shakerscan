"""Pure, content-free HTTP origin handling for discovery and report projections.

These helpers describe observations; they never follow redirects or grant scope.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urljoin, urlsplit

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def http_origin(value: Any) -> str | None:
    """Normalize scheme, IDNA hostname and effective port without retaining userinfo."""
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        return None
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        host = parsed.hostname.lower().rstrip(".")
        if ":" in host:
            host = f"[{ipaddress.IPv6Address(host)}]" if "%" not in host else ""
        else:
            host = host.encode("idna").decode("ascii")
            if len(host) > 253 or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in host.split(".")
            ):
                return None
        port = parsed.port
        if not host or port is not None and not 1 <= port <= 65535:
            return None
        if port is not None and port != (443 if scheme == "https" else 80):
            host += f":{port}"
        return f"{scheme}://{host}"
    except (ValueError, UnicodeError):
        return None


def redirect_destination(url: Any, location: Any) -> str | None:
    """Resolve relative locations against the actual request, validating both origins."""
    if http_origin(url) is None or not isinstance(location, str) or not location:
        return None
    if "\\" in location or any(ord(char) < 33 or ord(char) == 127 for char in location):
        return None
    try:
        destination = urljoin(url, location)
    except ValueError:
        return None
    return destination if http_origin(destination) is not None else None
