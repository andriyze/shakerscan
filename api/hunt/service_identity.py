"""Which service a Hunt finding was proven on.

Kept apart from the finding writers so the XSS and authorization materializers can both
use it without importing each other.
"""
from __future__ import annotations

import urllib.parse


def _origin(value: urllib.parse.SplitResult) -> tuple[str, str | None, int | None]:
    scheme = value.scheme.lower()
    default_port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, value.hostname, value.port or default_port


def service_identity_suffix(service_url: str, *, target_url: str) -> str:
    """Qualify a Hunt finding identity with the service it was proven on.

    Scan's templated identity keeps the path and parameter names only. A Hunt may reuse
    its authority on other services of the same host, so the same route on another
    scheme/port is a different endpoint and must not share (and overwrite) a row. The Hunt
    target's own service, under any default-port spelling, gets no suffix, which keeps the
    fingerprints of rows proven there before this qualifier existed.
    """
    service = _origin(urllib.parse.urlsplit(str(service_url)))
    try:
        baseline = _origin(urllib.parse.urlsplit(str(target_url)))
    except ValueError:
        baseline = None
    if service == baseline:
        return ""
    return f"|service={service[0]}://{service[1]}:{service[2]}"


__all__ = ["service_identity_suffix"]
