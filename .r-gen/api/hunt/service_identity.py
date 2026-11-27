"""Which service a Hunt finding was proven on.

Kept apart from the finding writers so the XSS and authorization materializers can both
use it without importing each other.
"""
from __future__ import annotations

import urllib.parse

try:
    from finding_service_identity import service_suffix
except ModuleNotFoundError:
    from scanner.finding_service_identity import service_suffix


def _origin(value: urllib.parse.SplitResult) -> tuple[str, str | None, int | None]:
    scheme = value.scheme.lower()
    default_port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, value.hostname, value.port or default_port


def service_identity_suffix(service_url: str, *, target_url: str) -> str:
    """Use the same absolute service qualifier as Scan, independent of Hunt's baseline."""
    return service_suffix(service_url)


__all__ = ["service_identity_suffix"]
