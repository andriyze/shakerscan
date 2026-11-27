"""Fail-closed detection for raw secret material at canonical queue boundaries."""

from __future__ import annotations

import re
from typing import Any, Mapping


_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SENSITIVE_PARTS = frozenset({
    "authorization", "auth", "bearer", "cookie", "credential", "password",
    "passwd", "private", "secret", "signature", "token", "session", "jwt",
})
_INLINE_SECRET_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[^\s,;]+"),
    re.compile(
        r"(?i)\b(?:authorization|cookie|set-cookie|x-api-key|api-key)\s*[:=]\s*"
        r"[^\s,;]+"
    ),
    re.compile(
        r"(?i)[?&](?:access_token|refresh_token|token|api_key|apikey|secret|"
        r"password|signature|session|jwt)=[^&#\s]+"
    ),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
)


def sensitive_key(value: Any) -> bool:
    """Return whether a field name conventionally carries credentials or secrets."""
    expanded = _CAMEL_BOUNDARY_RE.sub("_", str(value or ""))
    parts = tuple(
        part for part in re.split(r"[^A-Za-z0-9]+", expanded.lower()) if part
    )
    if not parts:
        return False
    return bool(
        any(part in _SENSITIVE_PARTS for part in parts)
        or "_".join(parts) in {
            "access_token", "refresh_token", "api_key", "private_key",
            "client_secret", "session_id", "session_token",
        }
    )


def contains_secret_material(value: Any, *, key: str | None = None) -> bool:
    """Detect raw secrets without accepting redaction as an execution mechanism.

    Canonical capability queues may carry bounded public arguments, but secret values
    must be represented by credential references and resolved only on the worker.
    """
    if key and sensitive_key(key) and value not in (None, "", [], {}, ()):
        return True
    if isinstance(value, Mapping):
        return any(
            contains_secret_material(nested, key=str(item_key))
            for item_key, nested in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(contains_secret_material(item) for item in value)
    if isinstance(value, bytes):
        return bool(value)
    if isinstance(value, str):
        return any(pattern.search(value) for pattern in _INLINE_SECRET_PATTERNS)
    return False
