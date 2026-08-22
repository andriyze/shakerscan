"""Compatibility hardening loaded while request replay is migrated into the native V2 runtime.

The V2 executor was introduced before two small pieces of its public contract landed in the
packaged request-replay module. Keep the compatibility layer explicit and idempotent so older
worker images fail safe rather than crashing before transport admission. This module can be
removed once the methods are defined directly on ``ReplayPlan`` in every supported release.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

from . import request_replay as _request_replay


_SENSITIVE_PATH_KEYS = frozenset({
    "access", "access-token", "access_token", "auth", "authorization", "bearer",
    "code", "confirm", "confirmation", "credential", "invite", "key", "magic",
    "password", "recover", "recovery", "reset", "secret", "session", "signature",
    "signed", "token", "verify", "verification",
})
_HEX_SECRET_RE = re.compile(r"^[0-9a-f]{24,}$", re.IGNORECASE)
_TOKENISH_RE = re.compile(r"^[A-Za-z0-9_-]{32,}$")
_JWTISH_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){1,2}$")


def _segment_is_sensitive(segment: str, previous: str | None) -> bool:
    decoded = urllib.parse.unquote(segment).strip()
    lowered = decoded.lower()
    if not decoded:
        return False
    if previous and previous.lower() in _SENSITIVE_PATH_KEYS:
        return True
    if lowered in _SENSITIVE_PATH_KEYS:
        return False
    if "=" in lowered:
        key, _separator, value = lowered.partition("=")
        if key in _SENSITIVE_PATH_KEYS and value:
            return True
    return bool(
        _HEX_SECRET_RE.fullmatch(decoded)
        or _JWTISH_RE.fullmatch(decoded)
        or _TOKENISH_RE.fullmatch(decoded)
    )


def redact_url_path(path: str) -> str:
    """Redact secret-bearing path segments while preserving route shape."""
    segments = str(path or "/").split("/")
    result: list[str] = []
    previous: str | None = None
    for segment in segments:
        decoded = urllib.parse.unquote(segment).strip()
        result.append("<redacted>" if _segment_is_sensitive(segment, previous) else segment)
        previous = decoded
    rendered = "/".join(result)
    return rendered if rendered.startswith("/") else f"/{rendered}"


def _redacted_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(str(value or ""))
    query = urllib.parse.urlencode([
        (str(name)[:200], "<redacted>")
        for name, _item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    ])
    return urllib.parse.urlunsplit((
        parsed.scheme,
        parsed.netloc,
        redact_url_path(parsed.path or "/"),
        query,
        "",
    ))[:2_000]


def _estimated_budget(plan: Any) -> dict[str, int]:
    state_changing = sum(
        request.method in _request_replay.STATE_CHANGING_METHODS
        for request in plan.requests
    )
    result = {"http_requests": len(plan.requests)}
    if state_changing:
        result["state_changing_requests"] = int(state_changing)
    return result


def apply_request_replay_hardening() -> None:
    if not isinstance(getattr(_request_replay.ReplayPlan, "estimated_budget", None), property):
        setattr(_request_replay.ReplayPlan, "estimated_budget", property(_estimated_budget))
    _request_replay.redact_url_path = redact_url_path
    _request_replay._redacted_url = _redacted_url


apply_request_replay_hardening()
