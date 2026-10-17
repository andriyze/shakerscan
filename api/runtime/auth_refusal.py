"""Whether a verifier's baseline response was the target refusing an unauthenticated request.

A verifier compares the target's answer to a control request with its answers to payloads. When
the control is a 401/403/407, or a redirect to a login page, every payload meets the same wall:
the code under test never ran, and "no difference" is not "not vulnerable". Lab Scan 13bd3497
(2.11.0) replayed browser-captured ``/hub/api/<name>/1`` routes without the captured session (a
capture never keeps credentials); each answered 401, sqlmap stopped after one request per
technique, and every technique was recorded as a settled negative.

The answer of an authentication endpoint is the exception: a login form answers a wrong password
with 401 or 403 by design, and that answer is what its injection tests compare against. Callers
decide which candidates are authentication endpoints; this module only reads responses.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Mapping
from typing import Any

AUTHENTICATION_REQUIRED = "authentication_required"
# The record of an external verifier's first (baseline) response, from its own wire log.
BASELINE_RECORD_KIND = "verifier_baseline_response"
AUTH_REFUSAL_STATUSES = frozenset({401, 403, 407})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# The last path segment of a sign-in page. Matched on the Location's path only (never its query,
# which may carry a return URL or a token).
_LOGIN_LEAF = re.compile(
    r"^(?:log[-_]?in|sign[-_]?in|signon|sso|authenticate|authorize)(?:\.[a-z]{2,5})?$",
    re.IGNORECASE,
)


def is_login_location(location: Any) -> bool:
    """True when a redirect's Location path ends at a sign-in page (``/hub/login``)."""
    try:
        path = urllib.parse.urlsplit(str(location or "")).path
    except ValueError:
        return False
    segments = [item for item in path.split("/") if item]
    return bool(segments) and bool(_LOGIN_LEAF.match(segments[-1]))


def _location(headers: Mapping[str, Any] | None) -> str | None:
    for name, value in dict(headers or {}).items():
        if str(name).lower() == "location":
            return str(value)
    return None


def refusal_status(status: Any, headers: Mapping[str, Any] | None = None) -> int | None:
    """The status code with which the target refused the request, or None.

    401, 403 and 407 refuse it outright; a redirect refuses it when it sends the client to a
    sign-in page.
    """
    if isinstance(status, bool):
        return None
    try:
        code = int(status)
    except (TypeError, ValueError):
        return None
    if code in AUTH_REFUSAL_STATUSES:
        return code
    if code in REDIRECT_STATUSES and is_login_location(_location(headers)):
        return code
    return None


def refusal_error(code: int) -> str:
    """The error token a verifier reports for a refused baseline (``authentication_required:401``)."""
    return f"{AUTHENTICATION_REQUIRED}:{int(code)}"


__all__ = [
    "AUTHENTICATION_REQUIRED", "AUTH_REFUSAL_STATUSES", "BASELINE_RECORD_KIND", "is_login_location", "refusal_error",
    "refusal_status",
]
