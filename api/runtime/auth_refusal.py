"""Whether a verifier's baseline response was the target refusing the request it replayed.

A verifier compares the target's answer to a control request with its answers to payloads. When
the control is refused, every payload meets the same wall: the code under test never ran, and
"no difference" is not "not vulnerable". Lab Scan 13bd3497 (2.11.0) replayed browser-captured
``/hub/api/<name>/1`` routes without the captured session (a capture never keeps credentials);
each answered 401, sqlmap stopped after one request per technique, and every technique was
recorded as a settled negative.

Two refusals are told apart, because they call for different action:

* ``authentication_required`` -- 401, 407, a 403 that asks for credentials
  (``WWW-Authenticate``), or a redirect to a sign-in page. Every request without a session meets
  it, so a verifier stops at once; a credential profile is the remedy.
* ``target_refused`` -- any other 403: a WAF rejecting the tool's user agent, or an ownership
  check that only some payloads may get past. Payloads can still change the answer, so a
  verifier keeps testing, but a negative measured against the refusal is not a verdict.

The answer of an authentication endpoint is the exception: a login form answers a wrong password
with 401 or 403 by design, and that answer is what its injection tests compare against
(``is_authentication_candidate``).

A proof can also meet a service that did not serve the page it tests (``unavailable_status``):
``target_unavailable`` is no refusal with a remedy, but what was measured against it is no
verdict either.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Iterable, Mapping
from typing import Any

AUTHENTICATION_REQUIRED = "authentication_required"
TARGET_REFUSED = "target_refused"
REFUSAL_REASONS = frozenset({AUTHENTICATION_REQUIRED, TARGET_REFUSED})
# The service, not the code under test, decided a proof's answers: it was down, overloaded or
# rate-limiting, or the route was missing or failing on every request.
TARGET_UNAVAILABLE = "target_unavailable"
# Answers that say the service decided: one of these anywhere leaves a proof's comparisons
# meaningless. A missing page or a server error does so when every answer met one.
UNAVAILABLE_STATUSES = frozenset({408, 429, 502, 503, 504})
MISSING_STATUSES = frozenset({404, 410})
# The record of an external verifier's first (baseline) response, from its own wire log.
BASELINE_RECORD_KIND = "verifier_baseline_response"
AUTH_REFUSAL_STATUSES = frozenset({401, 403, 407})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# A sign-in page: its last path segment, optionally with a page extension (never a stylesheet,
# script or image: /static/login.css is not a sign-in page), or an OAuth/OIDC authorization
# endpoint (``/oauth2/authorize``, Keycloak's ``/protocol/openid-connect/auth``). Matched on the
# Location's path only, never its query, which may carry a return URL or a token.
_PAGE_EXTENSION = r"(?:\.(?:php|html?|aspx?|jsp|do|cgi))?"
_LOGIN_LEAF = re.compile(
    rf"^(?:log[-_]?in|sign[-_]?in|signon|sso|authenticate|authorize|auth){_PAGE_EXTENSION}$",
    re.IGNORECASE,
)
_AUTHORIZATION_PATH = re.compile(
    r"/(?:protocol/openid-connect/auth|oauth2?/(?:v\d+(?:\.\d+)?/)?authorize|connect/authorize)/?$",
    re.IGNORECASE,
)
# Whole path segments that name an authentication endpoint (``/hub/login``, ``/oauth/token``),
# and the prefixes whose last or second-to-last segment is one (``/auth/login``, ``/session/new``).
# Whole segments only: ``/api/authors``, ``/api/sessions/123/notes`` and ``/api/loginhistory``
# are application routes, not authentication endpoints.
_AUTHENTICATION_SEGMENTS = frozenset({
    "login", "log-in", "log_in", "signin", "sign-in", "sign_in", "logon", "authenticate", "token",
})
_AUTHENTICATION_PREFIXES = frozenset({"auth", "session"})


def is_authentication_path(path: Any) -> bool:
    """Whether a route path names an authentication endpoint, by whole segments."""
    try:
        text = urllib.parse.urlsplit(str(path or "")).path
    except ValueError:
        return False
    segments = [item.lower() for item in text.split("/") if item]
    return any(
        item in _AUTHENTICATION_SEGMENTS
        or (item in _AUTHENTICATION_PREFIXES and index >= len(segments) - 2)
        for index, item in enumerate(segments)
    )


def is_login_location(location: Any) -> bool:
    """True when a redirect's Location path is a sign-in page (``/hub/login``)."""
    try:
        path = urllib.parse.urlsplit(str(location or "")).path
    except ValueError:
        return False
    if _AUTHORIZATION_PATH.search(path):
        return True
    segments = [item for item in path.split("/") if item]
    return bool(segments) and bool(_LOGIN_LEAF.match(segments[-1]))


def is_authentication_candidate(candidate: Mapping[str, Any]) -> bool:
    """Whether a candidate is an authentication endpoint, whose 401/403 is its real answer."""
    if str(candidate.get("request_class") or "") == "safe_authentication":
        return True
    return bool(candidate.get("body_field_names")) and is_authentication_path(
        candidate.get("canonical_path") or candidate.get("path"),
    )


def is_login_form_request(url: Any, body: Any) -> bool:
    """Whether a replayed body request posts to a sign-in endpoint (its last segment is one).

    Stricter than ``is_authentication_path``: ``/api/auth/change-password`` or
    ``/api/users/1/token`` replayed without the captured session is refused, not answering a
    wrong password.
    """
    if not body:
        return False
    try:
        path = urllib.parse.urlsplit(str(url or "")).path
    except ValueError:
        return False
    segments = [item for item in path.split("/") if item]
    return bool(segments) and bool(_LOGIN_LEAF.match(segments[-1]))


def request_refusal(
    status: Any, headers: Mapping[str, Any] | None, *,
    request_class: Any, url: Any, body: Any,
) -> tuple[int, str] | None:
    """``refusal`` for a replayed request, less a sign-in form's answer to a wrong password.

    A ``safe_authentication`` request is a login form by its class. A captured or seeded
    ``POST /hub/login`` keeps the ``confirmed_mutation`` class of every replayed body, so its
    path identifies it, and only its 401 (``authentication_required``) is its answer: a plain
    403 (a stale CSRF token, a firewall) is still a refusal.
    """
    if str(request_class or "") == "safe_authentication":
        return None
    refused = refusal(status, headers)
    if refused is not None and refused[1] == AUTHENTICATION_REQUIRED and is_login_form_request(url, body):
        return None
    return refused


def _header(headers: Mapping[str, Any] | None, wanted: str) -> str | None:
    for name, value in dict(headers or {}).items():
        if str(name).lower() == wanted:
            return str(value)
    return None


def refusal(
    status: Any, headers: Mapping[str, Any] | None = None, *,
    login_redirect: bool | None = None, www_authenticate: bool | None = None,
) -> tuple[int, str] | None:
    """``(status, reason)`` when the target refused the request, else None.

    ``login_redirect`` and ``www_authenticate`` stand in for ``headers`` when only a summary of
    the response was kept (a tool's wire log).
    """
    if isinstance(status, bool):
        return None
    try:
        code = int(status)
    except (TypeError, ValueError):
        return None
    challenge = (
        bool(www_authenticate) if www_authenticate is not None
        else _header(headers, "www-authenticate") is not None
    )
    if code in {401, 407} or (code == 403 and challenge):
        return code, AUTHENTICATION_REQUIRED
    if code == 403:
        return code, TARGET_REFUSED
    if code in REDIRECT_STATUSES and (
        bool(login_redirect) if login_redirect is not None
        else is_login_location(_header(headers, "location"))
    ):
        return code, AUTHENTICATION_REQUIRED
    return None


def unavailable_status(statuses: Iterable[Any]) -> int | None:
    """The status that leaves a proof's answers unusable, or None.

    The first of ``UNAVAILABLE_STATUSES`` among the answers, else the first answer when every
    answer was a missing page or a server error. A request that got no answer (0 or None) is not
    counted. Asked only of a negative: a proof that reproduced still proves its finding. A control
    that was answered, with payloads that met any other client or server error (not 408, 429 or
    502-504), is the route's own answer. The "every answer" half needs such a control: a proof
    that sent the payload alone (a browser proof of a query or body parameter) may have met the
    application's own 404 or 500 for that payload, so it reads only ``UNAVAILABLE_STATUSES``.
    """
    answered: list[int] = []
    for item in statuses or ():
        if isinstance(item, bool):
            continue
        try:
            code = int(item)
        except (TypeError, ValueError):
            continue
        if code > 0:
            answered.append(code)
    blocking = next((code for code in answered if code in UNAVAILABLE_STATUSES), None)
    if blocking is not None:
        return blocking
    if answered and all(code in MISSING_STATUSES or code >= 500 for code in answered):
        return answered[0]
    return None


def refusal_status(status: Any, headers: Mapping[str, Any] | None = None) -> int | None:
    """The status code with which the target refused the request, or None."""
    refused = refusal(status, headers)
    return refused[0] if refused else None


def refusal_error(code: int, reason: str = AUTHENTICATION_REQUIRED) -> str:
    """The error a verifier reports for a refused baseline (``authentication_required:401``)."""
    return f"{reason}:{int(code)}"


def refusal_reason(error: Any) -> str | None:
    """The refusal reason an error token names, or None (``target_refused:403`` -> reason)."""
    token = str(error or "").strip().lower().split(":", 1)[0]
    return token if token in REFUSAL_REASONS else None


__all__ = [
    "AUTHENTICATION_REQUIRED", "AUTH_REFUSAL_STATUSES", "BASELINE_RECORD_KIND",
    "MISSING_STATUSES", "REFUSAL_REASONS", "TARGET_REFUSED", "TARGET_UNAVAILABLE",
    "UNAVAILABLE_STATUSES", "is_authentication_candidate", "is_authentication_path",
    "is_login_location",
    "refusal", "refusal_error", "refusal_reason", "refusal_status", "unavailable_status",
]
