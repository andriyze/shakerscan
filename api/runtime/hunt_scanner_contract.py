"""The Hunt planner inputs of the scanner and verifier capabilities that run signed in.

Two additions to the planner projection of the worker scanners:

- **Identity.** ``web.crawl``, ``web.content_discover``, ``templates.scan``, ``xss.verify`` and
  ``sqli.verify`` take the Hunt's managed principal (``as_principal``) or one of its sessions
  (``session_ref``), or the session cookie the Hunt's own login captured (``request_bindings``
  naming an ``http.request`` Set-Cookie capture), and send it on every request, as a Scan sends
  its sign-in. ``web.browser_crawl``
  does not: the headless browser does not reliably carry request headers on the requests the
  application makes itself, so its Hunt schema offers no identity.
- **Body input.** ``xss.verify`` and ``sqli.verify`` may test a request body instead of a URL
  parameter: ``method``, ``body_field_names`` (every top-level field the endpoint expects) and the
  ``injection_field`` the claim is about. The body is sent with every field set to an inert
  placeholder and the tool's own payloads go into the fields, exactly as for a Scan body
  candidate. A body test sends POST/PUT/PATCH requests, so it needs the Hunt's state-changing
  permission; its requests are counted in the verifier's own hold, not in the Hunt's
  state-changing ceiling, which bounds the planner's own writes.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping

# Worker scanners that can carry an HTTP identity (the fixed adapters' header flags).
SIGNED_IN_SCANNERS = frozenset({
    "web.crawl", "web.content_discover", "templates.scan", "xss.verify", "sqli.verify",
})
BODY_INPUT_VERIFIERS = frozenset({"xss.verify", "sqli.verify"})

_SESSION_REF_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
HUNT_SCANNER_SESSION_PROPERTIES: Mapping[str, Any] = MappingProxyType({
    "session_ref": {
        "type": "string", "pattern": _SESSION_REF_PATTERN,
        "description": "Run signed in with this session of the Hunt; or name as_principal "
                       "or request_bindings instead, only one.",
    },
    # The session cookie this Hunt's own login captured (an http.request Set-Cookie capture),
    # sent as the Cookie header of every request: the capture's reference, never its value.
    "request_bindings": {
        "type": "array", "minItems": 1, "maxItems": 1,
        "description": "Run signed in with the session cookie a login of this Hunt captured: "
                       "[{source_action_id, capture_name, header: \"Cookie\"}] naming an "
                       "http.request Set-Cookie capture. Needs active testing.",
        "items": {
            "type": "object", "additionalProperties": False,
            "required": ["source_action_id", "capture_name", "header"],
            "properties": {
                "source_action_id": {
                    "type": "string", "maxLength": 36,
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                },
                "capture_name": {"type": "string", "pattern": r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$"},
                "header": {"type": "string", "enum": ["Cookie"]},
            },
        },
    },
})

_FIELD_NAME = r"^[A-Za-z0-9_\-\[\]]{1,64}$"
HUNT_INJECTION_BODY_PROPERTIES: Mapping[str, Any] = MappingProxyType({
    "method": {
        "type": "string", "enum": ["POST", "PUT", "PATCH"],
        "description": "Test a request body sent with this method instead of a URL parameter "
                       "(with body_field_names and injection_field). Needs the Hunt's "
                       "state-changing permission.",
    },
    "content_type": {
        "type": "string", "enum": ["application/x-www-form-urlencoded", "application/json"],
        "description": "The body encoding; a form body when omitted.",
    },
    "body_field_names": {
        "type": "array", "minItems": 1, "maxItems": 32,
        "items": {"type": "string", "pattern": _FIELD_NAME},
        "description": "Every top-level field the endpoint expects (a login form's username and "
                       "password, for example); each is sent with a placeholder and tested.",
    },
    "injection_field": {
        "type": "string", "pattern": _FIELD_NAME,
        "description": "The field the claim is about; one of body_field_names.",
    },
})
_BODY_KEYS = frozenset(HUNT_INJECTION_BODY_PROPERTIES)


class HuntScannerInputError(ValueError):
    """A scanner planner input the contract refuses."""


def hunt_body_input(value: Mapping[str, Any]) -> bool:
    """Whether a Hunt verifier call tests a request body rather than its URL."""
    return any(key in value for key in _BODY_KEYS)


def captured_login_request(value: Mapping[str, Any]) -> bool:
    """Whether the call sends a session cookie this Hunt's login captured."""
    return bool(value.get("request_bindings"))


def signed_in_request(value: Mapping[str, Any]) -> bool:
    """Whether the call names a managed principal, a session or a captured login."""
    slot = str(value.get("as_principal") or "").strip().lower()
    return (bool(value.get("session_ref")) or captured_login_request(value)
            or slot not in {"", "anonymous", "anon", "none"})


def validate_hunt_scanner_input(name: str, value: Mapping[str, Any]) -> None:
    """The cross-field rules a schema cannot state, for the scanners' planner inputs."""
    named = sum((
        bool(value.get("session_ref")), captured_login_request(value),
        str(value.get("as_principal") or "").strip().lower() not in {"", "anonymous", "anon", "none"},
    ))
    if named > 1:
        raise HuntScannerInputError(
            f"{name} runs as one identity: session_ref, as_principal or request_bindings")
    if not hunt_body_input(value):
        return
    if name not in BODY_INPUT_VERIFIERS:
        raise HuntScannerInputError(f"{name} does not test a request body")
    missing = sorted({"method", "body_field_names", "injection_field"} - set(value))
    if missing:
        raise HuntScannerInputError(
            f"{name} body input needs method, body_field_names and injection_field "
            f"(missing: {', '.join(missing)})"
        )
    fields = list(value["body_field_names"])
    if len(set(fields)) != len(fields):
        raise HuntScannerInputError(f"{name} body_field_names must be distinct")
    if value["injection_field"] not in fields:
        raise HuntScannerInputError(f"{name} injection_field must be one of body_field_names")
    if value.get("deep_domxss") is True:
        raise HuntScannerInputError(
            "xss.verify deep_domxss verifies a URL parameter, not a request body"
        )


__all__ = [
    "BODY_INPUT_VERIFIERS", "HUNT_INJECTION_BODY_PROPERTIES", "HUNT_SCANNER_SESSION_PROPERTIES",
    "HuntScannerInputError", "SIGNED_IN_SCANNERS", "captured_login_request", "hunt_body_input",
    "signed_in_request",
    "validate_hunt_scanner_input",
]
