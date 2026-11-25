"""The planner contract of ``request.verify``: its checks, inputs and hold.

Declared in the runtime layer, beside the registry that publishes it, so the registry does not
import the verifiers. ``hunt/request_verification.py`` runs it; a test keeps ``CHECKS`` equal to the
checks the verifiers implement.
"""
from __future__ import annotations

from typing import Any, Mapping

CHECKS: tuple[str, ...] = (
    "template_injection", "path_traversal", "command_injection", "xxe", "ssrf", "nosql_injection",
    "open_redirect", "crlf_injection", "host_header_injection", "cors", "security_headers",
    "directory_listing", "graphql", "file_upload", "rate_limit", "csrf", "ldap_injection", "jwt",
)
# What one call holds: the longest check (blind command injection: a baseline, seven echo
# probes, the substitution probes, two Windows probes and a seven-request timing confirmation; a
# rate-limit run of twelve attempts) with room for the repeat and the control. Settled to what
# was sent.
HOLD: Mapping[str, int] = {"http_requests": 48, "tool_wall_seconds": 120}

DESCRIPTION = (
    "Prove one vulnerability class on one exact request with a deterministic differential: a "
    "repeat with fresh random values and a negative control that must stay silent. A verified "
    "result becomes a finding; anything else stays an observation. Name the request as for "
    "http.request (method, path, query, json_body/form_body/xml_body, headers, identity) plus "
    "check and, for an input check, parameter. Checks: command_injection, path_traversal (GET), "
    "template_injection, xxe (xml_body), ssrf (GET, in-band loopback), nosql_injection, "
    "ldap_injection, crlf_injection, open_redirect take parameter; host_header_injection, cors, "
    "security_headers, directory_listing, graphql (the endpoint), jwt (as a principal with a "
    "bearer token), csrf (a signed-in write; token_field), rate_limit (a sign-in POST; parameter "
    "= password field) and file_upload (parameter = file field; retrieve_path with {filename}) "
    "test the request. Needs active testing; a write method or an upload needs state-changing "
    "permission (held as verifier writes)."
)

_FIELD = {"type": "string", "minLength": 1, "maxLength": 200,
          "description": "The input to test: a query parameter, form field or JSON field path "
                         "(user.name). Not used by checks that test the request itself."}


def input_properties(origin: Mapping[str, Any], as_principal: Mapping[str, Any],
                     request_bindings: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "check": {"type": "string", "enum": list(CHECKS)},
        "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]},
        "origin": origin,
        "path": {"type": "string", "minLength": 1, "maxLength": 2_048, "pattern": r"^/(?!/)[^\r\n]*$"},
        "query": {"type": "object", "maxProperties": 32},
        "headers": {"type": "object", "maxProperties": 16},
        "json_body": {"type": "object"},
        "form_body": {"type": "object", "maxProperties": 32},
        "xml_body": {"type": "string", "minLength": 1, "maxLength": 32_768},
        "parameter": _FIELD,
        "retrieve_path": {"type": "string", "minLength": 2, "maxLength": 2_048,
                          "pattern": r"^/(?!/)[^\r\n]*\{filename\}[^\r\n]*$",
                          "description": "file_upload: where an uploaded file is served, with {filename}."},
        "token_field": {"type": "string", "minLength": 1, "maxLength": 200,
                        "description": "csrf: the anti-CSRF form or JSON field, emptied in the forged request."},
        "as_principal": as_principal,
        "session_ref": {
            "type": "string",
            "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        },
        "request_bindings": request_bindings,
    }


__all__ = ["CHECKS", "DESCRIPTION", "HOLD", "input_properties"]
