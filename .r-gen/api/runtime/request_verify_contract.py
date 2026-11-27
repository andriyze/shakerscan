"""The planner contract of ``request.verify``: its checks, inputs and hold.

Declared in the runtime layer, beside the registry that publishes it, so the registry does not
import the verifiers. ``hunt/request_verification.py`` runs it; a test keeps ``CHECKS`` equal to the
checks the verifiers implement.
"""
from __future__ import annotations

from typing import Any, Mapping

CHECKS: tuple[str, ...] = (
    "sql_injection", "template_injection", "path_traversal", "command_injection", "xxe", "ssrf", "nosql_injection",
    "open_redirect", "crlf_injection", "host_header_injection", "cors", "security_headers",
    "directory_listing", "graphql", "file_upload", "rate_limit", "csrf", "ldap_injection", "jwt",
    "unauthenticated_api", "exposure",
)
# What one call holds: the longest check (blind command injection: a baseline, seven echo
# probes, the substitution probes, two Windows probes and a seven-request timing confirmation; a
# rate-limit run of twelve attempts) with room for the repeat and the control. Settled to what
# was sent. One minute of wall keeps it a short action (agent_job_concurrency: over a minute is
# long, and a Hunt runs at most two long actions at once), so it never waits behind a scanner.
HOLD: Mapping[str, int] = {"http_requests": 48, "tool_wall_seconds": 60}

DESCRIPTION = (
    "Prove one vulnerability class on one exact request: a repeat with fresh random values and a "
    "negative control that must stay silent; a verified result becomes a finding. Name the request "
    "as for http.request plus check (and parameter for an input check). Input checks: "
    "sql_injection, command_injection, path_traversal (GET), template_injection, xxe (xml_body), "
    "ssrf (GET), nosql_injection, ldap_injection, crlf_injection, open_redirect. Request checks: "
    "host_header_injection, cors, security_headers, directory_listing, exposure and "
    "unauthenticated_api (anonymous GETs), graphql, jwt (bearer principal), csrf (signed-in write; token_field), rate_limit "
    "(sign-in POST; parameter = password field), file_upload (parameter = file field; retrieve_path with {filename}). Needs "
    "active testing; writes and uploads need state-changing permission."
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
