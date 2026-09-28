"""Method-aware Hunt HTTP admission, shared by API and worker.

The existing http.request identity remains usable by saved principals. A PUT is
not a different target or a new credential capability: it consumes the standing
Hunt's explicitly enabled state-changing authority and existing budgets.
"""
from __future__ import annotations

import json
from typing import Any, Mapping

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
BODY_FIELDS = ("json_body", "form_body")


def validate_http_request_input(values: Mapping[str, Any]) -> None:
    """Validate cross-field rules without modifying the requested experiment.

    The capability registry owns field/type/size validation. This helper also
    runs in the worker, so a queued request cannot evade the same shape checks.
    """
    method = values.get("method")
    if not isinstance(method, str) or method not in READ_METHODS | WRITE_METHODS:
        raise ValueError("http.request requires GET, HEAD, OPTIONS, POST, PUT, PATCH or DELETE")
    bodies = [field for field in BODY_FIELDS if field in values]
    if len(bodies) > 1:
        raise ValueError("http.request accepts either json_body or form_body, not both")
    if bodies:
        body = values[bodies[0]]
        if not isinstance(body, dict):
            raise ValueError(f"{bodies[0]} must be an object")
        if method not in WRITE_METHODS:
            raise ValueError("request bodies require an explicitly authorized write method")
        try:
            json.dumps(body, allow_nan=False, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("request body must contain finite JSON values") from exc
        if bodies[0] == "form_body":
            for value in body.values():
                items = value if isinstance(value, list) else [value]
                if any(not isinstance(item, (str, int, float, bool, type(None))) for item in items):
                    raise ValueError("form_body values must be scalars or lists of scalars")
    if method in WRITE_METHODS and values.get("follow_redirects") is True:
        raise ValueError(
            "write redirects are returned without replay; set follow_redirects=false "
            "and issue an explicit next request when required"
        )


def require_http_request_authority(
    values: Mapping[str, Any], policy: Mapping[str, Any],
    *, requested_budget: Mapping[str, int] | None = None,
) -> bool:
    """Return whether this action writes, using saved server authority only.

    This does not create/replace an approval receipt. The caller must retain the
    existing target-bound approval revalidation, reservation and cancellation.
    """
    validate_http_request_input(values)
    writes = values["method"] in WRITE_METHODS
    if not writes:
        return False
    if policy.get("active_testing") is not True or policy.get("allow_state_changing_http") is not True:
        raise ValueError(
            "http.request write requires this Hunt's active_testing and "
            "allow_state_changing_http permissions; reuse standing target authorization"
        )
    if requested_budget is not None:
        for dimension in ("http_requests", "state_changing_requests", "active_actions"):
            value = requested_budget.get(dimension)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"HTTP write reservation lacks {dimension}")
    return True


def redact_http_request_body(values: Mapping[str, Any]) -> dict[str, Any]:
    """Keep body presence/kind visible without values or brute-forceable PIN hashes.

    Request-body bytes belong only in the existing explicitly sensitive archive.
    """
    result = dict(values)
    for field in BODY_FIELDS:
        if field in result:
            result.pop(field)
            result["body_kind"] = "json" if field == "json_body" else "form"
            result["body_values_visible"] = False
    return result
