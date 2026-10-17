"""An external verifier run whose baseline the target refused is inconclusive, not negative.

sqlmap and Dalfox compare payload answers against the target's answer to the original request.
The worker records that first answer from the tool's own wire log
(``agent_tools.parse_scanner_output``). When the target refused it (``runtime.auth_refusal``),
the payloads were measured against a refusal: lab Scan 13bd3497 (2.11.0) replayed
browser-captured ``/hub/api/<name>/1*`` routes without the captured session, sqlmap stopped
after one request per technique, and each technique was recorded as a settled negative.

Such a run is reported ``partial`` with ``authentication_required:<status>`` or
``target_refused:<status>``, so the candidate stays unverified for a stated reason. A run that
found something keeps its finding. Only an authentication endpoint is exempt (a login form
answers a wrong password with 401/403, and sqlmap tests it with ``--ignore-code`` on purpose).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Mapping
from typing import Any

try:
    from runtime.auth_refusal import (
        BASELINE_RECORD_KIND,
        is_authentication_candidate,
        refusal,
        refusal_error,
        refusal_reason,
    )
except ModuleNotFoundError:  # package import layout
    from ..runtime.auth_refusal import (
        BASELINE_RECORD_KIND,
        is_authentication_candidate,
        refusal,
        refusal_error,
        refusal_reason,
    )

REFUSAL_RECORD_KIND = "verifier_refused"
# Records that are a tool's positive signal: a run that produced one is never reclassified.
_FINDING_KINDS = frozenset({"sqli_finding", "xss_alert"})


def refused_baseline(observations: Iterable[Any]) -> tuple[int, str] | None:
    """``(status, reason)`` with which the target refused a run's baseline, or None."""
    for item in observations or ():
        if isinstance(item, Mapping) and item.get("kind") == BASELINE_RECORD_KIND:
            return refusal(
                item.get("http_status"),
                login_redirect=bool(item.get("login_redirect")),
                www_authenticate=bool(item.get("www_authenticate")),
            )
    return None


# The external verifiers whose baseline the worker records.
_BASELINE_VERIFIERS = frozenset({"sqlmap", "dalfox"})


def refusal_exempt(tool: str, candidate: Mapping[str, Any]) -> bool:
    """Whether a run's refused baseline is the candidate's real answer, not a refusal.

    Only for sqlmap on an authentication endpoint (``auth_refusal.is_authentication_candidate``):
    a login form answers a wrong password with 401/403, and sqlmap tests it with
    ``--ignore-code`` on purpose. Any other body -- a captured ``POST /api/orders`` replayed
    without its session -- answers 401 because it was refused. Dalfox is never exempt.
    """
    if tool not in _BASELINE_VERIFIERS:
        return True
    return tool == "sqlmap" and is_authentication_candidate(candidate)


def is_refusal_error(value: Any) -> bool:
    """True for the error token of a refused run (``authentication_required:401``)."""
    return refusal_reason(value) is not None


def mark_refused(result: Any, *, exempt: bool) -> Any:
    """``result`` reported as refused when the target refused its baseline, else unchanged."""
    if exempt or not dataclasses.is_dataclass(result):
        return result
    if str(getattr(result, "status", "")) in {"cancelled", "failed", "blocked"}:
        return result
    observations = tuple(getattr(result, "observations", ()) or ())
    if any(isinstance(item, Mapping) and item.get("kind") in _FINDING_KINDS for item in observations):
        return result
    refused = refused_baseline(observations)
    if refused is None:
        return result
    status, reason = refused
    return dataclasses.replace(
        result,
        status="partial",
        partial=True,
        errors=(refusal_error(status, reason), *tuple(getattr(result, "errors", ()) or ())),
        observations=(*observations, {
            "kind": REFUSAL_RECORD_KIND, "reason": reason, "http_status": status,
        }),
    )


__all__ = [
    "REFUSAL_RECORD_KIND", "is_refusal_error", "mark_refused", "refusal_exempt", "refused_baseline",
]
