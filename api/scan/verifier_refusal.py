"""An external verifier run whose baseline the target refused is inconclusive, not negative.

sqlmap and Dalfox compare payload answers against the target's answer to the original request.
The worker records that first answer from the tool's own wire log
(``agent_tools.parse_scanner_output``). When it is a 401/403/407, or a redirect to a sign-in
page, the payloads never reached the code under test: lab Scan 13bd3497 (2.11.0) replayed
browser-captured ``/hub/api/<name>/1*`` routes without the captured session, sqlmap stopped
after one request per technique, and each technique was recorded as a settled negative.

Such a run is reported ``partial`` with ``authentication_required:<status>``, so the candidate
stays unverified for a stated reason. A run that found something keeps its finding, and a body
candidate is exempt: sqlmap tests bodies with ``--ignore-code 401/403`` on purpose, because a
login form answers a wrong password that way and that answer is what it is compared against.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Mapping
from typing import Any

try:
    from runtime.auth_refusal import (
        AUTH_REFUSAL_STATUSES,
        AUTHENTICATION_REQUIRED,
        BASELINE_RECORD_KIND,
        refusal_error,
    )
except ModuleNotFoundError:  # package import layout
    from ..runtime.auth_refusal import (
        AUTH_REFUSAL_STATUSES,
        AUTHENTICATION_REQUIRED,
        BASELINE_RECORD_KIND,
        refusal_error,
    )

REFUSAL_RECORD_KIND = "verifier_refused"
# Records that are a tool's positive signal: a run that produced one is never reclassified.
_FINDING_KINDS = frozenset({"sqli_finding", "xss_alert"})


def refused_baseline(observations: Iterable[Any]) -> int | None:
    """The status with which the target refused a run's baseline request, or None."""
    for item in observations or ():
        if not isinstance(item, Mapping) or item.get("kind") != BASELINE_RECORD_KIND:
            continue
        try:
            status = int(item.get("http_status") or 0)
        except (TypeError, ValueError):
            return None
        if status in AUTH_REFUSAL_STATUSES or bool(item.get("login_redirect")):
            return status
        return None
    return None


def is_refusal_error(value: Any) -> bool:
    """True for the error token of a refused run (``authentication_required:401``)."""
    return str(value or "").strip().lower().split(":", 1)[0] == AUTHENTICATION_REQUIRED


def mark_refused(result: Any, *, exempt: bool) -> Any:
    """``result`` reported as refused when the target refused its baseline, else unchanged."""
    if exempt or not dataclasses.is_dataclass(result):
        return result
    if str(getattr(result, "status", "")) in {"cancelled", "failed", "blocked"}:
        return result
    observations = tuple(getattr(result, "observations", ()) or ())
    if any(isinstance(item, Mapping) and item.get("kind") in _FINDING_KINDS for item in observations):
        return result
    status = refused_baseline(observations)
    if status is None:
        return result
    return dataclasses.replace(
        result,
        status="partial",
        partial=True,
        errors=(refusal_error(status), *tuple(getattr(result, "errors", ()) or ())),
        observations=(*observations, {
            "kind": REFUSAL_RECORD_KIND,
            "reason": AUTHENTICATION_REQUIRED,
            "http_status": status,
        }),
    )


__all__ = ["REFUSAL_RECORD_KIND", "is_refusal_error", "mark_refused", "refused_baseline"]
