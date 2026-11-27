"""Admission of a ``request.verify`` call: its input fits its check, and its writes are allowed.

Decided from the call and the Hunt's policy alone, before anything is reserved, so a refusal costs
nothing; the worker decides it again at dispatch (``request_verification.prepare_operation``).
"""
from __future__ import annotations

from typing import Any, Mapping

from .permission_reasons import HuntRefusal


def request_verify_admission(values: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    """Whether the call writes; raises a coded ``HuntRefusal`` when it cannot run."""
    from .request_verification import admission_refusal, writes
    if writes(values) and not (policy.get("active_testing") and policy.get("allow_state_changing_http")):
        raise HuntRefusal(
            "state_changing_http_not_allowed",
            f"request.verify {values.get('check')} with {str(values.get('method') or 'GET').upper()} "
            "sends state-changing requests and needs this Hunt's active_testing and "
            "allow_state_changing_http permissions. A person can allow them for this Hunt (a "
            "permission request is raised).",
            subject={"capability": "request.verify", "flag": "state-changing"},
        )
    refused = admission_refusal(values, policy)
    if refused:
        raise HuntRefusal("request_verify_input_invalid", refused)
    return writes(values)


__all__ = ["request_verify_admission"]
