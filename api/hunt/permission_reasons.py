"""Closed reason codes for Hunt refusals, and the permission kind each one may ask for.

Every Hunt refusal a person could resolve carries one stable ``reason_code`` from
``REASON_CODES``: admission, capability, scope, credential (the E1 codes), budget and approval
refusals. A code names the refusal, never the remedy's wording; the server-rendered message says
what to do. ``kind`` is the permission request the refusal may raise
(``docs/hunt-permission-requests.md``); ``None`` is a hard limit or a refusal no grant can lift,
and it never becomes a request.

A refusal travels as ``HuntRefusal`` (an ``HTTPException`` whose ``detail`` is JSON with
``error``, ``reason_code`` and ``message``), so an older client still reads a readable 4xx.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException

from .credential_uses import CREDENTIAL_REFUSAL_CODES, HuntCredentialRefusal

# Permission request kinds (closed). ``preauthorization`` is the one request a Hunt start
# through the MCP tool makes for the bounds the agent proposed: the agent cannot set them itself.
KIND_TARGET_AUTHORIZE = "target.authorize"
KIND_CREDENTIAL_USE = "credential.use"
KIND_CAPABILITY_ENABLE = "capability.enable"
KIND_BUDGET_RAISE = "budget.raise"
KIND_SSH_EXEC = "ssh.exec"
KIND_SSH_HOST_TRUST = "ssh.host_trust"
KIND_PREAUTHORIZATION = "preauthorization"
PERMISSION_KINDS = (
    KIND_TARGET_AUTHORIZE, KIND_CREDENTIAL_USE, KIND_CAPABILITY_ENABLE, KIND_BUDGET_RAISE,
    KIND_SSH_EXEC, KIND_SSH_HOST_TRUST, KIND_PREAUTHORIZATION,
)
# Kinds whose refusal creates a request in this release. ssh.exec and ssh.host_trust keep their
# codes but stay plain refusals: the SSH worker re-reads the profile's command grant and meets
# the host key only at connection time, so a Hunt-scoped grant could not reach it yet.
REQUESTABLE_KINDS = frozenset({
    KIND_TARGET_AUTHORIZE, KIND_CREDENTIAL_USE, KIND_CAPABILITY_ENABLE, KIND_BUDGET_RAISE,
    KIND_PREAUTHORIZATION,
})


@dataclass(frozen=True)
class ReasonSpec:
    status: int
    kind: str | None = None
    recorded: bool = True  # leaves a blocked action on the Hunt (D25/D35)


# Every code a Hunt refusal may carry. The dictionary is the closed enum.
REASON_CODES: Mapping[str, ReasonSpec] = {
    # Hunt and target state: hard limits.
    "hunt_not_runnable": ReasonSpec(409, recorded=False),
    "target_not_found": ReasonSpec(404, recorded=False),
    "target_inactive": ReasonSpec(409),
    "target_locator_changed": ReasonSpec(409),
    # Capabilities.
    "capability_unregistered": ReasonSpec(404, recorded=False),
    "capability_target_kind_mismatch": ReasonSpec(403),
    "capability_requires_credentials": ReasonSpec(403),
    "capability_requires_active_testing": ReasonSpec(403, KIND_CAPABILITY_ENABLE),
    "capability_requires_state_changing_http": ReasonSpec(403, KIND_CAPABILITY_ENABLE),
    "capability_requires_network_discovery": ReasonSpec(403, KIND_CAPABILITY_ENABLE),
    "capability_requires_oob": ReasonSpec(403, KIND_CAPABILITY_ENABLE),
    "capability_not_selected": ReasonSpec(403, KIND_CAPABILITY_ENABLE),
    "state_changing_http_not_allowed": ReasonSpec(403, KIND_CAPABILITY_ENABLE),
    "active_replay_not_allowed": ReasonSpec(403, KIND_CAPABILITY_ENABLE),
    "principal_anonymous_only": ReasonSpec(422),
    "collection_not_bound": ReasonSpec(403),
    # Scope.
    "scope_other_service_port": ReasonSpec(403, KIND_TARGET_AUTHORIZE),
    "scope_other_host": ReasonSpec(422, KIND_TARGET_AUTHORIZE),
    "scope_credential_other_host": ReasonSpec(422),
    "scope_origin_invalid": ReasonSpec(422),
    "scope_destination_blocked": ReasonSpec(403),
    # Scanners run only against the Hunt's own host, so another host is refused at admission,
    # before anything is reserved; a granted destination is reached with http.request.
    "scope_scanner_other_host": ReasonSpec(422),
    # The worker refused an admitted action before any traffic (its authority changed in between);
    # the hold is released at once (D39).
    "dispatch_authority_rejected": ReasonSpec(403),
    # Approval.
    "approval_receipt_required": ReasonSpec(403),
    "approval_scope_changed": ReasonSpec(403),
    # Credentials: the E1 codes plus the inactive selection at start (D36a).
    **{code: ReasonSpec(403) for code in sorted(CREDENTIAL_REFUSAL_CODES)},
    "credential_not_attached": ReasonSpec(403, KIND_CREDENTIAL_USE),
    "credential_inactive": ReasonSpec(422),
    # Budget.
    "budget_exhausted": ReasonSpec(409, KIND_BUDGET_RAISE),
    "budget_insufficient_for_action": ReasonSpec(409, KIND_BUDGET_RAISE),
    "budget_dimension_needs_permission": ReasonSpec(403),
    "budget_above_profile_ceiling": ReasonSpec(422, recorded=False),
    "budget_resume_without_headroom": ReasonSpec(409, recorded=False),
    # Verification preflight (agent-resolvable, recorded so the attempt is visible).
    "verification_family_unsupported": ReasonSpec(422),
    "verification_route_unresolved": ReasonSpec(422),
    "verification_method_unsupported": ReasonSpec(422),
    # Another verifier still held the finding after the bounded wait (D40): retry, nothing ran.
    "verification_in_progress": ReasonSpec(409),
    # The Hunt's status could not be read during that wait: refused before traffic, not cancelled.
    "cancellation_state_unavailable": ReasonSpec(503),
    # SSH: codes now, requests in a later release (REQUESTABLE_KINDS).
    "ssh_exec_not_allowed": ReasonSpec(403, KIND_SSH_EXEC),
    "ssh_host_key_untrusted": ReasonSpec(403, KIND_SSH_HOST_TRUST),
    # Start contract.
    "direct_origin_address_required": ReasonSpec(422, recorded=False),
    "preauthorization_bound_invalid": ReasonSpec(422, recorded=False),
    # Bounds the agent proposed through the MCP start tool: one pending request for a person.
    "preauthorization_proposed": ReasonSpec(409, KIND_PREAUTHORIZATION, recorded=False),
    # Host bounds stored under IDNA 2003 whose IDNA 2008/UTS #46 spelling differs: withheld, and
    # offered back to the person as one pending request (``shakerscan approve``) to grant again.
    "preauthorization_reapproval": ReasonSpec(409, KIND_PREAUTHORIZATION, recorded=False),
    # Same key, other action.
    "idempotency_key_reused": ReasonSpec(409, recorded=False),
    # A parked action whose request was not granted.
    "permission_denied": ReasonSpec(403),
    "permission_expired": ReasonSpec(403),
    "permission_withdrawn": ReasonSpec(409),
    # Granted, but the agent never called the action again before the Hunt ended (D42).
    "permission_unused": ReasonSpec(409),
}

PERMISSION_REQUIRED = "permission_required"


def reason_kind(code: str) -> str | None:
    """The request kind a refusal may raise in this release, or None (hard or plain)."""
    spec = REASON_CODES.get(code)
    if spec is None or spec.kind not in REQUESTABLE_KINDS:
        return None
    return spec.kind


class HuntRefusal(HTTPException):
    """A Hunt refusal with a stable ``reason_code`` and a JSON ``detail``.

    ``subject`` holds only server-resolved values used to build a permission request; it is
    never shown to the agent as is. ``extra`` adds public fields to ``detail`` (a slot, a
    shortage table).
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int | None = None,
        subject: Mapping[str, Any] | None = None,
        extra: Mapping[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        if code not in REASON_CODES:
            raise ValueError(f"unknown Hunt refusal reason code: {code}")
        self.reason_code = code
        self.message = message
        self.subject = dict(subject or {})
        self.extra = dict(extra or {})
        detail = {
            # ``error`` stays the legacy machine string where one existed (budget_exhausted:<dim>).
            "error": error or code,
            "reason_code": code,
            "message": message,
            **self.extra,
        }
        super().__init__(status_code=status_code or REASON_CODES[code].status, detail=detail)

    @property
    def kind(self) -> str | None:
        return reason_kind(self.reason_code)

    @property
    def recorded(self) -> bool:
        return REASON_CODES[self.reason_code].recorded


def from_credential_refusal(exc: HuntCredentialRefusal) -> HuntRefusal:
    detail = exc.public_detail()
    extra = {key: value for key, value in detail.items() if key not in {"error", "reason_code", "message"}}
    return HuntRefusal(
        exc.code, exc.message, status_code=exc.status_code, extra=extra,
        subject={"slot": exc.slot, "profile_id": exc.profile_id},
    )


def refusal_summary(refusal: HuntRefusal) -> dict[str, Any]:
    """What a refused action stores: the code, the message, nothing executed or charged."""
    detail = refusal.detail if isinstance(refusal.detail, Mapping) else {}
    return {
        **{key: value for key, value in detail.items() if key in {
            "error", "reason_code", "message", "slot", "profile_id", "shortages", "remaining",
            "retryable_with_smaller_action",
        }},
        "refusal_stage": "admission",
        "http_status": refusal.status_code,
        "execution_started": False,
    }


__all__ = [
    "HuntRefusal", "KIND_BUDGET_RAISE", "KIND_CAPABILITY_ENABLE", "KIND_CREDENTIAL_USE",
    "KIND_PREAUTHORIZATION", "KIND_SSH_EXEC", "KIND_SSH_HOST_TRUST", "KIND_TARGET_AUTHORIZE",
    "PERMISSION_KINDS", "PERMISSION_REQUIRED", "REASON_CODES", "REQUESTABLE_KINDS", "ReasonSpec",
    "from_credential_refusal", "reason_kind", "refusal_summary",
]
