"""A retest runs as the identity its finding was found with, or not at all.

An authenticated Scan stores only content-free references to its credential profiles
(``credential_profile_refs``); the secrets are resolved by the Scan's own worker under its
authority and are never copied into a retest. A retest of such a finding that holds no identity
of its own (``auth_context``) would send the proof's request anonymously, and an anonymous guest
page that answers 200 would then read as "likely fixed" for a flaw that is still there for the
signed-in user. The same holds for a Scan an earlier release ran with managed credential
profiles or raw sign-in options (``retest_contract.scan_options_signed_in``), and for a Hunt
candidate whose own evidence was gathered as a signed-in Hunt principal (``as_principal``).

Such a finding is not offered a retest and none is queued for it (``retest_identity_refusal``),
and a retest that reaches the worker anyway (queued by an earlier release) sends nothing and is
inconclusive. The rule covers every tier: the proof's own check, the legacy ladder and the
AI-driven tier.
"""

from __future__ import annotations

from typing import Any, Mapping

try:
    from retest_contract import (
        auth_context_to_headers, candidate_evidence_principals, parse_json_field, scan_options_signed_in,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from ..retest_contract import (
        auth_context_to_headers, candidate_evidence_principals, parse_json_field, scan_options_signed_in,
    )


IDENTITY_UNRESOLVED_REASON = (
    "The Scan that found this finding was signed in, and the retest cannot run as that identity; "
    "it sent nothing, so nothing was reproduced or ruled out and the finding stays open. Run an "
    "authenticated Scan with the same profile to check it again."
)
CANDIDATE_IDENTITY_UNRESOLVED_REASON = (
    "The evidence behind this candidate was gathered signed in as a Hunt principal, and the retest "
    "cannot run as that identity; it sent nothing, so nothing was reproduced or ruled out and the "
    "candidate stays open. Run the Hunt again to check it."
)


def source_scan_was_authenticated(verification: Mapping[str, Any]) -> bool:
    """True when the retest's source Scan ran signed in (``scan_options_signed_in``)."""
    return scan_options_signed_in(parse_json_field(verification.get("source_scan_options")))


def candidate_evidence_was_signed_in(verification: Mapping[str, Any]) -> bool:
    """True when the retest is of an investigation candidate whose own evidence was gathered as
    a Hunt principal other than ``anonymous``: with no finding linked, the retest row's
    ``evidence`` is the candidate's ``verification_context``."""
    if verification.get("finding_id") or not verification.get("candidate_id"):
        return False
    return bool(candidate_evidence_principals(verification.get("evidence")))


def retest_identity_unresolved(verification: Mapping[str, Any]) -> bool:
    """True when the finding was found signed in and the retest holds no identity to apply."""
    if not (source_scan_was_authenticated(verification) or candidate_evidence_was_signed_in(verification)):
        return False
    auth_context = parse_json_field(verification.get("auth_context"))
    return not auth_context_to_headers(auth_context)


def identity_unresolved_result(
    *, replay_commands: list[str] | None = None, ladder: list[str] | None = None,
    verification: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The retest result when the identity cannot be applied: inconclusive, nothing sent."""
    reason = (
        CANDIDATE_IDENTITY_UNRESOLVED_REASON
        if verification is not None and not source_scan_was_authenticated(verification)
        and candidate_evidence_was_signed_in(verification)
        else IDENTITY_UNRESOLVED_REASON
    )
    return {
        "status": "completed", "result_status": "inconclusive", "verdict": "inconclusive",
        "verdict_reason": reason, "error_message": None, "confidence": None,
        "proof": None, "replay_commands": list(replay_commands or []),
        "artifacts": {"skipped_reason": "identity_unresolved", "requests_sent": 0},
        "message": reason, "attempt_ladder": list(ladder or []),
        "attempts_exhausted": True, "deterministic_exhausted": True, "has_ai_step": False,
        "retry_class": "none", "retryable": False, "verification_mode": "deterministic",
    }


__all__ = [
    "CANDIDATE_IDENTITY_UNRESOLVED_REASON", "IDENTITY_UNRESOLVED_REASON",
    "candidate_evidence_was_signed_in", "identity_unresolved_result", "retest_identity_unresolved",
    "source_scan_was_authenticated",
]
