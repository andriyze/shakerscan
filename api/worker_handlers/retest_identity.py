"""A retest runs as the identity its finding was found with, or not at all.

An authenticated Scan stores only content-free references to its credential profiles
(``credential_profile_refs``); the secrets are resolved by the Scan's own worker under its
authority and are never copied into a retest. A retest of such a finding that holds no identity
of its own (``auth_context``) would send the proof's request anonymously, and an anonymous guest
page that answers 200 would then read as "likely fixed" for a flaw that is still there for the
signed-in user.

So a retest whose source Scan was authenticated and that cannot apply an identity sends nothing
and is inconclusive. The rule covers every tier: the proof's own check, the legacy ladder and the
AI-driven tier.
"""

from __future__ import annotations

from typing import Any, Mapping

try:
    from retest_contract import auth_context_to_headers, parse_json_field
except ModuleNotFoundError:  # package import in host-side tests
    from ..retest_contract import auth_context_to_headers, parse_json_field


IDENTITY_UNRESOLVED_REASON = (
    "The Scan that found this finding was signed in with a credential profile, and the retest "
    "cannot run as that identity; it sent nothing, so nothing was reproduced or ruled out and the "
    "finding stays open. Run an authenticated Scan with the same profile to check it again."
)


def source_scan_was_authenticated(verification: Mapping[str, Any]) -> bool:
    """True when the retest's source Scan ran with managed credential profiles."""
    options = parse_json_field(verification.get("source_scan_options"))
    refs = options.get("credential_profile_refs")
    return isinstance(refs, (list, tuple)) and len(refs) > 0


def retest_identity_unresolved(verification: Mapping[str, Any]) -> bool:
    """True when the finding was found signed in and the retest holds no identity to apply."""
    if not source_scan_was_authenticated(verification):
        return False
    auth_context = parse_json_field(verification.get("auth_context"))
    return not auth_context_to_headers(auth_context)


def identity_unresolved_result(
    *, replay_commands: list[str] | None = None, ladder: list[str] | None = None,
) -> dict[str, Any]:
    """The retest result when the identity cannot be applied: inconclusive, nothing sent."""
    return {
        "status": "completed", "result_status": "inconclusive", "verdict": "inconclusive",
        "verdict_reason": IDENTITY_UNRESOLVED_REASON, "error_message": None, "confidence": None,
        "proof": None, "replay_commands": list(replay_commands or []),
        "artifacts": {"skipped_reason": "identity_unresolved", "requests_sent": 0},
        "message": IDENTITY_UNRESOLVED_REASON, "attempt_ladder": list(ladder or []),
        "attempts_exhausted": True, "deterministic_exhausted": True, "has_ai_step": False,
        "retry_class": "none", "retryable": False, "verification_mode": "deterministic",
    }


__all__ = [
    "IDENTITY_UNRESOLVED_REASON", "identity_unresolved_result", "retest_identity_unresolved",
    "source_scan_was_authenticated",
]
