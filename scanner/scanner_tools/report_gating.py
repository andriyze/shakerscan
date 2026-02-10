"""
Helpers for report-time finding gating.
"""

from typing import Any


def finding_has_verification_evidence(finding: dict[str, Any]) -> bool:
    """Return True when a finding has sufficient verification evidence for report gating."""
    if not isinstance(finding, dict):
        return False
    if finding.get("verified") is True:
        return True
    validation = finding.get("validation")
    if isinstance(validation, dict):
        if validation.get("verified") is True:
            return True
        if validation.get("poe_proven") is True:
            return True
    verdict = str(
        finding.get("verification_verdict")
        or finding.get("last_verification_verdict")
        or ""
    ).strip().lower()
    if verdict in {"exploited", "likely_vulnerable"}:
        return True
    result_status = str(finding.get("result_status") or "").strip().lower()
    if result_status in {"still_vulnerable", "verified_vulnerable"}:
        return True
    poe = finding.get("poe")
    if isinstance(poe, dict) and poe.get("proven") is True:
        return True
    poe_result = finding.get("poe_result")
    if isinstance(poe_result, dict) and poe_result.get("proven") is True:
        return True
    return False

