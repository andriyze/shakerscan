"""Helpers for merging fresh scan-time proof into persisted finding state."""

from __future__ import annotations

from typing import Any


def _coerce_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def scan_time_verification_fields(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Return DB verification fields implied by fresh scan-time proof.

    Post-scan retests persist their latest verdict on the canonical finding row.
    A later smart scan can independently prove the same fingerprint again; that
    fresh proof must override stale `false_positive` or `likely_fixed` state so
    scan detail pages and verified-only filters do not contradict the raw report.
    """
    if not isinstance(finding, dict):
        return None

    validation = finding.get("validation") if isinstance(finding.get("validation"), dict) else {}
    poe = finding.get("poe") if isinstance(finding.get("poe"), dict) else {}
    poe_result = finding.get("poe_result") if isinstance(finding.get("poe_result"), dict) else {}
    verdict = str(finding.get("verification_verdict") or finding.get("last_verification_verdict") or "").strip().lower()
    result_status = str(finding.get("result_status") or "").strip().lower()
    confidence_tier = str(finding.get("confidence_tier") or "").strip().lower()

    has_fresh_proof = (
        finding.get("verified") is True
        or validation.get("verified") is True
        or validation.get("poe_proven") is True
        or poe.get("proven") is True
        or poe_result.get("proven") is True
        or verdict in {"exploited", "likely_vulnerable"}
        or result_status in {"still_vulnerable", "verified_vulnerable"}
        or confidence_tier == "verified"
    )
    if not has_fresh_proof:
        return None

    confidence = None
    for value in (
        finding.get("verification_confidence"),
        finding.get("confidence"),
        validation.get("confidence"),
        poe.get("confidence"),
        poe_result.get("confidence"),
    ):
        confidence = _coerce_float(value)
        if confidence is not None:
            break

    return {
        "last_verification_status": "still_vulnerable",
        "last_verification_verdict": "exploited",
        "last_verification_confidence": confidence,
    }
