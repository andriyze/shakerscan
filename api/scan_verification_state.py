"""Helpers for merging fresh scan-time proof into persisted finding state."""

from __future__ import annotations

from typing import Any


def _coerce_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


_CONFIRMED_EVIDENCE_LEVELS = {
    "confirmed_exploit",
    "proof_of_exploit",
    "proof_of_exploitation",
    "browser_proven",
}

_DETERMINISTIC_PROOF_TYPES = {
    "browser_execution",
    "browser_proof",
    "cross_principal_replay",
    "sqli_data_extraction",
    "data_extraction",
    "oob_callback",
    "differential_response",
}


def _truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() in {"1", "true", "yes", "on"})


def scan_time_verification_fields(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Return DB verification fields implied by fresh scan-time proof.

    Post-scan retests persist their latest verdict on the canonical finding row.
    A later smart scan can independently prove the same fingerprint again; that
    fresh proof must override stale `false_positive` or `likely_fixed` state so
    scan detail pages and verified-only filters do not contradict the raw report.

    Proof strength is preserved rather than flattened: only hard proof (a proven
    PoE / explicit `exploited`) yields an `exploited` verdict. Softer signals
    (`likely_vulnerable`, a "verified" confidence tier) yield `likely_vulnerable`
    so the merged state never over-states a finding as exploited.
    """
    if not isinstance(finding, dict):
        return None

    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    validation = finding.get("validation") if isinstance(finding.get("validation"), dict) else {}
    poe = finding.get("poe") if isinstance(finding.get("poe"), dict) else {}
    poe_result = finding.get("poe_result") if isinstance(finding.get("poe_result"), dict) else {}
    verdict = str(finding.get("verification_verdict") or finding.get("last_verification_verdict") or "").strip().lower()
    result_status = str(finding.get("result_status") or "").strip().lower()
    confidence_tier = str(finding.get("confidence_tier") or "").strip().lower()
    evidence_level = str(validation.get("evidence_level") or "").strip().lower()
    proof_type = str(
        finding.get("proof_type")
        or evidence.get("proof_type")
        or validation.get("proof_type")
        or validation.get("poe_technique")
        or ""
    ).strip().lower()

    strong_proof = (
        _truthy(validation.get("poe_proven"))
        or _truthy(poe.get("proven"))
        or _truthy(poe_result.get("proven"))
        or verdict == "exploited"
        or result_status == "verified_vulnerable"
        or _truthy(finding.get("proof_of_exploitation"))
        or _truthy(evidence.get("proof_of_exploitation"))
        or _truthy(evidence.get("payload_executed"))
        or _truthy(evidence.get("executed"))
        or bool(finding.get("extraction_evidence") or evidence.get("extraction_evidence"))
        or bool(finding.get("extracted_data") or evidence.get("extracted_data"))
        or bool(finding.get("browser_proof") or evidence.get("browser_proof"))
        or proof_type in _DETERMINISTIC_PROOF_TYPES
        or (_truthy(validation.get("verified")) and evidence_level in _CONFIRMED_EVIDENCE_LEVELS)
    )
    weak_proof = (
        verdict == "likely_vulnerable"
        or result_status == "still_vulnerable"
        or confidence_tier == "verified"
    )

    if strong_proof:
        out_verdict = "exploited"
    elif weak_proof:
        out_verdict = "likely_vulnerable"
    else:
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
        "last_verification_verdict": out_verdict,
        "last_verification_confidence": confidence,
    }
