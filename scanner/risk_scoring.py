"""Canonical observed-risk scoring shared by scanner and API finalizers."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

try:
    from .ai_verdict_policy import (
        has_deterministic_exploit_proof,
        is_trusted_ai_false_positive,
    )
    from .score_bands import grade_for
except ImportError:  # direct scanner process import layout
    from ai_verdict_policy import (
        has_deterministic_exploit_proof,
        is_trusted_ai_false_positive,
    )
    from score_bands import grade_for


SEVERITY_WEIGHT: Mapping[str, int] = {
    "critical": 20, "high": 10, "medium": 5, "low": 2, "info": 0,
}
HTTP_POSTURE_WEIGHT: Mapping[str, int] = {
    "content-security-policy": 12,
    "x-frame-options": 4,
    "x-content-type-options": 4,
    "referrer-policy": 2,
}
PROVEN_CEILING: Mapping[str, int] = {"critical": 40, "high": 70, "medium": 85}
SUSPECTED_CEILING: Mapping[str, int] = {"critical": 70, "high": 85}


def has_proof(item: Mapping[str, Any]) -> bool:
    if has_deterministic_exploit_proof(dict(item)):
        return True
    return item.get("verified") is True and str(item.get("proof_state") or "") == "verified"


def proof_weight(finding: Mapping[str, Any]) -> float:
    item = dict(finding)
    if is_trusted_ai_false_positive(item):
        return 0.0
    if has_proof(item):
        return 1.0
    if item.get("suspected") or item.get("needs_verification"):
        return 0.25
    try:
        confidence = float(item.get("confidence"))
    except (TypeError, ValueError):
        confidence = 0.6
    if confidence < 0.5:
        return 0.25
    if confidence < 0.65:
        return 0.5
    if confidence < 0.8:
        return 0.75
    return 1.0


def caps_risk_grade(finding: Mapping[str, Any]) -> bool:
    item = dict(finding)
    if is_trusted_ai_false_positive(item):
        return False
    if has_proof(item):
        return True
    if item.get("suspected") or item.get("needs_verification"):
        return False
    validation = item.get("validation")
    validation = validation if isinstance(validation, Mapping) else {}
    try:
        confidence = float(item.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    return confidence >= 0.80 or str(
        validation.get("evidence_level") or ""
    ).lower() == "strong_indicator"


def severity(finding: Mapping[str, Any]) -> str:
    name = str(finding.get("severity") or "info").strip().lower()
    return name if name in SEVERITY_WEIGHT else "info"


def risk(
    findings: Sequence[Mapping[str, Any]],
    *,
    posture: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    penalty = 0.0
    ceiling = 100
    proven: dict[str, int] = {}
    suspected: dict[str, int] = {}
    for finding in findings:
        level = severity(finding)
        weight = proof_weight(finding)
        penalty += SEVERITY_WEIGHT[level] * weight
        if weight <= 0.0:
            continue
        if caps_risk_grade(finding):
            proven[level] = proven.get(level, 0) + 1
            ceiling = min(ceiling, PROVEN_CEILING.get(level, 100))
        else:
            suspected[level] = suspected.get(level, 0) + 1
            ceiling = min(ceiling, SUSPECTED_CEILING.get(level, 100))
    http = (posture or {}).get("http")
    http = http if isinstance(http, Mapping) else {}
    missing_headers = {
        str(header).strip().lower()
        for header in (http.get("missing_security_headers") or ())
        if str(header).strip()
    }
    posture_penalties = {
        header: points
        for header, points in HTTP_POSTURE_WEIGHT.items()
        if header in missing_headers
    }
    posture_penalty = sum(posture_penalties.values())
    penalty += posture_penalty

    score = min(max(0, 100 - int(round(penalty))), ceiling)
    reasons: list[str] = []
    for level in ("critical", "high", "medium"):
        if proven.get(level):
            reasons.append(f"proven_{level}:{proven[level]}")
        if suspected.get(level):
            reasons.append(f"suspected_{level}:{suspected[level]}")
    reasons.extend(
        f"posture_missing_{header}:{points}"
        for header, points in posture_penalties.items()
    )
    return {
        "score": score,
        "grade": grade_for(score),
        "reasons": reasons,
        "proven_counts": proven,
        "suspected_counts": suspected,
        "posture_penalty": posture_penalty,
        "posture_penalties": posture_penalties,
    }


__all__ = [
    "HTTP_POSTURE_WEIGHT", "PROVEN_CEILING", "SEVERITY_WEIGHT",
    "SUSPECTED_CEILING", "caps_risk_grade", "has_proof", "proof_weight",
    "risk", "severity",
]
