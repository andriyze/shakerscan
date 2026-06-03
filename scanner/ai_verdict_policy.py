"""Shared policy for using AI verdicts in DAST precision decisions."""

from __future__ import annotations

from typing import Any


TRUSTED_AI_CLASSIFICATION_SOURCES = {
    "provider",
    "semantic_judge",
    "llm_rubric",
    "regex_classifier",
}


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def ai_confidence(finding: dict[str, Any]) -> float:
    """Return normalized AI confidence from a finding."""
    return _as_float(finding.get("ai_confidence"), 0.0)


def ai_classification_source(finding: dict[str, Any]) -> str:
    """Return normalized classifier provenance."""
    return str(finding.get("ai_classification_source") or "").strip().lower()


def has_deterministic_exploit_proof(finding: dict[str, Any]) -> bool:
    """True when non-AI proof demonstrates exploitability.

    Generic ``verified=True`` can come from coarse scanner heuristics, so it is
    intentionally not enough by itself. This helper looks for PoE/extraction or
    validator proof fields that should block an AI false-positive downgrade.
    """
    evidence = _as_dict(finding.get("evidence"))
    validation = _as_dict(finding.get("validation"))
    poe_result = _as_dict(finding.get("poe_result"))

    explicit_truthy_keys = (
        (finding, "proof_of_exploitation"),
        (evidence, "proof_of_exploitation"),
        (evidence, "payload_executed"),
        (evidence, "executed"),
        (validation, "poe_proven"),
        (poe_result, "proven"),
    )
    if any(container.get(key) is True for container, key in explicit_truthy_keys):
        return True

    if evidence.get("extraction_evidence") or finding.get("extraction_evidence"):
        return True

    evidence_level = str(validation.get("evidence_level") or "").lower()
    return evidence_level == "confirmed_exploit"


def is_trusted_ai_verdict(
    finding: dict[str, Any],
    verdict: str,
    *,
    min_confidence: float = 0.90,
) -> bool:
    """Return True when an AI verdict is strong enough to affect policy."""
    if str(finding.get("ai_verdict") or "").strip().lower() != verdict:
        return False
    if ai_confidence(finding) < min_confidence:
        return False
    return ai_classification_source(finding) in TRUSTED_AI_CLASSIFICATION_SOURCES


def is_trusted_ai_true_positive(
    finding: dict[str, Any],
    *,
    min_confidence: float = 0.85,
) -> bool:
    """True when AI TP provenance is strong enough to confirm a finding."""
    return is_trusted_ai_verdict(
        finding,
        "true_positive",
        min_confidence=min_confidence,
    )


def is_trusted_ai_false_positive(
    finding: dict[str, Any],
    *,
    min_confidence: float = 0.90,
) -> bool:
    """True when AI FP can safely reduce policy/scoring impact."""
    return (
        is_trusted_ai_verdict(
            finding,
            "false_positive",
            min_confidence=min_confidence,
        )
        and not has_deterministic_exploit_proof(finding)
    )
