"""Shared policy for using AI verdicts in DAST precision decisions."""

from __future__ import annotations

from typing import Any


TRUSTED_AI_CLASSIFICATION_SOURCES = {
    "provider",
    "semantic_judge",
    "llm_rubric",
    "regex_classifier",
}

_CONFIRMED_EVIDENCE_LEVELS = {
    "confirmed_exploit",
    "proof_of_exploit",
    "proof_of_exploitation",
    "browser_proven",
}

_DETERMINISTIC_PROOF_TYPES = {
    "browser_execution",
    "cross_principal_replay",
    "write_cross_principal_replay",
    "sqli_data_extraction",
    "data_extraction",
    "oob_callback",
    "repeated_semantic_response_diff",
}

_BROWSER_EXECUTION_MARKERS = (
    "payload executed",
    "dialog fired",
    "dialog triggered",
    "console proof",
    "dom proof",
    "execution proof",
)


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() in {"1", "true", "yes", "on"})


def _has_browser_execution_proof(finding: dict[str, Any], evidence: dict[str, Any]) -> bool:
    """Return True only for positive browser execution proof, not failed attempts."""
    for proof in (finding.get("browser_proof"), evidence.get("browser_proof")):
        if isinstance(proof, dict):
            if _truthy(proof.get("proven")) or _truthy(proof.get("payload_executed")) or _truthy(proof.get("executed")):
                return True
        elif isinstance(proof, str):
            proof_text = proof.lower()
            if any(marker in proof_text for marker in _BROWSER_EXECUTION_MARKERS):
                return True
    evidence_text = str(evidence).lower()
    return any(marker in evidence_text for marker in _BROWSER_EXECUTION_MARKERS)


def _has_verified_proof_contract_v2(finding: dict[str, Any]) -> bool:
    proof = _as_dict(finding.get("proof_contract_v2"))
    if not proof:
        proof = _as_dict(_as_dict(finding.get("evidence")).get("proof_contract_v2"))
    predicate = _as_dict(proof.get("predicate"))
    reexecution = _as_dict(proof.get("reexecution"))
    return bool(
        proof.get("schema_version") == "proof-contract/v2"
        and str(proof.get("contract_id") or "").strip()
        and str(proof.get("contract_version") or "").strip()
        and str(reexecution.get("verifier_build") or "").strip()
        and reexecution.get("performed") is True
        and predicate.get("verdict") == "verified"
        and predicate.get("promotable") is True
        and not list(predicate.get("missing") or [])
    )


def _proof_type(finding: dict[str, Any]) -> str:
    evidence = _as_dict(finding.get("evidence"))
    validation = _as_dict(finding.get("validation"))
    poe = _as_dict(finding.get("poe"))
    poe_result = _as_dict(finding.get("poe_result"))
    return str(
        finding.get("proof_type")
        or evidence.get("proof_type")
        or validation.get("proof_type")
        or validation.get("poe_technique")
        or poe_result.get("evidence_type")
        or poe.get("evidence_type")
        or ""
    ).strip().lower()


def _has_legacy_deterministic_exploit_proof(finding: dict[str, Any]) -> bool:
    """Compatibility predicate used only to construct a typed v2 envelope at normalization."""
    evidence = _as_dict(finding.get("evidence"))
    validation = _as_dict(finding.get("validation"))
    poe = _as_dict(finding.get("poe"))
    poe_result = _as_dict(finding.get("poe_result"))
    explicit_truthy_keys = (
        (finding, "proof_of_exploitation"),
        (evidence, "proof_of_exploitation"),
        (validation, "poe_proven"),
        (poe, "proven"),
        (poe_result, "proven"),
    )
    if any(_truthy(container.get(key)) for container, key in explicit_truthy_keys):
        return True
    if evidence.get("extraction_evidence") or finding.get("extraction_evidence"):
        return True
    if evidence.get("extracted_data") or finding.get("extracted_data"):
        return True
    if _has_browser_execution_proof(finding, evidence):
        return True
    if _proof_type(finding) in _DETERMINISTIC_PROOF_TYPES:
        return True
    evidence_level = str(validation.get("evidence_level") or "").strip().lower()
    return _truthy(validation.get("verified")) and evidence_level in _CONFIRMED_EVIDENCE_LEVELS


def build_dast_proof_contract_v2(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Adapt trusted legacy deterministic output into the universal proof envelope.

    This runs at the scanner normalization boundary. Supplying an invalid v2 envelope never falls
    back to legacy fields, so callers cannot use a malformed contract plus an old boolean to promote.
    """
    if not _has_legacy_deterministic_exploit_proof(finding):
        return None
    evidence = _as_dict(finding.get("evidence"))
    validation = _as_dict(finding.get("validation"))
    poe = _as_dict(finding.get("poe_result")) or _as_dict(finding.get("poe"))
    basis = _proof_type(finding) or (
        "browser_execution" if _has_browser_execution_proof(finding, evidence)
        else "data_extraction" if (
            evidence.get("extraction_evidence") or finding.get("extraction_evidence")
            or evidence.get("extracted_data") or finding.get("extracted_data")
        ) else "proof_of_exploitation"
    )
    subject = {
        "url": str(finding.get("url") or evidence.get("url") or evidence.get("endpoint") or "")[:2000] or None,
        "method": str(finding.get("method") or evidence.get("method") or "GET").upper()[:16],
        "parameter": str(evidence.get("param") or evidence.get("parameter") or "")[:300] or None,
    }
    observations = [{
        "proof_basis": basis,
        "poe_proven": bool(poe.get("proven") or validation.get("poe_proven")),
        "browser_execution": _has_browser_execution_proof(finding, evidence),
        "extraction_present": bool(
            evidence.get("extraction_evidence") or finding.get("extraction_evidence")
            or evidence.get("extracted_data") or finding.get("extracted_data")
        ),
        "evidence_level": str(validation.get("evidence_level") or "")[:80] or None,
    }]
    return {
        "schema_version": "proof-contract/v2",
        "contract_id": f"dast.{basis}"[:160],
        "contract_version": "1.0.0",
        "family": str(finding.get("family") or finding.get("tool") or "dast")[:80],
        "subject": {key: value for key, value in subject.items() if value is not None},
        "reexecution": {
            "performed": True,
            "verifier_build": str(
                validation.get("verifier_build") or finding.get("tool") or "dast-verifier"
            )[:200],
        },
        "controls": [{"legacy_adapter": True, "normalization_boundary": "dast_precision_policy"}],
        "observations": observations,
        "proof_basis": basis,
        "predicate": {
            "verdict": "verified",
            "promotable": True,
            "missing": [],
        },
    }


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
    if "proof_contract_v2" in finding or "proof_contract_v2" in _as_dict(finding.get("evidence")):
        return _has_verified_proof_contract_v2(finding)
    return _has_legacy_deterministic_exploit_proof(finding)


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
