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
    """Trust only a structured positive result from ShakerScan's browser verifier.

    Free text is never proof: phrases such as ``no execution proof available`` and
    ``payload executed: false`` previously contained positive-looking substrings and could
    promote a negative observation.
    """
    for proof in (finding.get("browser_proof"), evidence.get("browser_proof")):
        if not isinstance(proof, dict) or proof.get("proven") is not True:
            continue
        evidence_type = str(proof.get("evidence_type") or "").strip().lower()
        technique = str(proof.get("technique") or "").strip().lower()
        if (
            proof.get("proof_producer") == "shakerscan"
            and evidence_type in {"dom_execution", "browser_execution"}
            and technique.startswith("headless_xss_")
        ):
            return True
    # Compatibility for canonical finalizer output written before browser_proof
    # became nested. Require the deterministic producer identity, technique, and
    # the executed DOM marker together; a flat verified flag alone is never proof.
    for proof in (finding, evidence):
        evidence_type = str(proof.get("evidence_type") or "").strip().lower()
        technique = str(proof.get("technique") or "").strip().lower()
        if (
            proof.get("proof_producer") == "shakerscan"
            and evidence_type in {"dom_execution", "browser_execution"}
            and technique.startswith("headless_xss_")
            and proof.get("dom_marker_executed") is True
        ):
            return True
    return False


def _has_verified_proof_contract_v2(finding: dict[str, Any]) -> bool:
    proof = _as_dict(finding.get("proof_contract_v2"))
    if not proof:
        proof = _as_dict(_as_dict(finding.get("evidence")).get("proof_contract_v2"))
    predicate = _as_dict(proof.get("predicate"))
    reexecution = _as_dict(proof.get("reexecution"))
    reexecution_required = reexecution.get("required", True) is not False
    reexecution_ok = (
        reexecution.get("performed") is True
        if reexecution_required
        else reexecution.get("performed") in {False, True}
    )
    return bool(
        proof.get("schema_version") == "proof-contract/v2"
        and str(proof.get("contract_id") or "").strip()
        and str(proof.get("contract_version") or "").strip()
        and str(reexecution.get("verifier_build") or "").strip()
        and reexecution_ok
        and proof.get("verdict") == "verified"
        and proof.get("promotable") is True
        and predicate.get("satisfied") is True
        and not list(predicate.get("missing") or [])
    )


def _legacy_reexecution_evidence(finding: dict[str, Any]) -> tuple[bool, str | None]:
    """Derive a live verifier replay from structured legacy producer output.

    This compatibility boundary may normalize a real replay, but must never invent one.
    """
    evidence = _as_dict(finding.get("evidence"))
    validation = _as_dict(finding.get("validation"))
    poe = _as_dict(finding.get("poe_result")) or _as_dict(finding.get("poe"))
    for container in (finding, evidence, validation, poe):
        if any(
            container.get(key) is True
            for key in ("reexecuted_at_handoff", "reexecution_performed", "reexecuted", "replayed")
        ):
            return True, str(container.get("verifier_build") or finding.get("tool") or "dast-verifier")[:200]
    if _has_browser_execution_proof(finding, evidence):
        proof = _as_dict(finding.get("browser_proof")) or _as_dict(evidence.get("browser_proof"))
        return True, str(proof.get("verifier_build") or proof.get("technique") or "headless-xss-verifier")[:200]
    proof_type = _proof_type(finding)
    if proof_type in {"repeated_semantic_response_diff", "cross_principal_replay", "write_cross_principal_replay"}:
        return True, str(validation.get("verifier_build") or finding.get("tool") or proof_type)[:200]
    if poe.get("proven") is True and str(poe.get("evidence_type") or "").strip().lower() in _DETERMINISTIC_PROOF_TYPES:
        return True, str(poe.get("verifier_build") or finding.get("tool") or "proof-of-exploit")[:200]
    return False, None


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
    reexecuted, verifier_build = _legacy_reexecution_evidence(finding)
    return {
        "schema_version": "proof-contract/v2",
        "contract_id": f"dast.{basis}"[:160],
        "contract_version": "1.0.0",
        "family": str(finding.get("family") or finding.get("tool") or "dast")[:80],
        "subject": {key: value for key, value in subject.items() if value is not None},
        "reexecution": {
            "required": False,
            "performed": reexecuted,
            "verifier_build": verifier_build or str(validation.get("verifier_build") or finding.get("tool") or "dast-verifier")[:200],
        },
        "controls": [{"legacy_adapter": True, "normalization_boundary": "dast_precision_policy"}],
        "observations": observations,
        "proof_basis": basis,
        "predicate": {
            "satisfied": True,
            "reason": "trusted deterministic producer output normalized",
            "requirements": ["deterministic_proof"],
            "met": ["deterministic_proof"],
            "missing": [],
            "refuted_by": [],
        },
        "verdict": "verified",
        "promotable": True,
        "traffic_receipt_id": None,
        "tool_receipt_ids": [],
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
