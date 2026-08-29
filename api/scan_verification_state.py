"""Helpers for merging fresh scan-time proof into persisted finding state."""

from __future__ import annotations

import json
from typing import Any

try:
    from proof_contracts import is_canonical_proof_contract
except ModuleNotFoundError:  # package import in host-side tests
    from .proof_contracts import is_canonical_proof_contract


def _coerce_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# Proof-state vocabulary + helpers live ONCE in scanner/ai_verdict_policy so the
# "one proof taxonomy" guarantee can't drift across copies (audit follow-up). The
# scanner dir is on path in the API/worker runtime (flattened /app); unit tests
# only add api/, so locate scanner/ relative to this file as a fallback.
try:
    from ai_verdict_policy import (
        _has_browser_execution_proof,
        _truthy,
        _CONFIRMED_EVIDENCE_LEVELS,
        _DETERMINISTIC_PROOF_TYPES,
    )
except ImportError:
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))
    from ai_verdict_policy import (
        _has_browser_execution_proof,
        _truthy,
        _CONFIRMED_EVIDENCE_LEVELS,
        _DETERMINISTIC_PROOF_TYPES,
    )


def _evidence_object(value: Any) -> dict[str, Any]:
    """Return an evidence mapping whether it arrives as a dict or as JSON text.

    Database rows carry evidence as JSON text, and this function only accepted a dict -- so every
    evidence-derived signal here (proof_of_exploitation, payload_executed, extraction_evidence, the
    V2 proof contract) was invisible for a persisted finding and visible only for one still in
    memory. Unparseable text yields an empty mapping: unreadable evidence is no evidence, never a
    reason to promote.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, (str, bytes, bytearray)):
        try:
            decoded = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return decoded if isinstance(decoded, dict) else {}
    return {}


def _has_satisfied_proof_contract(evidence: dict[str, Any]) -> bool:
    """True for a V2 deterministic proof contract the finalizer re-executed and satisfied.

    The signals above are the V1 vocabulary. The V2 finalizer speaks a different one -- it stamps
    a named `proof_contract`, `proof_state: verified`, and `triage.verified` only after the
    contract's own repetitions passed -- and the two share no key, so a complete deterministic
    proof was read as no proof at all and the finding persisted as suspected. That demoted the
    entire V2 proof chain out of verified-only filters and the headline grade.

    All three markers are required together. Any one alone is a weaker claim, for the same reason
    a bare `verified: true` is rejected here as a generic legacy flag: only the finalizer emits
    the triple, and only after re-execution.
    """
    if not isinstance(evidence, dict):
        return False
    triage = evidence.get("triage") if isinstance(evidence.get("triage"), dict) else {}
    # The contract must be one this scanner can re-execute. Accepting any non-empty
    # name let operator-supplied evidence name an invented contract and promote itself
    # to "exploited" without a single deterministic re-execution behind it.
    return bool(
        is_canonical_proof_contract(evidence.get("proof_contract"))
        and str(evidence.get("proof_state") or "").strip().lower() == "verified"
        and triage.get("verified") is True
    )


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

    evidence = _evidence_object(finding.get("evidence"))
    validation = finding.get("validation") if isinstance(finding.get("validation"), dict) else {}
    poe = finding.get("poe") if isinstance(finding.get("poe"), dict) else {}
    poe_result = finding.get("poe_result") if isinstance(finding.get("poe_result"), dict) else {}
    browser_proof = finding.get("browser_proof") if isinstance(finding.get("browser_proof"), dict) else {}
    # ``last_verification_verdict`` is persisted retest state and may come from
    # an advisory AI verifier. It is not fresh scan-time proof and must never
    # enter this deterministic recognizer. Callers handle deterministic retest
    # rows separately using their explicit verification_mode.
    verdict = str(finding.get("verification_verdict") or "").strip().lower()
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
    # A registered detector family whose registry proof contract is unmet was already judged NOT
    # trustworthy-verified at the report boundary (scanner.findings.enforce_registry_finding_contracts
    # stamps registry_contract.contract_satisfied=False and caps severity). Honor that verdict here so
    # a raw proof signal (proof_of_exploitation, proof_type, ...) cannot independently persist
    # `last_verification_verdict='exploited'` on the authoritative verified surface the UI,
    # verified-only filters, and benchmark gates read. Cap it at `likely_vulnerable` instead.
    registry_contract = finding.get("registry_contract") if isinstance(finding.get("registry_contract"), dict) else {}
    registry_rejected = registry_contract.get("contract_satisfied") is False

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
        or _has_browser_execution_proof(finding, evidence)
        or proof_type in _DETERMINISTIC_PROOF_TYPES
        or (_truthy(validation.get("verified")) and evidence_level in _CONFIRMED_EVIDENCE_LEVELS)
        or _has_satisfied_proof_contract(evidence)
    )
    weak_proof = (
        verdict == "likely_vulnerable"
        or result_status == "still_vulnerable"
        or confidence_tier == "verified"
    )

    if strong_proof and not registry_rejected:
        out_verdict = "exploited"
    elif weak_proof or (strong_proof and registry_rejected):
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
        browser_proof.get("confidence"),
    ):
        confidence = _coerce_float(value)
        if confidence is not None:
            break

    return {
        "last_verification_status": "still_vulnerable",
        "last_verification_verdict": out_verdict,
        "last_verification_confidence": confidence,
    }
