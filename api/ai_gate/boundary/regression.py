"""Versioned, offline regression handoff for the existing AI Boundary verifier.

No target traffic, credentials, proof promotion, or new verifier lives here. A
completed scan anchors the artifact; later scans are compared with the same
deterministic Boundary summary and its legitimate workflow controls.
"""
from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from .contract import BoundaryContract, ContractError, canonical_hash
from .hypothesis import materialize_boundary_contract, normalize_boundary_source_binding

_AI_RUN_KINDS = frozenset({"ai_api", "ai_widget", "ai_rag", "ai_trace", "ai_mcp"})
_ENVIRONMENTS = frozenset({"preview", "staging", "development"})
_PROFILES = frozenset({"smoke", "trace", "standard", "deep"})


def _uuid(value: Any) -> str:
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ContractError("boundary_regression_invalid_identifier") from exc


def _object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, RecursionError) as exc:
            raise ContractError("boundary_regression_invalid_stored_json") from exc
    if not isinstance(value, dict):
        raise ContractError("boundary_regression_invalid_stored_json")
    return value


def _created_at(value: Any) -> datetime:
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError) as exc:
        raise ContractError("boundary_regression_scan_timestamp_invalid") from exc


def _scan_boundary(
    scan: Mapping[str, Any], *, target_id: str, contract_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if _uuid(scan.get("ai_target_id")) != target_id or scan.get("run_kind") not in _AI_RUN_KINDS:
        raise ContractError("boundary_regression_scan_target_mismatch")
    if scan.get("status") != "completed":
        raise ContractError("boundary_regression_scan_incomplete")
    options = _object(scan.get("options"))
    if options.get("ai_probe_pack") != "shaker-ai-boundary":
        raise ContractError("boundary_regression_scan_not_boundary")
    result = _object(scan.get("result"))
    ai_gate = _object(result.get("ai_gate"))
    boundary = _object(ai_gate.get("boundary"))
    if boundary.get("schema_version") != "ai-boundary/v6":
        raise ContractError("boundary_regression_summary_unsupported")
    if boundary.get("contract_sha256") != contract_sha256:
        raise ContractError("boundary_regression_contract_mismatch")
    return options, result, boundary


def _control_failures(boundary: dict[str, Any], required: list[str]) -> list[str]:
    controls = boundary.get("controls")
    if not isinstance(controls, list):
        return required
    failures = []
    for name in required:
        matches = [
            item for item in controls
            if isinstance(item, dict) and item.get("name") == name
        ]
        if len(matches) != 1 or matches[0].get("passed") is not True:
            failures.append(name)
    return failures


def _validate_proposal_artifact_shape(proposal: Any) -> None:
    """Reject ignored fields before copying an operator proposal into an export."""
    required = {
        "schema_version", "status", "hypothesis_id", "hypothesis_sha256",
        "kind", "missing_facts", "contract_fragment", "provenance", "principal_bindings",
    }
    allowed = required | {"source_binding"}
    if (not isinstance(proposal, dict) or required - set(proposal)
            or set(proposal) - allowed):
        raise ContractError("boundary_regression_proposal_extra_or_missing_fields")
    if "source_binding" in proposal:
        normalize_boundary_source_binding(proposal.get("source_binding"))
    fragment = proposal.get("contract_fragment")
    kind = proposal.get("kind")
    if kind == "cross_tenant_read":
        expected = {
            "kind", "owner_role", "attacker_role",
            "owner_resource_id", "attacker_resource_id",
        }
        if not isinstance(fragment, dict) or set(fragment) != expected:
            raise ContractError("boundary_regression_proposal_fragment_invalid")
    elif kind not in {"cross_tenant_action", "approval_bypass", "tool_principal"}:
        raise ContractError("boundary_regression_proposal_fragment_invalid")
    provenance = proposal.get("provenance")
    if not isinstance(provenance, list) or not provenance or any(
        not isinstance(item, dict)
        or not {"kind", "id"} <= set(item) <= {"kind", "id", "evidence_sha256"}
        for item in provenance
    ):
        raise ContractError("boundary_regression_proposal_provenance_invalid")


def build_boundary_regression_artifact(
    *, proposal: dict[str, Any], boundary_base: dict[str, Any],
    target_id: str, source_scan: Mapping[str, Any],
) -> dict[str, Any]:
    """Export a reusable request only after a matching completed assessment."""
    target_id = _uuid(target_id)
    _validate_proposal_artifact_shape(proposal)
    materialized = materialize_boundary_contract(proposal, boundary_base=boundary_base)
    contract = BoundaryContract.parse(materialized["boundary_contract"])
    options, result, boundary = _scan_boundary(
        source_scan, target_id=target_id, contract_sha256=contract.digest,
    )
    environment = options.get("ai_environment")
    profile = options.get("ai_scan_profile")
    if environment not in _ENVIRONMENTS or profile not in _PROFILES:
        raise ContractError("boundary_regression_unsupported_run_profile")
    if boundary.get("coverage_complete") is not True or boundary.get("errors"):
        raise ContractError("boundary_regression_source_incomplete")
    required_controls = [
        "backend_denies_cross_customer_read",
        f"permitted_chat_works:{contract.owner.role}",
        f"permitted_chat_works:{contract.attacker.role}",
    ]
    if _control_failures(boundary, required_controls):
        raise ContractError("boundary_regression_legitimate_control_failed")
    state = boundary.get("state")
    if state not in {"passed", "failed"}:
        raise ContractError("boundary_regression_source_inconclusive")
    if state == "passed" and boundary.get("violations"):
        raise ContractError("boundary_regression_source_inconsistent")
    if state == "failed":
        findings = result.get("findings")
        if not isinstance(findings, list) or not any(
            isinstance(item, dict)
            and item.get("verified") is True
            and item.get("proof_state") == "exploited"
            and isinstance(item.get("evidence"), dict)
            and item["evidence"].get("contract_sha256") == contract.digest
            and isinstance(item.get("proof_contract_v2"), dict)
            and item["proof_contract_v2"].get("verdict") == "verified"
            and isinstance(item["proof_contract_v2"].get("predicate"), dict)
            and item["proof_contract_v2"]["predicate"].get("satisfied") is True
            for item in findings
        ):
            raise ContractError("boundary_regression_source_lacks_deterministic_proof")
    artifact = {
        "schema_version": "ai-boundary-regression/v1",
        "ai_target_id": target_id,
        "source_scan_id": _uuid(source_scan.get("id")),
        "source_scan_created_at": _created_at(source_scan.get("created_at")).isoformat(),
        "source_boundary_state": state,
        "boundary_contract_sha256": contract.digest,
        "proposal_sha256": materialized["proposal_sha256"],
        "verify_request": {
            "proposal": copy.deepcopy(proposal),
            "boundary_base": copy.deepcopy(boundary_base),
            "environment": environment,
            "scan_profile": profile,
        },
        "acceptance": {
            "expected_boundary_state": "passed",
            "require_complete_coverage": True,
            "require_no_violations": True,
            "required_legitimate_controls": required_controls,
        },
        "approval_receipt_included": False,
        "execution_enabled": False,
        "promotion_authority": False,
    }
    artifact["artifact_sha256"] = canonical_hash(artifact)
    return artifact


def evaluate_boundary_regression_artifact(
    artifact: dict[str, Any], *, scan: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare a later server-loaded scan with the artifact's verifier criteria."""
    if not isinstance(artifact, dict) or artifact.get("schema_version") != "ai-boundary-regression/v1":
        raise ContractError("boundary_regression_artifact_unsupported")
    unsigned = {key: value for key, value in artifact.items() if key != "artifact_sha256"}
    if canonical_hash(unsigned) != artifact.get("artifact_sha256"):
        raise ContractError("boundary_regression_artifact_digest_mismatch")
    target_id = _uuid(artifact.get("ai_target_id"))
    scan_id = _uuid(scan.get("id"))
    if scan_id == _uuid(artifact.get("source_scan_id")):
        raise ContractError("boundary_regression_requires_later_scan")
    if _created_at(scan.get("created_at")) <= _created_at(artifact.get("source_scan_created_at")):
        raise ContractError("boundary_regression_requires_later_scan")
    request = _object(artifact.get("verify_request"))
    materialized = materialize_boundary_contract(
        request.get("proposal"), boundary_base=request.get("boundary_base"),
    )
    if materialized["boundary_contract_sha256"] != artifact.get("boundary_contract_sha256"):
        raise ContractError("boundary_regression_artifact_contract_mismatch")
    contract = BoundaryContract.parse(materialized["boundary_contract"])
    required_controls = [
        "backend_denies_cross_customer_read",
        f"permitted_chat_works:{contract.owner.role}",
        f"permitted_chat_works:{contract.attacker.role}",
    ]
    acceptance = _object(artifact.get("acceptance"))
    if acceptance != {
        "expected_boundary_state": "passed",
        "require_complete_coverage": True,
        "require_no_violations": True,
        "required_legitimate_controls": required_controls,
    }:
        raise ContractError("boundary_regression_artifact_controls_invalid")
    options, _, boundary = _scan_boundary(
        scan, target_id=target_id,
        contract_sha256=artifact["boundary_contract_sha256"],
    )
    if (options.get("ai_environment") != request.get("environment")
            or options.get("ai_scan_profile") != request.get("scan_profile")):
        raise ContractError("boundary_regression_run_profile_mismatch")
    missing_controls = _control_failures(boundary, required_controls)
    reasons: list[str] = []
    if boundary.get("coverage_complete") is not True or boundary.get("errors"):
        reasons.append("boundary_coverage_incomplete")
    if missing_controls:
        reasons.append("legitimate_control_failed")
    if boundary.get("violations"):
        reasons.append("boundary_violation_observed")
    if boundary.get("state") != "passed":
        reasons.append("boundary_state_not_passed")
    status = (
        "pass" if not reasons else
        "inconclusive" if "boundary_coverage_incomplete" in reasons else "fail"
    )
    return {
        "schema_version": "ai-boundary-regression-evaluation/v1",
        "artifact_sha256": artifact["artifact_sha256"],
        "scan_id": scan_id,
        "status": status,
        "reasons": reasons,
        "missing_legitimate_controls": missing_controls,
        "boundary_contract_sha256": artifact["boundary_contract_sha256"],
        "promotion_authority": False,
    }
