"""Deterministic finding-family proof contracts (Wave 5).

Pure, host-testable registry. Experiment evidence may *request* promotion but never *replace* the
family verifier: a finding is `verified` only when the structured, deterministic proof predicates for
its family all hold AND the contract was re-executed live at handoff. An LLM label, a bare "anomaly",
or a generic differential can never reach `verified` — the verdict is computed from structured
evidence fields, never from any provided verdict/label string. Unsupported families fail closed
(`blocked`).

Verdicts: `verified` | `supported_unverified` | `refuted` | `inconclusive` | `blocked`.
Only `verified` may create/promote a finding (enforced by the caller).
"""

from __future__ import annotations

from typing import Any

FAMILY_PROOF_VERSION = "family-proof-2026-07-14.v3"
PROOF_CONTRACT_SCHEMA_VERSION = "proof-contract/v2"

VERDICTS = frozenset({"verified", "supported_unverified", "refuted", "inconclusive", "blocked"})

# Per-family deterministic proof contract: the structured evidence predicates that must ALL be true
# for `verified`. Keys are booleans the deterministic verifier/actuator sets — never LLM prose.
FAMILY_CONTRACTS: dict[str, dict[str, Any]] = {
    "bola": {
        "cwe": "CWE-639",
        "requires": ["distinct_identity", "ownership_established", "cross_principal_access", "denial_control"],
        "refute_if": ["cross_principal_denied", "same_account"],
    },
    "mass_assignment": {
        "cwe": "CWE-915",
        "requires": ["forbidden_field_accepted", "observable_state_change", "benign_control_accepted"],
        "refute_if": ["forbidden_field_rejected"],
    },
    "injection": {
        "cwe": "CWE-74",
        "requires": ["payload_control_differential", "deterministic_family_proof"],
        "refute_if": ["control_equivalent"],
    },
    "auth_bypass": {
        "cwe": "CWE-287",
        "requires": ["protected_resource_accessed", "unauthenticated_control"],
        "refute_if": ["access_denied_unauthenticated"],
    },
    "access_control": {
        "cwe": "CWE-285",
        "requires": ["authorized_role_control", "forbidden_role_access", "distinct_identity"],
        "refute_if": ["forbidden_role_denied", "same_account"],
    },
    "field_constraint": {
        "cwe": "CWE-840",
        "requires": ["constraint_baseline_observed", "constraint_violation_persisted", "before_after_state"],
        "refute_if": ["constraint_enforced"],
    },
    "workflow": {
        "cwe": "CWE-841",
        "requires": ["transition_invariant_broken", "before_after_state"],
        "refute_if": ["invariant_held"],
    },
    "data_exposure": {
        "cwe": "CWE-200",
        # sensitive VALUE evidence, not name-only classification.
        "requires": ["sensitive_value_present"],
        "refute_if": ["name_only_classification"],
    },
    "device_service_exposure": {
        "cwe": "CWE-284",
        "requires": ["protocol_handshake", "policy_denied", "recent_observation"],
        "refute_if": ["service_closed", "policy_allowed", "health_degraded"],
    },
    "device_tls": {
        "cwe": "CWE-295",
        "requires": ["strict_handshake_failed", "endpoint_identity_bound", "recent_observation"],
        "refute_if": ["strict_handshake_succeeded"],
    },
    "device_auth_bypass": {
        "cwe": "CWE-306",
        "requires": ["protected_resource_established", "anonymous_semantic_equivalence", "negative_control"],
        "refute_if": ["anonymous_access_denied", "generic_response_shell"],
    },
    "device_control_authorization": {
        "cwe": "CWE-862",
        "requires": [
            "exact_bound_request", "before_state", "underprivileged_effect",
            "after_state", "cleanup_or_safe_residue",
        ],
        "refute_if": ["underprivileged_control_rejected", "state_unchanged"],
    },
    "device_firmware_advisory": {
        "cwe": "CWE-1104",
        "requires": ["exact_product_identity", "version_in_affected_range", "advisory_snapshot_verified"],
        "refute_if": ["version_outside_affected_range", "heuristic_product_match"],
    },
    "device_ssh_posture": {
        "cwe": "CWE-327",
        "requires": ["pinned_host_key", "negotiated_posture", "policy_violation"],
        "refute_if": ["policy_requirements_satisfied", "host_key_changed"],
    },
}

# Aliases -> canonical family.
FAMILY_ALIASES = {
    "idor": "bola",
    "broken_object_level_authorization": "bola",
    "bfla": "auth_bypass",
    "authentication_bypass": "auth_bypass",
    "authz_bypass": "auth_bypass",
    "sqli": "injection",
    "xss": "injection",
    "nosqli": "injection",
    "ssti": "injection",
    "business_logic": "workflow",
    "sensitive_data_exposure": "data_exposure",
    "information_disclosure": "data_exposure",
    "service_exposure": "device_service_exposure",
    "firmware_advisory": "device_firmware_advisory",
}


def canonical_family(family: Any) -> str:
    f = str(family or "").strip().lower().replace(" ", "_").replace("-", "_")
    return FAMILY_ALIASES.get(f, f)


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "pass", "passed", "present", "accepted"}
    return bool(value)


def evaluate_family_proof(family: Any, evidence: Any, *, require_reexecution: bool = True) -> dict[str, Any]:
    """Evaluate a family proof contract against structured evidence. Never raises.

    `verified` requires every family predicate to hold AND (when ``require_reexecution``) an explicit
    ``reexecuted_at_handoff`` flag — a stored outcome is a claim, a live re-run is proof. Any
    ``refute_if`` predicate forces `refuted`. Unknown family -> `blocked` (fail closed).
    """
    fam = canonical_family(family)
    contract = FAMILY_CONTRACTS.get(fam)
    if not contract:
        return {
            "version": FAMILY_PROOF_VERSION, "family": fam, "verdict": "blocked",
            "reason": f"unsupported_family:{fam}", "cwe": None,
            "requirements": [], "met": [], "missing": [], "promotable": False,
        }
    ev = evidence if isinstance(evidence, dict) else {}
    required = list(contract["requires"])
    met = [r for r in required if _truthy(ev.get(r))]
    missing = [r for r in required if r not in met]
    refuted_by = [r for r in contract.get("refute_if", []) if _truthy(ev.get(r))]
    reexecuted = _truthy(ev.get("reexecuted_at_handoff"))

    if refuted_by:
        verdict, reason = "refuted", f"refuting_evidence:{refuted_by[0]}"
    elif not missing and (reexecuted or not require_reexecution):
        verdict, reason = "verified", "family_proof_contract_satisfied"
    elif not missing and not reexecuted:
        verdict, reason = "supported_unverified", "contract_met_but_not_reexecuted_at_handoff"
    elif met:
        verdict, reason = "supported_unverified", "partial_family_evidence"
    else:
        verdict, reason = "inconclusive", "no_family_evidence"

    return {
        "version": FAMILY_PROOF_VERSION,
        "family": fam,
        "cwe": contract["cwe"],
        "verdict": verdict,
        "reason": reason,
        "requirements": required,
        "met": met,
        "missing": missing,
        "refuted_by": refuted_by,
        "reexecuted_at_handoff": reexecuted,
        # Only `verified` may create/promote a finding.
        "promotable": verdict == "verified",
    }


def supported_families() -> list[str]:
    return sorted(FAMILY_CONTRACTS)


def evaluate_claim_preflight(family: Any, evidence: Any) -> dict[str, Any]:
    """Evaluate untrusted assertions without manufacturing terminal proof state.

    Workbench checkboxes can show which contract fields are missing, but they are not observations
    from a live verifier. They can therefore neither verify nor refute a claim and are never
    promotable, even if a caller supplies the re-execution flag.
    """
    asserted = dict(evidence) if isinstance(evidence, dict) else {}
    asserted["reexecuted_at_handoff"] = False
    result = evaluate_family_proof(family, asserted)
    if result["verdict"] == "refuted":
        return {
            **result,
            "verdict": "inconclusive",
            "reason": "caller_asserted_refutation_requires_live_verification",
            "reexecuted_at_handoff": False,
            "promotable": False,
        }
    return {**result, "reexecuted_at_handoff": False, "promotable": False}


PROMOTION_MIN_STRENGTH = "cross_principal_verified"


def promotion_gate(result: dict[str, Any] | None) -> tuple[bool, str | None]:
    """Deterministic promotion predicate for trusted live family-proof callers.

    Only a `verified`, live-re-executed family proof may promote to a finding — a stored outcome is a
    claim, `verified` already requires ``reexecuted_at_handoff`` and carries the top evidence-strength
    rung. Uniform wiring across legacy finding-creation paths is tracked separately; this helper must
    not be described as enforced where a caller does not invoke it. Returns ``(ok, reason)`` and
    fails closed on anything less.
    """
    r = result or {}
    verdict = str(r.get("verdict") or "")
    if verdict != "verified":
        return False, f"not_verified:{verdict or 'none'}"
    if not r.get("reexecuted_at_handoff"):
        return False, "not_reexecuted_at_handoff"
    if not r.get("promotable"):
        return False, "not_promotable"
    return True, None


def build_proof_contract_result(
    family: Any,
    evidence: Any,
    *,
    contract_id: str,
    contract_version: str,
    verifier_build: str,
    subject: Any = None,
    observations: Any = None,
    controls: Any = None,
    proof_basis: str = "deterministic_replay",
    traffic_receipt_id: str | None = None,
    tool_receipt_ids: Any = None,
    require_reexecution: bool = True,
) -> dict[str, Any]:
    """Wrap a family predicate in the versioned envelope accepted by promotion callers."""
    predicate = evaluate_family_proof(
        family, evidence, require_reexecution=require_reexecution,
    )
    return {
        "schema_version": PROOF_CONTRACT_SCHEMA_VERSION,
        "contract_id": str(contract_id or "")[:160],
        "contract_version": str(contract_version or "")[:80],
        "family_registry_version": FAMILY_PROOF_VERSION,
        "family": predicate["family"],
        "subject": subject if isinstance(subject, dict) else {},
        "reexecution": {
            "required": bool(require_reexecution),
            "performed": bool(predicate.get("reexecuted_at_handoff")),
            "verifier_build": str(verifier_build or "")[:200],
        },
        "controls": list(controls or [])[:100],
        "observations": list(observations or [])[:200],
        "predicate": {
            "satisfied": predicate["verdict"] == "verified",
            "reason": predicate["reason"],
            "requirements": predicate["requirements"],
            "met": predicate["met"],
            "missing": predicate["missing"],
            "refuted_by": predicate.get("refuted_by") or [],
        },
        "verdict": predicate["verdict"],
        "proof_basis": str(proof_basis or "deterministic_replay")[:80],
        "promotable": bool(predicate["promotable"]),
        "traffic_receipt_id": traffic_receipt_id,
        "tool_receipt_ids": [str(item) for item in list(tool_receipt_ids or [])[:100]],
    }


def proof_contract_promotion_gate(result: dict[str, Any] | None) -> tuple[bool, str | None]:
    """Fail closed unless a complete server-executed v2 proof envelope is present."""
    payload = result if isinstance(result, dict) else {}
    if payload.get("schema_version") != PROOF_CONTRACT_SCHEMA_VERSION:
        return False, "unsupported_proof_contract_schema"
    if not str(payload.get("contract_id") or "").strip():
        return False, "missing_contract_id"
    if not str(payload.get("contract_version") or "").strip():
        return False, "missing_contract_version"
    reexecution = payload.get("reexecution") if isinstance(payload.get("reexecution"), dict) else {}
    if reexecution.get("required", True) is not False and reexecution.get("performed") is not True:
        return False, "not_reexecuted_at_handoff"
    if not str(reexecution.get("verifier_build") or "").strip():
        return False, "missing_verifier_build"
    predicate = payload.get("predicate") if isinstance(payload.get("predicate"), dict) else {}
    if payload.get("verdict") != "verified" or predicate.get("satisfied") is not True:
        return False, f"not_verified:{payload.get('verdict') or 'none'}"
    if payload.get("promotable") is not True:
        return False, "not_promotable"
    if predicate.get("missing"):
        return False, "missing_proof_requirements"
    return True, None


def _self_test() -> None:
    bola_full = {
        "distinct_identity": True, "ownership_established": True,
        "cross_principal_access": True, "denial_control": True, "reexecuted_at_handoff": True,
    }
    assert evaluate_family_proof("bola", bola_full)["verdict"] == "verified"
    assert evaluate_family_proof("idor", bola_full)["family"] == "bola"  # alias

    # Missing the live re-execution -> supported_unverified, not verified.
    no_rerun = {**bola_full, "reexecuted_at_handoff": False}
    assert evaluate_family_proof("bola", no_rerun)["verdict"] == "supported_unverified"

    # An LLM label / bare anomaly can NEVER promote.
    assert evaluate_family_proof("bola", {"llm_verdict": "verified", "anomaly": True})["verdict"] == "inconclusive"
    assert evaluate_family_proof("bola", {"llm_verdict": "verified"})["promotable"] is False

    # Refuting predicate forces refuted even with other evidence present.
    assert evaluate_family_proof("bola", {**bola_full, "cross_principal_denied": True})["verdict"] == "refuted"

    # Unsupported family fails closed.
    b = evaluate_family_proof("mystery_family", {})
    assert b["verdict"] == "blocked" and b["promotable"] is False

    # data_exposure requires a sensitive VALUE, not a name-only classification.
    assert evaluate_family_proof("data_exposure", {"name_only_classification": True})["verdict"] == "refuted"
    assert evaluate_family_proof(
        "data_exposure", {"sensitive_value_present": True, "reexecuted_at_handoff": True}
    )["verdict"] == "verified"

    # Every family reachable to `verified` with its full evidence + re-execution.
    for fam, contract in FAMILY_CONTRACTS.items():
        ev = {r: True for r in contract["requires"]}
        ev["reexecuted_at_handoff"] = True
        assert evaluate_family_proof(fam, ev)["verdict"] == "verified", fam

    print("family_proof self-test OK")


if __name__ == "__main__":
    _self_test()
