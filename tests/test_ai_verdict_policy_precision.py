import os
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "scanner"))

from ai_verdict_policy import (  # noqa: E402
    build_dast_proof_contract_v2,
    has_deterministic_exploit_proof,
    is_trusted_ai_false_positive,
)


def _proof(**overrides):
    proof = {
        "schema_version": "proof-contract/v2",
        "contract_id": "device.service_exposure",
        "contract_version": "1.0.0",
        "reexecution": {"required": True, "performed": True, "verifier_build": "worker:test"},
        "predicate": {"satisfied": True, "missing": []},
        "verdict": "verified",
        "promotable": True,
    }
    proof.update(overrides)
    return proof


def test_complete_proof_contract_v2_is_deterministic_proof():
    assert has_deterministic_exploit_proof({"proof_contract_v2": _proof()}) is True


def test_incomplete_or_unreexecuted_proof_contract_v2_fails_closed():
    proof = _proof(reexecution={"performed": False, "verifier_build": "worker:test"})
    assert has_deterministic_exploit_proof({"proof_contract_v2": proof}) is False
    proof = _proof(predicate={"satisfied": False, "missing": ["control"]}, verdict="supported_unverified", promotable=False)
    assert has_deterministic_exploit_proof({"proof_contract_v2": proof}) is False


def test_generic_differential_label_is_not_deterministic_proof():
    assert has_deterministic_exploit_proof({"proof_type": "differential_response"}) is False
    assert has_deterministic_exploit_proof({"proof_type": "repeated_semantic_response_diff"}) is True


def test_invalid_supplied_v2_contract_blocks_legacy_boolean_fallback():
    finding = {
        "proof_of_exploitation": True,
        "proof_contract_v2": _proof(predicate={"satisfied": True, "missing": []}, promotable=False),
    }
    assert has_deterministic_exploit_proof(finding) is False


def test_legacy_deterministic_result_can_be_normalized_to_v2():
    finding = {
        "tool": "smart_sqli",
        "url": "https://example.test/search?q=redacted",
        "proof_type": "repeated_semantic_response_diff",
        "validation": {"poe_proven": True, "evidence_level": "confirmed_exploit"},
    }
    contract = build_dast_proof_contract_v2(finding)
    assert contract["schema_version"] == "proof-contract/v2"
    assert contract["predicate"]["satisfied"] is True
    assert contract["verdict"] == "verified"
    assert contract["reexecution"]["performed"] is True


def test_legacy_adapter_is_honest_when_no_live_reexecution_occurred():
    contract = build_dast_proof_contract_v2({
        "tool": "forced_browsing",
        "proof_of_exploitation": True,
    })
    assert contract["reexecution"] == {
        "required": False,
        "performed": False,
        "verifier_build": "forced_browsing",
    }
    assert contract["controls"][0]["legacy_adapter"] is True


def test_ai_false_positive_cannot_erase_canonical_flat_browser_proof():
    finding = {
        "evidence": {
            "proof_producer": "shakerscan",
            "evidence_type": "dom_execution",
            "technique": "headless_xss_dom",
            "dom_marker_executed": True,
        },
        "ai_verdict": "false_positive",
        "ai_confidence": 0.99,
        "ai_classification_source": "provider",
    }
    assert has_deterministic_exploit_proof(finding) is True
    assert is_trusted_ai_false_positive(finding) is False
