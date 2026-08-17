import os
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "scanner"))

from ai_verdict_policy import has_deterministic_exploit_proof  # noqa: E402


def _proof(**overrides):
    proof = {
        "schema_version": "proof-contract/v2",
        "contract_id": "device.service_exposure",
        "contract_version": "1.0.0",
        "reexecution": {"performed": True, "verifier_build": "worker:test"},
        "predicate": {"verdict": "verified", "promotable": True, "missing": []},
    }
    proof.update(overrides)
    return proof


def test_complete_proof_contract_v2_is_deterministic_proof():
    assert has_deterministic_exploit_proof({"proof_contract_v2": _proof()}) is True


def test_incomplete_or_unreexecuted_proof_contract_v2_fails_closed():
    proof = _proof(reexecution={"performed": False, "verifier_build": "worker:test"})
    assert has_deterministic_exploit_proof({"proof_contract_v2": proof}) is False
    proof = _proof(predicate={"verdict": "supported_unverified", "promotable": False, "missing": ["control"]})
    assert has_deterministic_exploit_proof({"proof_contract_v2": proof}) is False


def test_generic_differential_label_is_not_deterministic_proof():
    assert has_deterministic_exploit_proof({"proof_type": "differential_response"}) is False
    assert has_deterministic_exploit_proof({"proof_type": "repeated_semantic_response_diff"}) is True
