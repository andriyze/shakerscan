"""Unit tests for the deterministic family proof contracts (api/family_proof.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import family_proof as fp  # noqa: E402


def _full(family):
    ev = {r: True for r in fp.FAMILY_CONTRACTS[fp.canonical_family(family)]["requires"]}
    ev["reexecuted_at_handoff"] = True
    return ev


def test_self_test():
    fp._self_test()


def test_every_family_reaches_verified_with_full_evidence():
    for fam in fp.FAMILY_CONTRACTS:
        v = fp.evaluate_family_proof(fam, _full(fam))
        assert v["verdict"] == "verified", fam
        assert v["promotable"] is True


def test_llm_label_or_anomaly_cannot_promote():
    for payload in ({"llm_verdict": "verified"}, {"verdict": "verified"}, {"anomaly": True}, {"label": "bola"}):
        v = fp.evaluate_family_proof("bola", payload)
        assert v["verdict"] != "verified"
        assert v["promotable"] is False


def test_missing_reexecution_is_supported_not_verified():
    ev = _full("bola")
    ev["reexecuted_at_handoff"] = False
    assert fp.evaluate_family_proof("bola", ev)["verdict"] == "supported_unverified"


def test_refuting_predicate_forces_refuted():
    ev = {**_full("bola"), "cross_principal_denied": True}
    assert fp.evaluate_family_proof("bola", ev)["verdict"] == "refuted"


def test_unsupported_family_fails_closed():
    v = fp.evaluate_family_proof("totally_unknown", {"x": True})
    assert v["verdict"] == "blocked"
    assert v["promotable"] is False


def test_aliases_canonicalize():
    assert fp.canonical_family("IDOR") == "bola"
    assert fp.canonical_family("sqli") == "injection"
    assert fp.canonical_family("BFLA") == "auth_bypass"
    assert fp.evaluate_family_proof("idor", _full("bola"))["family"] == "bola"


def test_data_exposure_requires_value_not_name():
    assert fp.evaluate_family_proof("data_exposure", {"name_only_classification": True})["verdict"] == "refuted"
    ok = fp.evaluate_family_proof("data_exposure", {"sensitive_value_present": True, "reexecuted_at_handoff": True})
    assert ok["verdict"] == "verified"


def test_partial_evidence_is_supported_unverified():
    v = fp.evaluate_family_proof("bola", {"distinct_identity": True, "reexecuted_at_handoff": True})
    assert v["verdict"] == "supported_unverified"
    assert "cross_principal_access" in v["missing"]


def test_no_evidence_is_inconclusive():
    assert fp.evaluate_family_proof("bola", {})["verdict"] == "inconclusive"


def test_all_verdicts_are_known():
    for fam in list(fp.FAMILY_CONTRACTS) + ["unknown"]:
        assert fp.evaluate_family_proof(fam, {})["verdict"] in fp.VERDICTS


def test_promotion_gate_only_passes_verified_reexecuted():
    verified = fp.evaluate_family_proof("bola", _full("bola"))
    assert fp.promotion_gate(verified) == (True, None)

    supported = fp.evaluate_family_proof("bola", {"distinct_identity": True, "reexecuted_at_handoff": True})
    ok, reason = fp.promotion_gate(supported)
    assert not ok and reason.startswith("not_verified")

    # A crafted "verified" without the re-execution flag is still refused.
    assert fp.promotion_gate({"verdict": "verified", "promotable": True, "reexecuted_at_handoff": False}) == (
        False, "not_reexecuted_at_handoff",
    )
    assert fp.promotion_gate({}) == (False, "not_verified:none")


def test_caller_claim_preflight_can_neither_verify_nor_refute():
    asserted_verified = fp.evaluate_claim_preflight("bola", _full("bola"))
    assert asserted_verified["verdict"] == "supported_unverified"
    assert asserted_verified["reexecuted_at_handoff"] is False
    assert asserted_verified["promotable"] is False

    asserted_refuted = fp.evaluate_claim_preflight("bola", {"cross_principal_denied": True})
    assert asserted_refuted["verdict"] == "inconclusive"
    assert asserted_refuted["promotable"] is False


def test_v2_proof_envelope_requires_verifier_build_and_live_reexecution():
    result = fp.build_proof_contract_result(
        "device_service_exposure",
        {
            "protocol_handshake": True,
            "policy_denied": True,
            "recent_observation": True,
            "reexecuted_at_handoff": True,
        },
        contract_id="device.service_exposure",
        contract_version="1.0.0",
        verifier_build="worker:abc123",
        subject={"device_target_id": "d1", "transport": "tcp", "port": 23},
        proof_basis="protocol_handshake",
    )

    assert result["schema_version"] == "proof-contract/v2"
    assert result["verdict"] == "verified"
    assert fp.proof_contract_promotion_gate(result) == (True, None)

    missing_build = {**result, "reexecution": {"performed": True, "verifier_build": ""}}
    assert fp.proof_contract_promotion_gate(missing_build) == (
        False, "missing_verifier_build",
    )


def test_device_proof_contract_refuters_override_positive_predicates():
    result = fp.build_proof_contract_result(
        "device_auth_bypass",
        {
            "protected_resource_established": True,
            "anonymous_semantic_equivalence": True,
            "negative_control": True,
            "anonymous_access_denied": True,
            "reexecuted_at_handoff": True,
        },
        contract_id="device.auth_bypass",
        contract_version="1.0.0",
        verifier_build="worker:abc123",
    )

    assert result["verdict"] == "refuted"
    assert fp.proof_contract_promotion_gate(result)[0] is False
