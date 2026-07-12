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
