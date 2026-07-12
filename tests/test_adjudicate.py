"""Unit tests for the pure adjudication module (api/adjudicate.py).

Runs on the host — the module has no db/httpx/fastapi imports.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import adjudicate  # noqa: E402


DET_CITE = {"verdict_basis": "deterministic_replay", "cite": {"mitigation": "ownership 403", "observed": True}}


def test_self_test_passes():
    # The module's own invariants must hold.
    adjudicate._self_test()


def test_corroborated_deterministic_refute_counts():
    vote = adjudicate.citecheck_vote({"refuter_verdict": "refuted", **DET_CITE})
    assert vote["counts_as_refute"] is True
    assert vote["corroborated"] is True
    assert vote["downgraded"] is False


def test_signal_only_refute_is_downgraded():
    vote = adjudicate.citecheck_vote(
        {"refuter_verdict": "refuted", "verdict_basis": "signal_only", "cite": {"observed": True}}
    )
    assert vote["counts_as_refute"] is False
    assert vote["downgraded"] is True
    assert vote["reason"] == "refute_basis_not_deterministic"


def test_deterministic_but_uncorroborated_refute_is_downgraded():
    vote = adjudicate.citecheck_vote({"refuter_verdict": "refuted", "verdict_basis": "deterministic_replay"})
    assert vote["counts_as_refute"] is False
    assert vote["reason"] == "refute_missing_corroborating_evidence"


def test_evidence_ids_corroborate_a_deterministic_refute():
    vote = adjudicate.citecheck_vote(
        {"refuter_verdict": "refuted", "verdict_basis": "cryptographic", "tool_receipt_ids": ["r1"]}
    )
    assert vote["counts_as_refute"] is True


def test_strict_majority_refute_dismisses():
    panel = adjudicate.adjudicate_panel([
        {"refuter_verdict": "refuted", **DET_CITE},
        {"refuter_verdict": "refuted", **DET_CITE},
        {"refuter_verdict": "supported", "verdict_basis": "deterministic_replay"},
    ])
    assert panel["verdict"] == "refuted"
    assert panel["survives"] is False
    assert panel["refuted_count"] == 2


def test_tie_resolves_to_survive():
    panel = adjudicate.adjudicate_panel([
        {"refuter_verdict": "refuted", **DET_CITE},
        {"refuter_verdict": "supported", "verdict_basis": "deterministic_replay"},
    ])
    assert panel["verdict"] != "refuted"
    assert panel["survives"] is True


def test_panel_of_only_uncorroborated_refutes_survives():
    panel = adjudicate.adjudicate_panel([
        {"refuter_verdict": "refuted", "verdict_basis": "signal_only"},
        {"refuter_verdict": "refuted", "verdict_basis": "signal_only"},
    ])
    assert panel["verdict"] == "inconclusive"
    assert panel["survives"] is True
    assert panel["downgraded_count"] == 2


def test_panel_below_min_is_inconclusive():
    panel = adjudicate.adjudicate_panel([{"refuter_verdict": "refuted", **DET_CITE}])
    assert panel["verdict"] == "inconclusive"
    assert panel["survives"] is True


def test_negative_gate_accepts_deterministic_reference():
    ok, reason = adjudicate.require_deterministic_refutation(
        {"verdict_basis": "deterministic_replay", "refuted_by": {"verification_id": "abc"}}
    )
    assert ok is True and reason is None


def test_negative_gate_rejects_llm_source():
    ok, reason = adjudicate.require_deterministic_refutation(
        {"verdict_basis": "deterministic_replay", "refuted_by": {"ref": "x", "source": "llm"}}
    )
    assert ok is False and reason == "refuted_by_llm_forbidden"


def test_negative_gate_rejects_non_deterministic_basis():
    ok, reason = adjudicate.require_deterministic_refutation(
        {"verdict_basis": "signal_only", "refuted_by": {"verification_id": "abc"}}
    )
    assert ok is False and reason == "refutation_basis_not_deterministic"


def test_negative_gate_rejects_missing_reference():
    ok, reason = adjudicate.require_deterministic_refutation({"verdict_basis": "deterministic_replay"})
    assert ok is False and reason == "refutation_missing_deterministic_reference"


def test_evidence_strength_ladder_order():
    assert adjudicate.evidence_strength_rank("claimed") < adjudicate.evidence_strength_rank("signal")
    assert adjudicate.evidence_strength_rank("signal") < adjudicate.evidence_strength_rank("reproduced")
    assert adjudicate.evidence_strength_rank("reproduced") < adjudicate.evidence_strength_rank(
        "cross_principal_verified"
    )
    assert adjudicate.meets_strength("cross_principal_verified", "cross_principal_verified") is True
    assert adjudicate.meets_strength("reproduced", "cross_principal_verified") is False
    assert adjudicate.evidence_strength_rank("bogus") == -1


def test_vote_from_review_normalizes_counterevidence_cite():
    vote = adjudicate.vote_from_review(
        {"refuter_verdict": "refuted", "verdict_basis": "deterministic_replay",
         "counterevidence": {"cite": {"mitigation": "403", "observed": True}}, "created_by": "r"}
    )
    checked = adjudicate.citecheck_vote(vote)
    assert checked["counts_as_refute"] is True
