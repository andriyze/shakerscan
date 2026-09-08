from copy import deepcopy

import pytest

from scripts.score_hunt_investigation import score_run


def inputs():
    record = {"schema_version": "hunt-record/v1", "hunt": {"hunt_id": "h1", "target_id": "t1", "status": "completed"},
              "decision_trace": [{"action_id": "a1", "status": "completed", "result": {
                  "reference_ids": {}, "budget_accounting": {"basis": "exact_settlement",
                    "charge_basis": "capability_reported_settlement", "actual": {"http_requests": 4}}}}]}
    oracle = {"hunt_id": "h1", "target_id": "t1", "baseline_fingerprints": [], "expected": [], "negative_controls": []}
    investigations = [{"schema_version": "hunt-authorization/v1", "hunt_id": "h1", "proposal_id": "p1",
        "attempts": [{"attempt": 1, "action_id": "a1"}],
        "candidate_history": [{"id": "c1", "created_from_attempt": 1}]}]
    review = {"hunt_id": "h1", "useful_lead_ids": ["c1"], "not_useful_lead_ids": [], "human_minutes": 12.5, "duplicate_experiments": 0}
    return record, oracle, investigations, review


def test_useful_lead_metrics_cannot_increase_verified_findings_or_recall():
    record, oracle, investigations, review = inputs()
    result = score_run(record, [], oracle, investigations=investigations, review=review)
    assert result["new_verified_fingerprints"] == 0
    assert result["recall"] is None
    assert result["operator_review"]["useful_leads"] == 1
    assert result["operator_review"]["human_minutes"] == 12.5
    assert result["operator_review"]["productivity_improvement_demonstrated"] is False


def test_missing_human_measurement_is_null_not_zero():
    record, oracle, investigations, _ = inputs()
    result = score_run(record, [], oracle, investigations=investigations)["operator_review"]
    assert result["available"] is False and result["human_minutes"] is None
    assert result["useful_leads"] is None and result["unreviewed_leads"] == 1


@pytest.mark.parametrize("change", [
    {"useful_lead_ids": ["foreign"]}, {"not_useful_lead_ids": ["c1"]},
    {"useful_lead_ids": ["c1", "c1"]}, {"human_minutes": float("nan")},
    {"human_minutes": float("inf")}, {"human_minutes": True}, {"hunt_id": "other"},
    {"duplicate_experiments": -1},
])
def test_invalid_or_unbound_human_labels_are_rejected(change):
    record, oracle, investigations, review = inputs()
    with pytest.raises(ValueError):
        score_run(record, [], oracle, investigations=investigations, review={**review, **change})


def test_candidate_links_require_an_action_in_the_canonical_run():
    record, oracle, investigations, review = inputs()
    investigations[0]["attempts"][0]["action_id"] = "unrelated"
    with pytest.raises(ValueError, match="not linked"):
        score_run(record, [], oracle, investigations=investigations, review=review)


def test_duplicate_exports_do_not_inflate_review_metrics():
    record, oracle, investigations, review = inputs()
    with pytest.raises(ValueError, match="duplicate"):
        score_run(record, [], oracle, investigations=investigations + deepcopy(investigations), review=review)


def test_conservative_settlement_is_not_measured_traffic():
    record, oracle, _, _ = inputs()
    record["decision_trace"][0]["result"]["budget_accounting"].update(
        charge_basis="conservative_full_reservation", actual={"http_requests": 24})
    result = score_run(record, [], oracle)
    assert result["measured_action_budget"] == {}
    assert result["settled_upper_bound_budget"] == {"http_requests": 24}
    assert result["complete_exact_accounting"] is False


@pytest.mark.parametrize("amount", [float("nan"), float("inf"), -1, True])
def test_invalid_accounting_is_rejected(amount):
    record, oracle, _, _ = inputs()
    record["decision_trace"][0]["result"]["budget_accounting"]["actual"]["http_requests"] = amount
    with pytest.raises(ValueError, match="Invalid measured"):
        score_run(record, [], oracle)
