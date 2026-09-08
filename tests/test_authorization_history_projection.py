from copy import deepcopy

import pytest

from api.hunt.authorization_history import with_candidate_history


@pytest.mark.parametrize("assessment", ["access_denied", "inconclusive", "not_examined"])
def test_latest_result_does_not_erase_or_reconfirm_a_historical_lead(assessment):
    state = {"attempts": [{"attempt": 1}, {"attempt": 2}],
             "authorization_assessment": assessment, "cross_access_observed": False,
             "resume": {"open_questions": ["Review missing evidence"]}}
    before = deepcopy(state)
    result = with_candidate_history(state, [{"id": "c1", "created_from_attempt": 1, "authoritative": False}])
    assert result["candidate"]["id"] == "c1"
    assert result["candidate_relation"] == "historical_only"
    assert result["candidate_matches_latest_attempt"] is False
    assert result["authorization_assessment"] == assessment
    assert result["cross_access_observed"] is False
    assert result["resume"]["retained_candidate_ids"] == ["c1"]
    assert result["resume"]["historical_lead_requires_review"] is True
    assert state == before


def test_multiple_attempt_associations_are_retained_but_resume_ids_are_deduplicated():
    result = with_candidate_history({"attempts": [{"attempt": 1}, {"attempt": 2}]}, [
        {"id": "c1", "created_from_attempt": 2}, {"id": "c1", "created_from_attempt": 1}])
    assert len(result["candidate_history"]) == 2
    assert result["candidate"]["created_from_attempt"] == 2
    assert result["candidate_relation"] == "current_attempt"
    assert result["resume"]["retained_candidate_ids"] == ["c1"]


def test_read_without_a_link_does_not_infer_a_candidate_from_observed_access():
    result = with_candidate_history({"cross_access_observed": True, "attempts": [{"attempt": 1}]}, [])
    assert result["candidate"] is None
    assert result["candidate_history"] == []
    assert result["candidate_relation"] == "none"


def test_unexecuted_proposal_has_no_historical_or_current_candidate():
    result = with_candidate_history({"attempts": []}, [])
    assert result["candidate"] is None
    assert result["resume"]["latest_authorization_assessment"] == "not_examined"
