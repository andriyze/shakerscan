"""Own-object crossings become useful Hunt leads without becoming proof."""
from api.hunt.authorization_candidate import candidate_plan


def state(**overrides):
    base = {
        "baseline_kind": "own_object",
        "expected_access": "denied",
        "authorization_assessment": "potential_violation",
        "cross_access_observed": True,
        "selected_request_examined": True,
        "proposal_id": "00000000-0000-0000-0000-000000000010",
        "proposal_digest": "a" * 64,
        "route": "/rest/basket/<owner-object>",
        "attempts": [{
            "attempt": 1,
            "action_id": "00000000-0000-0000-0000-000000000011",
            "receipt_id": "00000000-0000-0000-0000-000000000012",
            "transaction_ids": ["00000000-0000-0000-0000-000000000013"],
            "cross_access_observed": True,
            "authorization_assessment": "potential_violation",
            "proof_state": "inconclusive",
            "certainty": "observed",
        }],
    }
    base.update(overrides)
    return base


def test_potential_violation_becomes_an_explicitly_unverified_bola_candidate_plan():
    plan = candidate_plan(state())
    assert plan is not None
    assert plan["family"] == "bola" and plan["severity"] == "high"
    assert plan["verifier_contract_id"] is None
    assert plan["locus"] == {"method": "GET", "route": "/rest/basket/<owner-object>"}
    assert "unverified authorization candidate" in plan["claim"]
    assert plan["observation_context"]["proof_state"] == "inconclusive"
    assert plan["observation_context"]["authoritative"] is False
    assert plan["observation_context"]["finding_promoted"] is False


def test_action_receipt_and_transactions_are_the_only_candidate_evidence_refs():
    plan = candidate_plan(state())
    assert plan["evidence_refs"] == [
        "00000000-0000-0000-0000-000000000011",
        "00000000-0000-0000-0000-000000000012",
        "00000000-0000-0000-0000-000000000013",
    ]


def test_shared_or_unknown_entitlement_does_not_create_a_candidate():
    assert candidate_plan(state(expected_access="allowed", authorization_assessment="shared_access_as_declared")) is None
    assert candidate_plan(state(expected_access="unknown", authorization_assessment="entitlement_unknown")) is None


def test_denied_or_incomplete_access_does_not_create_a_candidate():
    assert candidate_plan(state(cross_access_observed=False, authorization_assessment="access_denied")) is None
    broken = state()
    broken["attempts"][-1]["receipt_id"] = None
    assert candidate_plan(broken) is None


def test_verified_or_unattributed_result_is_not_reinterpreted_as_this_unverified_lead():
    verified = state()
    verified["attempts"][-1]["proof_state"] = "verified"
    assert candidate_plan(verified) is None
    unattributed = state(selected_request_examined=False)
    assert candidate_plan(unattributed) is None
