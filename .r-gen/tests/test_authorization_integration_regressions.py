"""Remaining prototype errors and exact action/evidence attribution regressions."""
from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from api.hunt.authorization_evidence import AuthorizationWorkflowError, attributed_outcome, mapping
from api.hunt.authorization_workflow import CapturedRequest, explain, investigate, outcome_from_result, reproduction
from api.hunt.investigation_memory import (
    INCONCLUSIVE, SUPPORTED, UNKNOWN, Experiment, InMemoryGraphStore,
    InvestigationMemory, OwnershipClaim,
)


def memory():
    return InvestigationMemory(InMemoryGraphStore(), target_id="target-1")


def proposal(store=None, path="/orders/1001"):
    return investigate(CapturedRequest("GET", path, "primary"), available_principals=["primary", "secondary"],
                       memory=store or memory())["proposals"][0]


@pytest.mark.parametrize("verb", ["DELETE", "PATCH", "PUT", "POST"])
def test_directly_constructed_mutation_cannot_be_reproduced(verb):
    with pytest.raises(ValueError, match="GET-only"):
        reproduction(replace(proposal(), method=verb))


def test_same_object_id_in_another_collection_is_not_the_selected_object():
    item = {"url": "https://app.example.test/invoices/1001", "evidence": {
        "proof_type": "cross_principal_replay", "requested_object_id": "1001"}}
    status, _ = outcome_from_result(proposal(), {"findings": [item]}, validator=lambda _: SimpleNamespace(verified=True))
    assert status == INCONCLUSIVE


def test_same_path_at_another_origin_is_not_the_selected_object():
    selected = replace(proposal(), conditions={"origin": "https://app.example.test"})
    item = {"url": "https://other.example.test/orders/1001", "evidence": {
        "proof_type": "cross_principal_replay", "requested_object_id": "1001"}}
    status, _ = outcome_from_result(selected, {"findings": [item]}, validator=lambda _: SimpleNamespace(verified=True))
    assert status == INCONCLUSIVE


def test_matching_label_without_validation_is_not_proof():
    item = {"url": "https://app.example.test/orders/1001", "evidence": {
        "proof_type": "cross_principal_replay", "requested_object_id": "1001"}}
    status, _ = outcome_from_result(proposal(), {"findings": [item]}, validator=lambda _: SimpleNamespace(verified=False))
    assert status == INCONCLUSIVE


def test_aggregate_negative_replay_count_cannot_refute_the_selection():
    status, _ = outcome_from_result(proposal(), {"replays_completed": 10, "findings": []})
    assert status == INCONCLUSIVE


def test_validated_selected_object_is_supported():
    item = {"url": "https://app.example.test/orders/1001", "evidence": {
        "proof_type": "cross_principal_replay", "requested_object_id": "1001"}}
    status, why = outcome_from_result(proposal(), {"findings": [item]}, validator=lambda _: SimpleNamespace(verified=True))
    assert status == SUPPORTED and "evidence names object 1001" in why


@pytest.mark.parametrize("actor_status", [0, 401, 404, 429, 500, 503])
def test_transport_or_authentication_errors_are_not_boundary_enforcement(actor_status):
    result = explain(owner_status=200, attacker_status=actor_status, owner_fields=[], attacker_fields=[],
                     object_absent_from_attacker_listing=True, proven=False)
    assert result["certainty"] == UNKNOWN
    assert "not evidence of enforcement" in result["reading"]


def test_contradictory_confirmed_flag_does_not_overrule_observations():
    result = explain(owner_status=200, attacker_status=403, owner_fields=[], attacker_fields=[],
                     object_absent_from_attacker_listing=True, proven=True)
    assert result["certainty"] == UNKNOWN


def test_exact_trailing_slash_survives_reproduction():
    steps = reproduction(proposal(path="/orders/1001/"), origin="https://app.example.test")
    assert steps[-1]["request"] == "GET https://app.example.test/orders/1001/"


@pytest.mark.parametrize("path", ["/orders/" + "-" * 36, "/orders/1001?view=secret", "/orders//1001", "/../1001"])
def test_shape_heuristics_do_not_rewrite_unsupported_captures(path):
    assert not CapturedRequest("GET", path, "primary").addresses_an_object


def test_retrying_after_a_new_inconclusive_attempt_keeps_the_issue_open():
    store = memory(); plan = proposal(store)
    store.record_experiment(plan.as_experiment(SUPPORTED))
    store.record_experiment(replace(plan.as_experiment(INCONCLUSIVE), detail="session expired"))
    resumed = investigate(CapturedRequest("GET", "/orders/1001", "primary"),
                          available_principals=["primary", "secondary"], memory=store)
    assert len(resumed["proposals"]) == 1
    assert "session expired" in resumed["proposals"][0].why
    briefing = store.resume_briefing()
    assert briefing["open_questions"] and not briefing["settled"]
    # The latest attempt is inconclusive, so the route is not *currently* demonstrated, but the
    # earlier demonstration is retained rather than reinterpreted as fixed.
    conclusion = store.route_conclusion("GET", "/orders/{id}")
    assert conclusion["weakness_demonstrated"] is False
    assert conclusion["historical_weakness_demonstrated"] is True


def test_same_attempt_read_twice_is_not_two_executions():
    store = memory()
    attempt = replace(proposal().as_experiment(SUPPORTED), attempt_id="canonical-action", evidence_refs=("receipt-1",))
    store.record_experiment(attempt)
    store.record_experiment(replace(attempt, at="another read time"))
    assert store.resume_briefing()["attempts_run"] == 1
    with pytest.raises(ValueError, match="different evidence"):
        store.record_experiment(replace(attempt, outcome=INCONCLUSIVE))


def test_conflicting_ownership_claims_are_not_resolved_by_insertion_order():
    store = memory()
    for principal in ("a", "b"):
        store.claim_ownership(OwnershipClaim("orders", "1001", principal, "claimed by listing"))
    assert store.ownership_of("orders", "1001")["certainty"] == UNKNOWN
