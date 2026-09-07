"""Investigation memory must hold evidence honestly and survive an interruption.

Each test here encodes a way this kind of memory produces false confidence: treating a successful
read as proof of entitlement, letting one passing check speak for a whole route, discarding the
ideas that failed, or forgetting enough that a resumed session pays for the same experiment twice.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from hunt.investigation_memory import (  # noqa: E402
    CONFIRMED,
    INCONCLUSIVE,
    INFERRED,
    OBSERVED,
    REFUTED,
    SUPPORTED,
    UNKNOWN,
    AccessObservation,
    Experiment,
    InMemoryGraphStore,
    InvestigationMemory,
    OwnershipClaim,
)

TARGET = "target-1"


@pytest.fixture
def memory():
    return InvestigationMemory(InMemoryGraphStore(), target_id=TARGET)


def _experiment(**overrides):
    base = dict(
        hypothesis="user-b can read user-a's order",
        route_template="/authz/vuln/orders/{id}", method="GET",
        collection="orders", identifier="1001",
        actor_principal="user-b", subject_principal="user-a",
        outcome=SUPPORTED, conditions={"auth_context": "bearer"},
    )
    base.update(overrides)
    return Experiment(**base)


def test_a_successful_read_is_recorded_as_access_not_authorization(memory):
    """The distinction the whole module exists for."""
    recorded = memory.record_access(AccessObservation(
        principal="user-a", collection="orders", identifier="1001",
        status=200, auth_context="bearer", disclosed_fields=("email",),
    ))
    assert recorded["certainty"] == OBSERVED
    assert "does NOT establish who is authorised" in recorded["means"]
    # Reaching an object must not create an ownership claim.
    assert memory.ownership_of("orders", "1001")["certainty"] == UNKNOWN


def test_ownership_is_unknown_until_something_asserts_it(memory):
    assert memory.ownership_of("orders", "4242") == {
        "principal": None, "certainty": UNKNOWN,
        "basis": "no ownership evidence recorded",
    }


def test_an_ownership_claim_must_state_its_basis(memory):
    with pytest.raises(ValueError):
        OwnershipClaim(collection="orders", identifier="1001", principal="user-a", basis="  ")


def test_an_ownership_claim_carries_its_certainty(memory):
    memory.claim_ownership(OwnershipClaim(
        collection="orders", identifier="1001", principal="user-a",
        basis="listing scoped to the caller returned this id", certainty=INFERRED,
    ))
    owner = memory.ownership_of("orders", "1001")
    assert owner["principal"] == "user-a" and owner["certainty"] == INFERRED
    assert "listing scoped to the caller" in owner["basis"]


def test_an_experiment_settles_only_what_it_tested(memory):
    memory.record_experiment(_experiment(outcome=REFUTED))
    conclusion = memory.route_conclusion("GET", "/authz/vuln/orders/{id}")
    assert conclusion["experiments"] == 1
    # Never "safe": the untested remainder is stated explicitly.
    assert "untested pairs and objects remain unexamined" in conclusion["verdict"]
    assert conclusion["tested_pairs"] == ["user-b->user-a"]


def test_one_demonstrated_weakness_is_reported_for_the_route(memory):
    memory.record_experiment(_experiment(outcome=SUPPORTED))
    assert "weakness demonstrated" in memory.route_conclusion(
        "GET", "/authz/vuln/orders/{id}")["verdict"]


def test_an_untested_route_is_not_examined_rather_than_clean(memory):
    assert memory.route_conclusion("GET", "/never/touched")["verdict"] == "not examined"


def test_a_repeated_experiment_is_recognised_so_it_is_not_paid_for_twice(memory):
    first = _experiment()
    memory.record_experiment(first)
    assert memory.already_tried(_experiment())["outcome"] == SUPPORTED


def test_changing_the_conditions_makes_it_a_different_experiment(memory):
    """Skipping this would silently skip the case that matters."""
    memory.record_experiment(_experiment(conditions={"auth_context": "bearer"}))
    assert memory.already_tried(_experiment(conditions={"auth_context": "expired"})) is None


def test_changing_the_subject_principal_makes_it_a_different_experiment(memory):
    memory.record_experiment(_experiment(subject_principal="user-a"))
    assert memory.already_tried(_experiment(subject_principal="user-c")) is None


def test_rejected_and_inconclusive_results_are_retained(memory):
    memory.record_experiment(_experiment(hypothesis="idea one", outcome=REFUTED))
    memory.record_experiment(_experiment(hypothesis="idea two", outcome=INCONCLUSIVE))
    briefing = memory.resume_briefing()
    assert any("idea one — refuted" in item for item in briefing["settled"])
    assert any("idea two — inconclusive" in item for item in briefing["open_questions"])


def test_a_fresh_context_resumes_without_rediscovering_or_repeating(memory):
    """The acceptance criterion: interrupt, resume cold, continue."""
    store = InMemoryGraphStore()
    live = InvestigationMemory(store, target_id=TARGET)
    live.record_access(AccessObservation(
        principal="user-a", collection="orders", identifier="1001",
        status=200, auth_context="bearer",
    ))
    live.claim_ownership(OwnershipClaim(
        collection="orders", identifier="1001", principal="user-a",
        basis="caller-scoped listing", certainty=INFERRED,
    ))
    live.record_experiment(_experiment(outcome=SUPPORTED))

    # A completely fresh reader over the same durable store.
    resumed = InvestigationMemory(store, target_id=TARGET)
    briefing = resumed.resume_briefing()
    assert "object:orders/1001" in briefing["objects"]      # object not rediscovered
    assert "principal:user-a" in briefing["principals"]
    assert briefing["experiments_run"] == 1
    assert resumed.already_tried(_experiment()) is not None  # experiment not repeated
    assert resumed.ownership_of("orders", "1001")["principal"] == "user-a"


def test_an_invalid_outcome_or_certainty_is_refused(memory):
    with pytest.raises(ValueError):
        _experiment(outcome="probably")
    with pytest.raises(ValueError):
        OwnershipClaim(collection="orders", identifier="1", principal="a",
                       basis="x", certainty="fairly sure")


def test_a_refusal_is_recorded_as_faithfully_as_a_success(memory):
    """A 403 is evidence about the boundary and must not be dropped."""
    recorded = memory.record_access(AccessObservation(
        principal="user-b", collection="orders", identifier="1001",
        status=403, auth_context="bearer",
    ))
    assert recorded["succeeded"] is False and recorded["status"] == 403


def test_the_verdict_is_machine_readable_because_the_prose_is_not(memory):
    """The two verdict strings differ only by a leading "no", so prose matching flips the answer."""
    empty = memory.route_conclusion("GET", "/untouched")
    assert empty["weakness_demonstrated"] is False and empty["examined"] is False
    memory.record_experiment(_experiment(outcome=REFUTED))
    refuted = memory.route_conclusion("GET", "/authz/vuln/orders/{id}")
    assert refuted["weakness_demonstrated"] is False and refuted["examined"] is True
    memory.record_experiment(_experiment(hypothesis="another", outcome=SUPPORTED))
    assert memory.route_conclusion("GET", "/authz/vuln/orders/{id}")["weakness_demonstrated"] is True
