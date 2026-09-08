"""The assisted authorization workflow against the seeded component fixture.

The differential is called directly here. The integrated REST/persistence path is
covered separately in test_hunt_authorization_api.py. A collection-level result
must not be attributed to an object without matching validated evidence.
"""

import asyncio
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "tests/e2e/fixtures"))
sys.path.insert(0, str(ROOT / "scanner"))

import fixtures_server  # noqa: E402
from hunt.authorization_workflow import (  # noqa: E402
    CapturedRequest,
    explain,
    investigate,
    outcome_from_result,
    reproduction,
    resume,
)
from hunt.investigation_memory import (  # noqa: E402
    INCONCLUSIVE,
    INFERRED,
    REFUTED,
    SUPPORTED,
    UNKNOWN,
    AccessObservation,
    InMemoryGraphStore,
    InvestigationMemory,
    OwnershipClaim,
)
from scanner_tools.access_control_checks import authz_resource_replay_test  # noqa: E402

TOKENS = {"user-a": "authz-token-a", "user-b": "authz-token-b"}
PRINCIPALS = ["user-a", "user-b"]


@pytest.fixture(scope="module")
def base_url():
    server = fixtures_server.start(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


@pytest.fixture
def memory():
    return InvestigationMemory(InMemoryGraphStore(), target_id="target-1")


async def _fetch(url, headers=None, timeout=10, **_kwargs):
    request = urllib.request.Request(url)
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {"status_code": response.status, "headers": dict(response.headers),
                    "body": response.read().decode(), "error": None}
    except urllib.error.HTTPError as exc:
        return {"status_code": exc.code, "headers": {}, "body": exc.read().decode(), "error": None}


def _session(principal):
    return SimpleNamespace(
        config=SimpleNamespace(headers={"Authorization": f"Bearer {TOKENS[principal]}"}, cookies={}),
        state=None,
    )


def execute(base, proposal, mode):
    """Run the proposed experiment through the shipping collection differential."""
    collection = f"{base}/{proposal.collection}".replace("/vuln/", f"/{mode}/")
    obj = f"{collection}/{proposal.identifier}"
    return asyncio.run(authz_resource_replay_test(
        base, [collection, obj],
        _session(proposal.subject_principal), _session(proposal.actor_principal),
        max_producers=5, max_replays=20, timeout=10, max_seconds=30,
        fetcher=_fetch, allow_write_replays=False,
    ))


def captured(mode="vuln"):
    return CapturedRequest(method="GET", path=f"/authz/{mode}/orders/1001", principal="user-a")


def test_a_captured_request_yields_a_proposal_with_the_evidence_it_needs(memory):
    result = investigate(captured(), available_principals=PRINCIPALS, memory=memory)
    assert len(result["proposals"]) == 1
    proposal = result["proposals"][0]
    assert proposal.actor_principal == "user-b" and proposal.subject_principal == "user-a"
    assert any("own baseline" in item for item in proposal.evidence_needed)
    assert any("owner's view" in item for item in proposal.evidence_needed)


def test_a_request_without_an_object_is_declined_with_a_reason(memory):
    result = investigate(CapturedRequest(method="GET", path="/authz/vuln/orders", principal="user-a"),
                         available_principals=PRINCIPALS, memory=memory)
    assert result["proposals"] == []
    assert "does not address a specific object" in result["not_proposed"][0]


def test_a_single_principal_cannot_support_a_cross_user_test(memory):
    result = investigate(captured(), available_principals=["user-a"], memory=memory)
    assert result["proposals"] == []
    assert "second principal" in result["not_proposed"][0]


def test_the_approved_experiment_finds_the_weakness_and_is_recorded(base_url, memory):
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    result = execute(base_url, proposal, "vuln")
    assert result["vulnerable"] is True
    outcome, _ = outcome_from_result(proposal, result)
    assert outcome == SUPPORTED
    memory.record_experiment(proposal.as_experiment(outcome))
    conclusion = memory.route_conclusion(proposal.method, proposal.route_template)
    assert conclusion["weakness_demonstrated"] is True


def test_the_same_loop_on_the_patched_twin_finds_nothing(base_url, memory):
    proposal = investigate(captured("safe"), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    result = execute(base_url, proposal, "safe")
    assert result["vulnerable"] is False
    outcome, _ = outcome_from_result(proposal, result)
    # No exact selected-request denial record is exported by this raw helper.
    # The integrated API can refute from canonical action-linked HTTP records.
    assert outcome == INCONCLUSIVE
    memory.record_experiment(proposal.as_experiment(outcome))
    conclusion = memory.route_conclusion(proposal.method, proposal.route_template)
    assert conclusion["weakness_demonstrated"] is False
    assert "untested pairs and objects remain unexamined" in conclusion["verdict"]


def test_a_skipped_proposal_leaves_no_trace(memory):
    investigate(captured(), available_principals=PRINCIPALS, memory=memory)
    assert memory.resume_briefing()["experiments_run"] == 0


def test_explaining_a_confirmed_result_states_what_was_crossed():
    told = explain(owner_status=200, attacker_status=200, owner_fields=["email", "address"],
                   attacker_fields=["email", "address"], object_absent_from_attacker_listing=True, proven=True)
    assert told["certainty"] == "confirmed"
    assert "belonging to another principal" in told["reading"]
    assert told["fields_visible_to_both"] == ["address", "email"]
    assert told["scope"] == "this pair of principals, this object, these conditions"


def test_explaining_shared_access_does_not_read_as_a_breach():
    told = explain(owner_status=200, attacker_status=200, owner_fields=["email"], attacker_fields=["email"],
                   object_absent_from_attacker_listing=False, proven=False)
    assert told["certainty"] == UNKNOWN
    assert "shared access rather than a boundary crossing" in told["reading"]


def test_explaining_an_enforced_boundary_does_not_declare_the_route_safe():
    told = explain(owner_status=200, attacker_status=403, owner_fields=["email"], attacker_fields=[],
                   object_absent_from_attacker_listing=True, proven=False)
    assert told["status_differs"] is True
    assert "not proof the route is safe elsewhere" in told["reading"]


def test_explaining_without_a_baseline_admits_it_cannot_say():
    told = explain(owner_status=200, attacker_status=200, owner_fields=["email"], attacker_fields=["email"],
                   object_absent_from_attacker_listing=None, proven=False)
    assert told["certainty"] == UNKNOWN
    assert "not possible to say" in told["reading"]


def test_a_resumed_context_does_not_re_propose_finished_work(memory):
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    memory.record_experiment(proposal.as_experiment(SUPPORTED))
    again = investigate(captured(), available_principals=PRINCIPALS, memory=memory)
    assert again["proposals"] == []
    assert "already tested as user-b: supported" in again["not_proposed"][0]


def test_resuming_restores_facts_settled_results_and_open_questions(memory):
    memory.record_access(AccessObservation(principal="user-a", collection="orders", identifier="1001", status=200, auth_context="bearer"))
    memory.claim_ownership(OwnershipClaim(collection="orders", identifier="1001", principal="user-a", basis="caller-scoped listing", certainty=INFERRED))
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    memory.record_experiment(proposal.as_experiment(SUPPORTED))
    briefing = resume(memory)
    assert "object:orders/1001" in briefing["objects"]
    assert briefing["experiments_run"] == 1
    assert any("supported" in item for item in briefing["settled"])
    assert "propose a new object or principal pair" in briefing["next_step_hint"]


def test_reproduction_is_the_minimal_evidence_backed_sequence(memory):
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    steps = reproduction(proposal, origin="https://app.example.test")
    assert [s["as"] for s in steps] == ["user-b", "user-a", "user-b"]
    assert steps[0]["request"].endswith("/authz/vuln/orders")
    assert steps[-1]["request"].endswith("/authz/vuln/orders/1001")
    assert all(step["establishes"] for step in steps)


@pytest.mark.parametrize("verb", ["POST", "DELETE", "PUT", "PATCH"])
def test_a_mutating_request_is_not_proposed_as_read_only(memory, verb):
    result = investigate(CapturedRequest(method=verb, path="/authz/vuln/orders/1001", principal="user-a"),
                         available_principals=PRINCIPALS, memory=memory)
    assert result["proposals"] == []
    assert "mutation authorization" in result["not_proposed"][0]


def test_identical_answers_without_proof_are_inconclusive_not_enforcement():
    told = explain(owner_status=200, attacker_status=200, owner_fields=["email"], attacker_fields=["email"],
                   object_absent_from_attacker_listing=True, proven=False)
    assert told["certainty"] == UNKNOWN
    assert "not evidence of enforcement" in told["reading"]


def test_an_inconclusive_attempt_is_re_proposed_with_its_reason(memory):
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    memory.record_experiment(proposal.as_experiment(INCONCLUSIVE))
    again = investigate(captured(), available_principals=PRINCIPALS, memory=memory)
    assert len(again["proposals"]) == 1
    assert "previous attempt was inconclusive" in again["proposals"][0].why


def test_a_settled_experiment_can_be_retried_on_explicit_instruction(memory):
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    memory.record_experiment(proposal.as_experiment(SUPPORTED))
    assert investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"] == []
    again = investigate(captured(), available_principals=PRINCIPALS, memory=memory, retry_settled=True)
    assert len(again["proposals"]) == 1


def test_another_objects_finding_cannot_confirm_the_selected_object(base_url, memory):
    sealed = CapturedRequest(method="GET", path="/authz/vuln/orders/1009", principal="user-a")
    proposal = investigate(sealed, available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    result = execute(base_url, proposal, "vuln")
    assert result["vulnerable"] is True
    outcome, why = outcome_from_result(proposal, result)
    assert outcome != SUPPORTED
    assert "1009" in why
    memory.record_experiment(proposal.as_experiment(outcome))
    assert memory.route_conclusion(proposal.method, proposal.route_template)["weakness_demonstrated"] is False


def test_outcome_is_bound_to_the_evidence_for_this_object(base_url, memory):
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    result = execute(base_url, proposal, "vuln")
    outcome, why = outcome_from_result(proposal, result)
    assert outcome == SUPPORTED
    assert "evidence names object 1001" in why


def test_patched_replay_without_selected_denial_record_remains_inconclusive(base_url, memory):
    proposal = investigate(captured("safe"), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    outcome, why = outcome_from_result(proposal, execute(base_url, proposal, "safe"))
    assert outcome == INCONCLUSIVE
    assert "selected request" in why
