"""The assisted authorization workflow, driven end to end against the seeded fixture.

This is the milestone's user-facing claim under test: a pentester hands Hunt a captured request,
Hunt proposes a cross-user test and says what evidence it needs, the human approves it, the
existing differential executes it, the result is explained with its uncertainty and recorded, and a
fresh context can resume and reproduce without repeating the work.

The workflow never decides proof. Whether the finding stands is settled by the deterministic
differential, which these tests call directly.
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
    """Run the approved experiment through the SHIPPING differential."""
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


def test_proposal_export_cannot_mutate_approved_conditions(memory):
    from dataclasses import replace

    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    supplied = {"credentials": {"versions": [1, 2]}}
    proposal = replace(proposal, conditions=supplied)
    identity = proposal.as_experiment(INCONCLUSIVE).key
    supplied["credentials"]["versions"].append(3)
    exported = proposal.as_row()
    exported["conditions"]["credentials"]["versions"].append(4)
    assert proposal.as_experiment(INCONCLUSIVE).key == identity
    assert proposal.conditions["credentials"]["versions"] == (1, 2)


def test_inconclusive_retry_reopens_previously_supported_experiment(memory):
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    memory.record_experiment(proposal.as_experiment(SUPPORTED))
    memory.record_experiment(proposal.as_experiment(INCONCLUSIVE))
    again = investigate(captured(), available_principals=PRINCIPALS, memory=memory)
    assert len(again["proposals"]) == 1
    assert "previous attempt was inconclusive" in again["proposals"][0].why


# -- investigate ---------------------------------------------------------------------------

def test_a_captured_request_yields_a_proposal_with_the_evidence_it_needs(memory):
    result = investigate(captured(), available_principals=PRINCIPALS, memory=memory)
    assert len(result["proposals"]) == 1
    proposal = result["proposals"][0]
    assert proposal.actor_principal == "user-b" and proposal.subject_principal == "user-a"
    # The pentester is told what the test will need before approving it.
    assert any("own baseline" in item for item in proposal.evidence_needed)
    assert any("owner's view" in item for item in proposal.evidence_needed)


def test_a_request_without_an_object_is_declined_with_a_reason(memory):
    result = investigate(
        CapturedRequest(method="GET", path="/authz/vuln/orders", principal="user-a"),
        available_principals=PRINCIPALS, memory=memory,
    )
    assert result["proposals"] == []
    assert "does not address a specific object" in result["not_proposed"][0]


def test_a_single_principal_cannot_support_a_cross_user_test(memory):
    result = investigate(captured(), available_principals=["user-a"], memory=memory)
    assert result["proposals"] == []
    assert "second principal" in result["not_proposed"][0]


# -- approve and execute -------------------------------------------------------------------

def test_the_approved_experiment_finds_the_weakness_and_is_recorded(base_url, memory):
    """The whole loop on the vulnerable twin."""
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    result = execute(base_url, proposal, "vuln")
    assert result["vulnerable"] is True

    memory.record_experiment(proposal.as_experiment(SUPPORTED))
    conclusion = memory.route_conclusion(proposal.method, proposal.route_template)
    assert conclusion["weakness_demonstrated"] is True


def test_the_same_loop_on_the_patched_twin_finds_nothing(base_url, memory):
    proposal = investigate(captured("safe"), available_principals=PRINCIPALS,
                           memory=memory)["proposals"][0]
    result = execute(base_url, proposal, "safe")
    assert result["vulnerable"] is False

    memory.record_experiment(proposal.as_experiment(REFUTED))
    conclusion = memory.route_conclusion(proposal.method, proposal.route_template)
    # A refuted experiment must never read as "safe".
    assert "untested pairs and objects remain unexamined" in conclusion["verdict"]


def test_a_skipped_proposal_leaves_no_trace(memory):
    """Skipping is a real choice: nothing is recorded, so it can be reconsidered."""
    investigate(captured(), available_principals=PRINCIPALS, memory=memory)
    assert memory.resume_briefing()["experiments_run"] == 0


# -- explain ---------------------------------------------------------------------------------

def test_explaining_a_confirmed_result_states_what_was_crossed():
    told = explain(owner_status=200, attacker_status=200, owner_fields=["email", "address"],
                   attacker_fields=["email", "address"],
                   object_absent_from_attacker_listing=True, proven=True)
    assert told["certainty"] == "confirmed"
    assert "belonging to another principal" in told["reading"]
    assert told["fields_visible_to_both"] == ["address", "email"]
    assert told["scope"] == "this pair of principals, this object, these conditions"


def test_explaining_shared_access_does_not_read_as_a_breach():
    told = explain(owner_status=200, attacker_status=200, owner_fields=["email"],
                   attacker_fields=["email"],
                   object_absent_from_attacker_listing=False, proven=False)
    assert told["certainty"] == UNKNOWN
    assert "shared access rather than a boundary crossing" in told["reading"]


def test_explaining_an_enforced_boundary_does_not_declare_the_route_safe():
    told = explain(owner_status=200, attacker_status=403, owner_fields=["email"],
                   attacker_fields=[], object_absent_from_attacker_listing=True, proven=False)
    assert told["status_differs"] is True
    assert "not proof the route is safe elsewhere" in told["reading"]


def test_explaining_without_a_baseline_admits_it_cannot_say():
    told = explain(owner_status=200, attacker_status=200, owner_fields=["email"],
                   attacker_fields=["email"], object_absent_from_attacker_listing=None,
                   proven=False)
    assert told["certainty"] == UNKNOWN
    assert "not possible to say" in told["reading"]


# -- resume and reproduce ---------------------------------------------------------------------

def test_a_resumed_context_does_not_re_propose_finished_work(memory):
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    memory.record_experiment(proposal.as_experiment(SUPPORTED))
    again = investigate(captured(), available_principals=PRINCIPALS, memory=memory)
    assert again["proposals"] == []
    assert "already tested as user-b: supported" in again["not_proposed"][0]


def test_resuming_restores_facts_settled_results_and_open_questions(memory):
    memory.record_access(AccessObservation(principal="user-a", collection="orders",
                                           identifier="1001", status=200, auth_context="bearer"))
    memory.claim_ownership(OwnershipClaim(collection="orders", identifier="1001",
                                          principal="user-a", basis="caller-scoped listing",
                                          certainty=INFERRED))
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
    assert steps[0]["request"].endswith("/authz/vuln/orders")       # baseline first
    assert steps[-1]["request"].endswith("/authz/vuln/orders/1001")  # then the crossing
    assert all(step["establishes"] for step in steps)


# -- review fixes: mutating verbs, honest explanations, retries, evidence attribution ---------

def test_a_mutating_request_is_declined_rather_than_labelled_read_only(memory):
    """A cross-principal DELETE is not a read-only test and must not be proposed as one."""
    for method in ("DELETE", "POST", "PATCH", "PUT"):
        result = investigate(
            CapturedRequest(method=method, path="/authz/vuln/orders/1001", principal="user-a"),
            available_principals=PRINCIPALS, memory=memory,
        )
        assert result["proposals"] == []
        assert "not supported by this workflow" in result["not_proposed"][0]
        assert "mutation authorization" in result["not_proposed"][0]


def test_identical_answers_without_proof_are_inconclusive_not_enforcement():
    """Failing to demonstrate a crossing is not evidence that the boundary held."""
    told = explain(owner_status=200, attacker_status=200, owner_fields=["email"],
                   attacker_fields=["email"],
                   object_absent_from_attacker_listing=True, proven=False)
    assert told["certainty"] == UNKNOWN
    assert "not evidence of enforcement" in told["reading"]
    assert "Missing:" in told["reading"]


def test_an_inconclusive_experiment_stays_open_and_is_re_proposed(memory):
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    memory.record_experiment(proposal.as_experiment(INCONCLUSIVE))
    again = investigate(captured(), available_principals=PRINCIPALS, memory=memory)
    assert len(again["proposals"]) == 1
    assert "previous attempt was inconclusive" in again["proposals"][0].why


def test_every_attempt_is_retained_not_overwritten(memory):
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    memory.record_experiment(proposal.as_experiment(INCONCLUSIVE))
    memory.record_experiment(proposal.as_experiment(SUPPORTED))
    record = memory.already_tried(proposal.as_experiment(INCONCLUSIVE))
    assert record["attempt_count"] == 2
    assert [a["outcome"] for a in record["attempts"]] == [INCONCLUSIVE, SUPPORTED]
    assert record["settled"] is True


def test_a_settled_experiment_can_still_be_retried_on_request(memory):
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    memory.record_experiment(proposal.as_experiment(SUPPORTED))
    assert investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"] == []
    forced = investigate(captured(), available_principals=PRINCIPALS, memory=memory,
                         retry_settled=True)
    assert len(forced["proposals"]) == 1


def test_a_sealed_object_is_not_confirmed_by_another_objects_finding(base_url, memory):
    """Evidence attribution: the collection is vulnerable, but the SELECTED object is not.

    Running the collection differential reports a crossing for 1001. Recording that as the
    outcome for 1009 would attribute another object's finding to the object the pentester chose.
    """
    request = CapturedRequest(method="GET", path="/authz/vuln/orders/1009", principal="user-a")
    proposal = investigate(request, available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    assert proposal.identifier == "1009"

    result = execute(base_url, proposal, "vuln")
    outcome, why = outcome_from_result(proposal, result)
    assert outcome != SUPPORTED
    assert "1009" in why

    memory.record_experiment(proposal.as_experiment(outcome))
    conclusion = memory.route_conclusion(proposal.method, proposal.route_template)
    assert conclusion["weakness_demonstrated"] is False


def test_the_selected_object_is_confirmed_by_its_own_evidence(base_url, memory):
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    outcome, why = outcome_from_result(proposal, execute(base_url, proposal, "vuln"))
    assert outcome == SUPPORTED
    assert "evidence names object 1001" in why


def test_the_patched_twin_is_refuted_by_evidence_not_by_an_absent_flag(base_url, memory):
    proposal = investigate(captured("safe"), available_principals=PRINCIPALS,
                           memory=memory)["proposals"][0]
    outcome, why = outcome_from_result(proposal, execute(base_url, proposal, "safe"))
    assert outcome == REFUTED
    assert "no cross-principal evidence" in why


@pytest.mark.parametrize("result", [
    {"replays_completed": 1, "findings": []},
    {"findings": [{"evidence": ["malformed"]}]},
    {"endpoint_attempts": [{"requested_object_id": "2002", "status": "completed"}]},
])
def test_aggregate_completion_and_unrelated_or_malformed_evidence_are_inconclusive(memory, result):
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    assert outcome_from_result(proposal, result)[0] == INCONCLUSIVE


@pytest.mark.parametrize("field,value", [
    ("method", "POST"), ("producer_endpoint", "GET /invoices"),
    ("consumer_endpoint", "GET /authz/vuln/orders/2002"),
])
def test_same_object_id_in_a_different_request_cannot_support_proposal(memory, field, value):
    proposal = investigate(captured(), available_principals=PRINCIPALS, memory=memory)["proposals"][0]
    evidence = {
        "proof_type": "cross_principal_replay", "requested_object_id": "1001",
        "method": "GET", "producer_endpoint": "GET /authz/vuln/orders",
        "consumer_endpoint": "GET /authz/vuln/orders/1001", field: value,
    }
    assert outcome_from_result(proposal, {"findings": [{"evidence": evidence}]})[0] == INCONCLUSIVE
