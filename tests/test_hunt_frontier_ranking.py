"""The Hunt lead frontier is ordered by the deterministic scheduler, fed only from server records."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from api.hunt.hunt_hypotheses import _remaining_requests, rank_frontier

OWNER = "hunt:11111111-1111-1111-1111-111111111111"
NOW = datetime.now(timezone.utc)


def _row(*, family="bola", severity="high", route="/api/orders/{id}", claim_owner=None, tests=None,
         request_cost=None, confidence=0.5, status="open", **metadata):
    lead_id = str(uuid4())
    return {"id": lead_id, "family": family, "title": f"{family} at {route}", "status": status, "version": 1,
            "confidence": confidence, "severity_guess": severity, "source": "ai_planner",
            "dedupe_key": f"hypothesis:v1|family={family}|route={route}|{lead_id}",
            "metadata_json": {"dedupe_dimensions": {"route": route}, "tests": tests or {}, **metadata},
            "endorsements": [], "next_test_action": {"request_cost": request_cost} if request_cost else {},
            "claim_owner": claim_owner,
            "claim_lease_expires_at": NOW + timedelta(minutes=10) if claim_owner else None,
            "updated_at": NOW}


def _order(rows, **context):
    ranked = rank_frontier(rows, owner=OWNER, **{"auth_available": True, **context})
    return [lead["id"] for lead in ranked["hypotheses"]], ranked


def test_impact_and_boundary_order_claimable_leads():
    weak = _row(family="info_disclosure", severity="low", route="/robots.txt", confidence=0.1)
    strong = _row(family="bola", severity="high")
    order, ranked = _order([weak, strong])
    assert order == [strong["id"], weak["id"]]
    first = ranked["hypotheses"][0]
    assert first["priority"] > ranked["hypotheses"][1]["priority"]
    assert set(first["priority_breakdown"]) >= {"impact", "boundary_value", "novelty", "reachability"}


def test_the_lead_this_hunt_holds_comes_first_and_another_holders_last():
    mine = _row(family="info_disclosure", severity="low", claim_owner=OWNER, route="/a")
    open_lead = _row(family="bola", severity="critical", route="/b")
    theirs = _row(family="bola", severity="critical", route="/c", claim_owner="hunt:someone-else")
    order, ranked = _order([theirs, open_lead, mine])
    assert order == [mine["id"], open_lead["id"], theirs["id"]]
    assert ranked["hypotheses"][-1]["claimable"] is False


def test_coverage_settled_negative_removes_novelty_for_the_same_family_and_route():
    covered = _row(route="/api/orders/{id}/")
    fresh = _row(route="/api/carts/{id}")
    order, ranked = _order([covered, fresh], negative_pairs=frozenset({("bola", "/api/orders/{id}")}))
    assert order == [fresh["id"], covered["id"]]
    by_id = {lead["id"]: lead for lead in ranked["hypotheses"]}
    assert by_id[covered["id"]]["priority_breakdown"]["novelty"] == 0.0
    assert by_id[fresh["id"]]["priority_breakdown"]["novelty"] == 2.0
    assert ranked["ranking"]["novelty_settled"] == 1
    # Another family settled at that route says nothing about this lead.
    _, other = _order([covered], negative_pairs=frozenset({("sqli", "/api/orders/{id}")}))
    assert other["hypotheses"][0]["priority_breakdown"]["novelty"] == 2.0


def test_tests_that_found_no_signal_count_as_prior_failures():
    # The count each holder kept, whatever its latest move was.
    tried = _row(route="/a", tests={"hunt:x": {"reason_code": "testing_started", "no_signal_count": 1},
                                    "hunt:y": {"reason_code": "expected_signal_absent", "no_signal_count": 1},
                                    "hunt:z": {"reason_code": "testing_started", "no_signal_count": 0}})
    untried = _row(route="/b")
    order, ranked = _order([tried, untried])
    assert order == [untried["id"], tried["id"]]
    assert ranked["hypotheses"][1]["priority_breakdown"]["prior_failures"] == 2.0


def test_an_authorization_lead_without_an_active_session_is_not_reachable():
    bola = _row(family="bola", severity="high", route="/a")
    xss = _row(family="xss", severity="high", route="/b")
    order, ranked = _order([bola, xss], auth_available=False)
    assert order == [xss["id"], bola["id"]]
    assert ranked["hypotheses"][1]["priority_breakdown"]["reachability"] == 0.0
    assert ranked["ranking"]["auth_available"] is False


def test_a_lead_costlier_than_the_remaining_requests_is_deferred_after_claimable_ones():
    costly = _row(family="bola", severity="critical", route="/a", request_cost=4)
    cheap = _row(family="xss", severity="low", route="/b")
    order, ranked = _order([costly, cheap], remaining_requests=2)
    assert order == [cheap["id"], costly["id"]]
    assert ranked["hypotheses"][1]["deferred_reason"] == "insufficient_request_budget"
    assert ranked["ranking"]["counts"]["deferred"] == 1


def test_nothing_stored_on_a_lead_can_nudge_the_order():
    nudged = _row(family="info_disclosure", severity="low", route="/a", hint_delta=999)
    plain = _row(family="bola", severity="high", route="/b")
    order, ranked = _order([nudged, plain])
    assert order == [plain["id"], nudged["id"]]
    assert all(lead["priority_breakdown"]["hint_delta"] == 0.0 for lead in ranked["hypotheses"])


def test_remaining_requests_reads_the_hunts_real_budget_shape():
    run = {"budget_json": '{"max_http_requests": 500, "max_capability_calls": 90}',
           "budget_used_json": {"http_requests": 120, "agent_actions": 7}}
    assert _remaining_requests(run) == 380
    assert _remaining_requests({**run, "budget_used_json": {"http_requests": 900}}) == 0
    # No request ceiling recorded means no deferral, not a zero budget.
    assert _remaining_requests({"budget_json": {}, "budget_used_json": {}}) is None
