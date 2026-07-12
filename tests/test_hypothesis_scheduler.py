"""Unit tests for the pure hypothesis scheduler (api/hypothesis_scheduler.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import hypothesis_scheduler as sched  # noqa: E402


def _h(**kw):
    base = {"id": kw.get("id", "x"), "family": "bola", "severity_guess": "high",
            "confidence": 0.5, "dedupe_key": kw.get("id", "x"), "status": "open", "metadata_json": {}}
    base.update(kw)
    return base


def test_self_test():
    sched._self_test()


def test_authenticated_high_impact_outranks_generic_low():
    hi = _h(id="a", family="bola", severity_guess="high", metadata_json={"authenticated": True})
    lo = _h(id="b", family="info_disclosure", severity_guess="low", confidence=0.1, metadata_json={})
    hi_score = sched.score_hypothesis(hi, context={"auth_available": True})["priority"]
    lo_score = sched.score_hypothesis(lo, context={})["priority"]
    assert hi_score > lo_score


def test_terminal_excluded():
    for st in ("refuted", "promoted", "dead"):
        assert sched.score_hypothesis(_h(status=st), context={})["excluded"] is True


def test_blocked_and_exhausted_excluded():
    for st in ("blocked", "exhausted"):
        assert sched.score_hypothesis(_h(status=st), context={})["excluded"] is True


def test_needs_auth_without_auth_penalized():
    h = _h(id="a", family="bola")
    with_auth = sched.score_hypothesis(h, context={"auth_available": True})
    without = sched.score_hypothesis(h, context={"auth_available": False})
    assert without["breakdown"]["reachability"] == 0.0
    assert without["breakdown"]["blocker_penalty"] == 2.0
    assert without["priority"] < with_auth["priority"]


def test_novelty_drops_when_dimension_completed():
    h = _h(id="a", dedupe_key="d1")
    fresh = sched.score_hypothesis(h, context={"auth_available": True})
    seen = sched.score_hypothesis(h, context={"auth_available": True, "completed_dimensions": ["d1"]})
    assert fresh["breakdown"]["novelty"] == 2.0
    assert seen["breakdown"]["novelty"] == 0.0
    assert seen["priority"] < fresh["priority"]


def test_hint_delta_is_clamped():
    h = _h(id="a")
    assert sched.score_hypothesis(h, context={"hint_delta": 999})["breakdown"]["hint_delta"] == sched.MAX_HINT_DELTA
    assert sched.score_hypothesis(h, context={"hint_delta": -999})["breakdown"]["hint_delta"] == -sched.MAX_HINT_DELTA


def test_rank_orders_and_excludes():
    hi = _h(id="a", family="bola", severity_guess="critical", metadata_json={"authenticated": True})
    lo = _h(id="b", family="info_disclosure", severity_guess="low", confidence=0.1)
    dead = _h(id="c", status="dead")
    ranked = sched.rank_hypotheses([lo, hi, dead], context={"auth_available": True})
    assert [s["hypothesis_id"] for s in ranked["scheduled"]] == ["a", "b"]
    assert ranked["counts"]["excluded"] == 1


def test_cost_aware_deferral():
    costly = _h(id="e", next_test_action={"request_cost": 4})
    r = sched.rank_hypotheses([costly], context={"remaining_requests": 2, "auth_available": True})
    assert r["counts"]["deferred"] == 1
    assert r["counts"]["scheduled"] == 0


def test_autonomous_schedule_requires_dast_residue_or_graph_source():
    generic = _h(id="generic", source="manual")
    graph = _h(id="graph", source="app_graph")
    ranked = sched.rank_hypotheses(
        [generic, graph], context={"auth_available": True, "require_residue": True}
    )
    assert [item["hypothesis_id"] for item in ranked["scheduled"]] == ["graph"]
    assert ranked["excluded"][0]["exclude_reason"] == "not_backed_by_dast_residue_or_graph"


def test_breakdown_is_explainable():
    s = sched.score_hypothesis(_h(id="a"), context={"auth_available": True})
    for key in ("impact", "boundary_value", "novelty", "evidence_strength", "reachability",
                "request_cost", "prior_failures", "blocker_penalty", "hint_delta"):
        assert key in s["breakdown"]
