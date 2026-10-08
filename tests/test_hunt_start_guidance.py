"""What a Hunt start tells its planner before it spends anything.

Agents starve themselves: in the 2026-10-08 OpenCode runs luna set its own ``max_http_requests``
to 300, then 180, below one content discovery's reservation, skipped content discovery and
missed every exposed file, while reporting that no budget had stopped useful work. A chosen
limit is never refused or raised, but the start response now names what it rules out
(``budget_warnings``) and which families candidate.verify can prove (``verification``, D27).
"""
from __future__ import annotations

import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.hunt import run_router
from api.hunt.candidate_verification_preflight import VERIFIABLE_FAMILIES
from api.hunt.start_contract import HUNT_BUDGET_PROFILES, hunt_start_public_contract
from api.hunt.start_guidance import start_budget_warnings, with_start_guidance
from api.runtime.capability_registry import CAPABILITY_REGISTRY


def _manifest(*names):
    return [CAPABILITY_REGISTRY.require(name).planner_contract() for name in names]


def _started(budget, *names, profile="balanced", kind="web"):
    resolved = {**HUNT_BUDGET_PROFILES[profile].__dict__, **budget}
    return {"hunt_id": "h-1", "target_kind": kind, "budget_profile": profile, "budget": resolved,
            "capabilities": _manifest(*(names or ("web.crawl", "web.content_discover", "http.request")))}


def test_an_http_limit_below_content_discovery_is_named_with_the_profile_default():
    warnings = start_budget_warnings(_started({"max_http_requests": 180}))
    codes = {(item["code"], item.get("capability")) for item in warnings}
    assert ("budget_below_capability_reservation", "web.content_discover") in codes
    assert ("budget_below_mapping_minimum", None) in codes
    discovery = next(item for item in warnings if item.get("capability") == "web.content_discover")
    assert discovery["value"] == 180 and discovery["reserves"] == 220
    assert discovery["profile_default"] == HUNT_BUDGET_PROFILES["balanced"].max_http_requests
    assert "can never run in this Hunt" in discovery["message"]


def test_a_limit_that_fits_each_capability_but_not_mapping_still_warns():
    warnings = start_budget_warnings(_started({"max_http_requests": 300}))
    assert [item["code"] for item in warnings] == ["budget_below_mapping_minimum"]
    assert warnings[0]["needed"] == 370 and "/.env" in warnings[0]["message"]


def test_the_profile_defaults_and_a_policy_zeroed_dimension_do_not_warn():
    for profile in HUNT_BUDGET_PROFILES:
        assert start_budget_warnings(_started({}, profile=profile)) == [], profile
    # A dimension the policy turned off is authority, not a lowered budget.
    assert start_budget_warnings(_started({"max_state_changing_requests": 0}, "http.request")) == []


def test_a_duration_below_a_verification_reservation_is_named():
    warnings = start_budget_warnings(_started({"max_duration_seconds": 120}, "candidate.verify"))
    assert [(item["limit"], item["capability"]) for item in warnings] == [("max_duration_seconds", "candidate.verify")]


def test_the_start_response_and_the_contract_name_the_verifiable_families():
    guided = with_start_guidance(_started({}))
    assert guided["verification"]["verifiable_families"] == sorted(VERIFIABLE_FAMILIES)
    assert guided["verification"]["family_aliases"]["idor"] == "bola"
    assert "do not call candidate.verify" in guided["verification"]["other_families"]
    assert "verification" not in with_start_guidance(_started({}, kind="device")), (
        "device Hunts verify through their own contracts"
    )
    contract = hunt_start_public_contract()["candidates"]["verification"]
    assert contract == guided["verification"]


def test_the_start_route_returns_the_guidance(monkeypatch):
    saved = {name: getattr(run_router, name) for name in (
        "_service_provider", "_start_handler", "_metrics_provider",
        "_standing_authorization_resolver", "_target_scope_refusal_resolver",
    )}

    async def start(contract):
        return _started({"max_http_requests": 180})

    try:
        run_router.configure_hunt_run_router(lambda: None, start_handler=start)
        app = FastAPI()
        app.include_router(run_router.router)
        response = TestClient(app).post("/hunts", json={
            "schema_version": "hunt-start/v2", "target_id": str(uuid.uuid4()), "target_kind": "web",
            "goal": "map", "budget_profile": "balanced", "budgets": {"max_http_requests": 180}, "policy": {},
        })
    finally:
        for name, value in saved.items():
            setattr(run_router, name, value)
    assert response.status_code == 200, response.text
    body = response.json()
    assert {item["code"] for item in body["budget_warnings"]} >= {"budget_below_mapping_minimum"}
    assert body["verification"]["verifiable_families"] == sorted(VERIFIABLE_FAMILIES)


def _every_capability(kind="web"):
    return [spec.planner_contract() for spec in CAPABILITY_REGISTRY.list()
            if spec.planner_visible and spec.hunt_executor is not None and kind in spec.target_kinds]


def test_a_start_at_the_profile_defaults_warns_about_nothing_whatever_the_manifest():
    """D49: every start warned that collections.replay_active reserves 2000 state-changing requests
    (balanced allows 20) and fast's browser crawl, sqli.verify and templates.scan exceed fast's
    maxima: limits no allowed start setting can meet. Those calls ask for a budget raise instead."""
    for profile in HUNT_BUDGET_PROFILES:
        started = {**_started({}, profile=profile), "capabilities": _every_capability()}
        assert start_budget_warnings(started) == [], profile


def test_a_lowered_limit_names_the_start_maximum_when_a_restart_cannot_fix_it():
    started = {**_started({"max_state_changing_requests": 5}), "capabilities": _every_capability()}
    warnings = {item["capability"]: item for item in start_budget_warnings(started)
                if item["limit"] == "max_state_changing_requests"}
    replay = warnings["collections.replay_active"]
    assert replay["restart_fixes_it"] is False and replay["start_maximum"] == 20
    assert "Start again without lowering it" not in replay["message"]
    assert "start maximum, 20, is below that" in replay["message"]
    fits = [item for item in warnings.values() if item["restart_fixes_it"]]
    assert all("Start again without lowering it" in item["message"] for item in fits)
