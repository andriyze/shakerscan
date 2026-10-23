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


SAFETY_LIMITS = {"max_state_changing_requests", "max_tcp_ports", "max_hosts", "max_udp_ports",
                 "max_oob_interactions", "max_device_fragility_points"}


def test_default_starts_need_no_raise_for_the_standard_web_workflow():
    """Logging in, mapping a web app and verifying what it finds fits every profile's defaults."""
    from api.hunt.start_guidance import STANDARD_WEB_WORKFLOW
    for profile in HUNT_BUDGET_PROFILES:
        for kind in ("web", "api"):
            started = {**_started({}, profile=profile, kind=kind), "capabilities": _manifest(*STANDARD_WEB_WORKFLOW)}
            assert start_budget_warnings(started) == [], (profile, kind)


def test_default_warnings_name_only_safety_ceilings():
    """At a profile's defaults a warning can only be a safety ceiling (ports, hosts, writes,
    out-of-band, device wear) that a person decides to raise, never a traffic or call budget."""
    for profile in HUNT_BUDGET_PROFILES:
        for kind in ("web", "network", "device"):
            started = {**_started({}, profile=profile, kind=kind), "capabilities": _every_capability(kind)}
            for warning in start_budget_warnings(started):
                assert warning["limit"] in SAFETY_LIMITS, (profile, kind, warning)
                assert warning["restart_fixes_it"] is False


def test_device_verifications_reach_a_safety_ceiling_before_their_http_hold():
    """A device verification queues a scan whose fan-out holds thousands of requests; the port
    ceiling, not HTTP, must be what limits how many a profile can run."""
    from api import device_agent
    from api.hunt import interaction_router
    for contract in sorted(interaction_router._DEVICE_VERIFICATION_WEB_CONTRACTS):
        fanout = device_agent.device_verification_fanout_budget(
            contract_id=contract, web_scan_type=interaction_router._DEVICE_VERIFICATION_WEB_SCAN_TYPE,
            max_web_origins=interaction_router._DEVICE_VERIFICATION_MAX_WEB_ORIGINS)
        for name, profile in HUNT_BUDGET_PROFILES.items():
            allowed = profile.max_tcp_ports // fanout["tcp_ports_attempted"]
            assert profile.max_http_requests >= allowed * fanout["http_requests"], (contract, name)


def test_a_manifest_capability_the_registry_does_not_know_is_costed_from_its_manifest():
    started = _started({"max_http_requests": 100})
    started["capabilities"] = [*started["capabilities"],
                               {"name": "custom.unregistered", "budget_cost": {"http_requests": 500}}]
    warnings = start_budget_warnings(started)
    assert any(item.get("capability") == "custom.unregistered" and item["reserves"] == 500 for item in warnings)


def test_a_replay_is_costed_by_the_least_it_can_reserve():
    """A collection replay holds what it selects (one to 25 requests), not the registry's 2,000."""
    warnings = start_budget_warnings(_started({}, "collections.replay_active", "collections.replay_safe",
                                              profile="fast"))
    assert warnings == []


def test_verifier_warnings_use_the_execution_hold_instead_of_the_registry_floor():
    warnings = start_budget_warnings(_started({'max_duration_seconds': 400}, 'sqli.verify'))
    assert warnings[0]['reserves'] == 540


def test_every_profile_funds_mapping_then_both_full_verifiers():
    from api import agent_tools
    for name, profile in HUNT_BUDGET_PROFILES.items():
        holds = [agent_tools.canonical_hunt_scanner_budget(capability, budget_profile=name)
                 for capability in ('web.crawl', 'web.content_discover', 'sqli.verify', 'xss.verify')]
        assert sum(hold.get('http_requests', 0) for hold in holds) <= profile.max_http_requests
        assert sum(hold.get('tool_wall_seconds', 0) for hold in holds) <= profile.max_duration_seconds
        # Approval-gated calls may use the whole call allowance; each one still checks its receipt.
        assert profile.max_active_actions == profile.max_capability_calls


def test_a_lowered_limit_names_the_start_maximum_when_a_restart_cannot_fix_it():
    started = {**_started({"max_tcp_ports": 50}, profile="fast"), "capabilities": _every_capability()}
    warnings = {item["capability"]: item for item in start_budget_warnings(started)
                if item["limit"] == "max_tcp_ports"}
    ports = warnings["ports.discover"]
    assert ports["restart_fixes_it"] is False and ports["start_maximum"] == 100
    assert "Start again without lowering it" not in ports["message"]
    assert "start maximum, 100, is below that" in ports["message"]
    fits = [item for item in warnings.values() if item["restart_fixes_it"]]
    assert fits and all("Start again without lowering it" in item["message"] for item in fits)
