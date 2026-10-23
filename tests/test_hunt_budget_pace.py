"""No Hunt budget but the duration runs out first, checked with real settlement and the real ledger.

Each shape is the densest charge a valid call can settle: admission's hold, then what the adapter
or settlement helper that settles it in production returns for a call that answers at once. Each
call is admitted through ``reserve_budget_snapshot`` with its whole hold, as admission does, and
charged its settlement. On every profile the call the ledger first refuses must be refused for the
duration (``tool_wall_seconds``): calls, approval-gated calls, HTTP requests, browser actions and
verifications must all still have room. Every target response here is a labelled unit fixture
(an operation that returns at once); nothing is sent.

The expected paces are independent literals (one call per second of settled wall, a login check's
32 browser actions and 128 requests over that second), so a change that lowers the derived pace in
``budget_pace`` fails here even when the profiles still match what it derives.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from fractions import Fraction
import os
import sys
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from capabilities.browser import BrowserInteractAdapter, _browser_result
from capabilities.inline import ControlPlaneExecutionAdapter, HttpRequestExecutionAdapter
from fastapi import HTTPException
from http_experiment import MAX_REDIRECT_HOPS
from hunt import budget_pace
from hunt.budget_pace import PACED_DIMENSIONS, paced_minimum, spend_pace, wire_requests_per_second
from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from hunt.start_contract import HUNT_BUDGET_PROFILES, hunt_ledger_limits
from hunt.verification_budget import web_candidate_budget
from runtime.budgets import BudgetExceeded, reserve_budget_snapshot
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import TargetBinding
from runtime.request_replay_executor import _settled_budget

TARGET = TargetBinding(
    target_id="target-1", target_kind="web", canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",), allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("example.test",), scope_receipt_id="scope-1",
)
# Every call that runs may also be approval-gated: charge both call ledgers.
CALL = {"agent_actions": 1, "active_actions": 1}


def _executed(name, adapter, requested):
    """Settle one call through the production executor, which also settles its call charge."""
    result = asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(specification=CAPABILITY_REGISTRY.require(name), target=TARGET,
                                   requested_budget=requested),
        adapter, heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False,
    ))
    assert result.status == "success", result
    return dict(result.actual_budget)


def _http_request(hops):
    spec = CAPABILITY_REGISTRY.require("http.request")
    hold = {**spec.budget_cost, **CALL, "http_requests": 1 + hops}

    async def answered_at_once():  # unit fixture: the target answers instantly
        return {"ok": True, "request": {"method": "GET", "path": "/"}, "hops_followed": hops,
                "response": {"status": 200, "body_sha256": "a" * 64}}

    adapter = HttpRequestExecutionAdapter(specification=spec, operation=answered_at_once,
                                          requested_budget=hold, redacted_execution={})
    return hold, _executed("http.request", adapter, hold)


def _candidate_verify():
    spec = CAPABILITY_REGISTRY.require("candidate.verify")
    # A read-only family: a mutating one also holds state-changing requests, a safety ceiling.
    hold = {**spec.budget_cost, **CALL, **{key: value for key, value in web_candidate_budget("bola").items() if value}}

    async def verdict_at_once():  # unit fixture: the verifier returns at once
        return {"ok": True, "status": "success"}

    adapter = ControlPlaneExecutionAdapter(
        specification=spec, operation=verdict_at_once, requested_budget=hold, redacted_execution={},
        blocked_exceptions=(HTTPException,), conservative_full_budget=True, measured_wall=True,
    )
    return hold, _executed("candidate.verify", adapter, hold)


def _browser_interact():
    args = {"steps": [{"action": "click", "selector": f"#tab-{index}"} for index in range(8)],
            "timeout_ms": 1_000, "max_requests": 50}
    CAPABILITY_REGISTRY.validate_hunt_input("browser.interact", dict(args))
    prepared = BrowserInteractAdapter.prepare(target=TARGET, base_url="https://app.example.test", args=args)
    settled = _browser_result(prepared, status="success", request_count=prepared.max_requests,
                              browser_actions=prepared.estimated_budget["browser_actions"],
                              started=time.monotonic() - 0.001, observations=[], blocked=[], errors=())
    return {**prepared.estimated_budget, **CALL}, {**settled.actual_budget, **CALL}


def _login_check():
    # Once the browser is entered the adapter charges its whole 32 browser actions and the
    # attempts it admitted (at most the 128 held); a check that fails before its login POST sends
    # no state-changing request. Settled in one second.
    hold = {**CAPABILITY_REGISTRY.require("browser.login_check").budget_cost, **CALL}
    return hold, {"browser_actions": hold["browser_actions"], "http_requests": hold["http_requests"],
                  "state_changing_requests": 0, "tool_wall_seconds": 1, **CALL}


def _replay():
    plan = SimpleNamespace(requests=[SimpleNamespace(method="GET")] * 25,  # unit fixture plan
                           estimated_budget={"http_requests": 25})
    hold = {"http_requests": 25, "tool_wall_seconds": 60, **CALL}
    started = datetime(2026, 10, 23, tzinfo=timezone.utc)
    settled = _settled_budget(plan, 25, requested=hold, started_at=started,
                              finished_at=started + timedelta(milliseconds=1))
    return hold, settled


SHAPES = {
    "http.request": lambda: _http_request(0),
    "http.request following redirects": lambda: _http_request(MAX_REDIRECT_HOPS),
    "candidate.verify": _candidate_verify,
    "browser.interact, eight steps": _browser_interact,
    "browser.login_check": _login_check,
    "collections.replay_safe": _replay,
}
VERIFYING = {"candidate.verify"}


def test_every_call_that_runs_settles_at_least_one_second_of_the_duration():
    assert budget_pace.SETTLED_WALL_FLOOR_SECONDS == 1
    for name, shape in SHAPES.items():
        _hold, settled = shape()
        assert settled["tool_wall_seconds"] == 1, (name, settled)


@pytest.mark.parametrize("shape", sorted(SHAPES))
@pytest.mark.parametrize("profile", sorted(HUNT_BUDGET_PROFILES))
def test_a_loop_of_the_densest_calls_is_stopped_by_the_duration_and_nothing_else(profile, shape):
    budget = HUNT_BUDGET_PROFILES[profile]
    limits = hunt_ledger_limits(asdict(budget))
    hold, settled = SHAPES[shape]()
    # The last call the duration admits needs its whole wall hold free.
    calls = (budget.max_duration_seconds - hold["tool_wall_seconds"]) // settled["tool_wall_seconds"] + 1
    before_last = {key: (calls - 1) * value for key, value in settled.items()}
    reserve_budget_snapshot(limits, before_last, hold)  # admitted: every ledger has room
    after_last = {key: calls * value for key, value in settled.items()}
    with pytest.raises(BudgetExceeded) as refused:
        reserve_budget_snapshot(limits, after_last, hold)
    # The clock refuses it. A one-second hold can use the last second, so calls may run out with it
    # (never before it: every earlier call was admitted).
    assert "tool_wall_seconds" in refused.value.shortages, (profile, shape, refused.value.shortages)
    assert set(refused.value.shortages) <= {"tool_wall_seconds", "agent_actions", "active_actions"}
    if shape in VERIFYING:
        assert calls <= budget.max_verifications, (profile, calls)


def test_the_derived_pace_is_at_least_what_a_real_call_settles_per_second():
    """Literal paces, independent of budget_pace: one call and one verification per settled second,
    a login check's 32 browser actions and 128 requests in that second."""
    expected = {"agent_actions": 1, "active_actions": 1, "verifications": 1, "browser_actions": 32,
                "http_requests": 128}
    assert set(expected) == set(PACED_DIMENSIONS)
    for name in HUNT_BUDGET_PROFILES:
        for kind in ("web", "api", "network", "device"):
            pace = spend_pace(name, kind)
            assert pace == {key: Fraction(value) for key, value in expected.items()}, (name, kind, pace)
            for shape in SHAPES.values():
                _hold, settled = shape()
                for dimension in ("http_requests", "browser_actions", "agent_actions", "active_actions"):
                    assert pace[dimension] >= Fraction(settled.get(dimension, 0), settled["tool_wall_seconds"])
    assert wire_requests_per_second() == 10


def test_each_profile_covers_its_duration_at_the_derived_pace():
    limit_of = {"http_requests": "max_http_requests", "browser_actions": "max_browser_actions",
                "agent_actions": "max_capability_calls", "active_actions": "max_active_actions",
                "verifications": "max_verifications"}
    for name, profile in HUNT_BUDGET_PROFILES.items():
        for kind in ("web", "api", "network", "device"):
            for dimension, needed in paced_minimum(asdict(profile), name, kind).items():
                assert getattr(profile, limit_of[dimension]) >= needed, (name, kind, dimension, needed)
        duration = profile.max_duration_seconds
        assert profile.max_capability_calls >= duration and profile.max_active_actions >= duration
        assert profile.max_verifications >= duration
        assert profile.max_browser_actions >= 32 * duration and profile.max_http_requests >= 128 * duration
        # Recording costs no traffic and no wall: at least one record per call a Hunt can make.
        assert profile.max_candidates >= profile.max_capability_calls


def test_a_network_candidate_verification_counts_its_http_envelope():
    """Admission adds the verifier's HTTP envelope on a network target too: its candidate is
    verified on the HTTP service it names, so the pace counts those requests there as well."""
    envelope = web_candidate_budget("bola")["http_requests"]
    for kind in ("web", "api", "network"):
        ceiling = budget_pace.call_ceiling("candidate.verify", profile="fast", target_kind=kind)
        assert ceiling["http_requests"] == envelope, kind
    assert "http_requests" not in budget_pace.call_ceiling("candidate.verify", profile="fast", target_kind="device")
