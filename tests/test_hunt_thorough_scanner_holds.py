"""A thorough Hunt's sqli.verify and xss.verify calls get a wall they can finish in.

Measured on lab Hunts: 2 of 2 sqli.verify calls timed out at 300.06 s and 300.08 s after 272 and
295 requests, and 2 of 2 Juice Shop xss.verify calls timed out at 120 s after 400 requests. The
argv paces sqlmap at about 1 request/s and Dalfox at about 3.3 requests/s on every Hunt profile,
so a one-field sqlmap negative (about 432 requests) and one Dalfox parameter (about 1,300
requests) cannot finish inside the registry wall. Every profile reserved the same hold.

A thorough Hunt now reserves 900 requests / 540 s for sqli.verify and 1,800 requests / 480 s for
xss.verify, with the same argv. Fast and balanced Hunts, the passive templates.scan pack and
headless (deep_domxss) xss.verify keep their 2.11.0 holds, plans and waits byte for byte.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
import uuid

import pytest

from api.hunt import interaction_router as router
from api.hunt.capability_reservations import hunt_capability_lease_seconds
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from tests.test_hunt_authz_verification_limit import (
    HUNT, AdmissionStore, Lifecycle, Reservation, admission,
)

agent_tools = router.agent_tools

SQLMAP_OUTPUT = {"sqlmap_output_dir": "/tmp/shakerscan-sqlmap-fixture"}
DALFOX_SCRATCH = {"scratch_dir": "/tmp/shakerscan-dalfox-fixture"}
REGISTRY_SQLI = {"http_requests": 900, "tool_wall_seconds": 300}
REGISTRY_XSS = {"http_requests": 400, "tool_wall_seconds": 120, "browser_actions": 2}
THOROUGH_SQLI = {"http_requests": 900, "tool_wall_seconds": 540}
THOROUGH_XSS = {"http_requests": 1_800, "tool_wall_seconds": 480, "browser_actions": 2}
# Fixture: the process plan digests that build_enforced_scanner_plan produced at 2.11.0
# (81caee26d) for the registry holds below. A changed digest means a changed argv, wall,
# ceiling or proof for the fast and balanced Hunt profiles.
PLAN_DIGESTS_2_11_0 = {
    "sqli.verify": "de9f3bed040e980c17feaa847d19a9baf940411ce5d2587bbd9f7438fb6b3ba8",
    "xss.verify": "fa1d2958c59e42e66f3dfac467bf3d67d94d4e6aba4c38ae63c78e4628291f83",
    "xss.verify:deep_domxss": (
        "12946aeb1d41159d1285fbb55a1901884b790a67bd64fd20272c15f615b07869"
    ),
}
# Lab measurements behind the thorough holds (2.10.0 Hunt evals; no relevant change in 2.11).
MEASURED_SQLMAP_REQUESTS_PER_SECOND = 0.98
MEASURED_DALFOX_REQUESTS_PER_SECOND = 3.33


def _plan(capability, planner_input, reservation):
    tool = "sqlmap" if capability == "sqli.verify" else "dalfox"
    options = agent_tools.canonical_hunt_scanner_options(capability, planner_input)
    return agent_tools.build_enforced_scanner_plan(
        tool,
        "http://app.example.test:8080" + planner_input["path"],
        dict(options),
        reserved_budget=reservation,
        pinned_address="192.0.2.10",
        pinned_proxy_url="socks5://127.0.0.1:41000",
        runtime_paths=SQLMAP_OUTPUT if tool == "sqlmap" else DALFOX_SCRATCH,
    )


def _flag(plan, name):
    return plan.argv[plan.argv.index(name) + 1]


# --- the per-call holds -----------------------------------------------------------------------


def test_a_thorough_hunt_reserves_the_reviewed_per_call_holds():
    assert agent_tools.canonical_hunt_scanner_budget(
        "sqli.verify", budget_profile="thorough",
    ) == THOROUGH_SQLI
    assert agent_tools.canonical_hunt_scanner_budget(
        "xss.verify", budget_profile="thorough",
    ) == THOROUGH_XSS
    # Headless Dalfox runs unpaced with 10 workers, so it keeps the registry hold.
    assert agent_tools.canonical_hunt_scanner_budget(
        "xss.verify", budget_profile="thorough", deep_domxss=True,
    ) == REGISTRY_XSS


@pytest.mark.parametrize("profile", [None, "fast", "balanced"])
def test_fast_balanced_and_unprofiled_hunts_keep_every_registry_hold(profile):
    for spec in CAPABILITY_REGISTRY.for_hunt_executor("worker_scanner"):
        expected = dict(spec.budget_cost)
        if spec.name == "templates.scan":
            expected["http_requests"] = 7
        for deep in (False, True):
            assert agent_tools.canonical_hunt_scanner_budget(
                spec.name, budget_profile=profile, deep_domxss=deep,
            ) == expected, spec.name
    assert agent_tools.canonical_hunt_scanner_budget("sqli.verify") == REGISTRY_SQLI


def test_only_the_two_verifiers_change_on_thorough():
    for spec in CAPABILITY_REGISTRY.for_hunt_executor("worker_scanner"):
        if spec.name in {"sqli.verify", "xss.verify"}:
            continue
        assert agent_tools.canonical_hunt_scanner_budget(
            spec.name, budget_profile="thorough",
        ) == agent_tools.canonical_hunt_scanner_budget(spec.name), spec.name
    # The passive pack stays the reviewed seven-request GET-only allowlist.
    assert agent_tools.canonical_hunt_scanner_budget(
        "templates.scan", budget_profile="thorough",
    )["http_requests"] == 7


# --- the process plans ------------------------------------------------------------------------


@pytest.mark.parametrize("key,planner_input,reservation", [
    ("sqli.verify", {"path": "/item?id=1"}, REGISTRY_SQLI),
    ("xss.verify", {"path": "/search?q=1"}, REGISTRY_XSS),
    ("xss.verify:deep_domxss", {"path": "/search?q=1", "deep_domxss": True}, REGISTRY_XSS),
])
def test_registry_hold_plans_are_byte_identical_to_2_11_0(key, planner_input, reservation):
    plan = _plan(key.split(":", 1)[0], planner_input, reservation)
    assert plan.digest == PLAN_DIGESTS_2_11_0[key]


def test_a_thorough_sqlmap_call_keeps_its_argv_and_gets_the_longer_wall():
    registry = _plan("sqli.verify", {"path": "/item?id=1"}, REGISTRY_SQLI)
    thorough = _plan("sqli.verify", {"path": "/item?id=1"}, THOROUGH_SQLI)

    assert thorough.argv == registry.argv
    assert _flag(thorough, "--technique") == "BEUT"
    assert _flag(thorough, "--delay") == "1" and _flag(thorough, "--threads") == "1"
    assert thorough.timeout_ms == 540_000
    assert thorough.hard_budget_dict == THOROUGH_SQLI
    assert thorough.budget_proof["method"] == "fixed_conservative_profile"
    assert thorough.budget_proof["inputs"] == registry.budget_proof["inputs"]


def test_a_thorough_dalfox_call_keeps_its_argv_and_gets_the_longer_wall():
    registry = _plan("xss.verify", {"path": "/search?q=1"}, REGISTRY_XSS)
    thorough = _plan("xss.verify", {"path": "/search?q=1"}, THOROUGH_XSS)

    assert thorough.argv == registry.argv
    assert _flag(thorough, "--delay") == "1000" and _flag(thorough, "--worker") == "3"
    assert thorough.timeout_ms == 480_000
    assert thorough.hard_budget_dict == {"http_requests": 1_800, "tool_wall_seconds": 480}
    assert thorough.budget_proof["inputs"] == registry.budget_proof["inputs"]


def test_headless_dalfox_stays_at_its_floor_whatever_it_reserved():
    plan = _plan(
        "xss.verify", {"path": "/search?q=1", "deep_domxss": True}, THOROUGH_XSS,
    )
    assert _flag(plan, "--delay") == "0" and _flag(plan, "--worker") == "10"
    assert plan.hard_budget_dict == {"http_requests": 400, "tool_wall_seconds": 120}
    assert plan.timeout_ms == 120_000


@pytest.mark.parametrize("capability,reservation,expected", [
    ("sqli.verify", {"http_requests": 900, "tool_wall_seconds": 400},
     {"http_requests": 900, "tool_wall_seconds": 400}),
    ("sqli.verify", {"http_requests": 5_000, "tool_wall_seconds": 3_600},
     {"http_requests": 900, "tool_wall_seconds": 540}),
    ("xss.verify", {"http_requests": 900, "tool_wall_seconds": 200},
     {"http_requests": 900, "tool_wall_seconds": 200}),
    ("xss.verify", {"http_requests": 9_000, "tool_wall_seconds": 3_600},
     {"http_requests": 1_800, "tool_wall_seconds": 480}),
])
def test_a_plan_runs_with_what_it_reserved_up_to_the_reviewed_ceiling(
    capability, reservation, expected,
):
    path = "/item?id=1" if capability == "sqli.verify" else "/search?q=1"
    plan = _plan(capability, {"path": path}, reservation)
    assert plan.hard_budget_dict == expected
    assert plan.timeout_ms == expected["tool_wall_seconds"] * 1_000
    plan.validate_reservation(reservation)


@pytest.mark.parametrize("capability,reservation", [
    ("sqli.verify", {"http_requests": 899, "tool_wall_seconds": 540}),
    ("sqli.verify", {"http_requests": 900, "tool_wall_seconds": 299}),
    ("xss.verify", {"http_requests": 399, "tool_wall_seconds": 480}),
    ("xss.verify", {"http_requests": 1_800, "tool_wall_seconds": 119}),
])
def test_reservations_below_the_floors_are_still_refused(capability, reservation):
    path = "/item?id=1" if capability == "sqli.verify" else "/search?q=1"
    with pytest.raises(agent_tools.AgentToolError, match="verification requires"):
        _plan(capability, {"path": path}, reservation)


def test_paced_traffic_over_the_whole_wall_stays_inside_the_request_hold():
    """The pinned proxy stops a call at its connection ceiling and fails it. A paced call that
    runs its whole wall must reach that wall first, with a 10% margin."""
    sqlmap = _plan("sqli.verify", {"path": "/item?id=1"}, THOROUGH_SQLI)
    dalfox = _plan("xss.verify", {"path": "/search?q=1"}, THOROUGH_XSS)
    sqlmap_nominal = int(_flag(sqlmap, "--threads")) / float(_flag(sqlmap, "--delay"))
    dalfox_nominal = int(_flag(dalfox, "--worker")) / (int(_flag(dalfox, "--delay")) / 1_000)
    for rate, plan in (
        (max(sqlmap_nominal, MEASURED_SQLMAP_REQUESTS_PER_SECOND), sqlmap),
        (max(dalfox_nominal, MEASURED_DALFOX_REQUESTS_PER_SECOND), dalfox),
    ):
        hard = plan.hard_budget_dict
        assert rate * hard["tool_wall_seconds"] <= 0.9 * hard["http_requests"], plan.tool_name


# --- the wait, the lease and the worker's re-derivation ----------------------------------------


def test_the_wait_follows_the_reserved_wall_and_registry_holds_keep_the_spec_default():
    sqli = CAPABILITY_REGISTRY.require("sqli.verify")
    xss = CAPABILITY_REGISTRY.require("xss.verify")
    assert agent_tools.hunt_scanner_timeout_ms(sqli.default_timeout_ms, THOROUGH_SQLI) == 540_000
    assert agent_tools.hunt_scanner_timeout_ms(xss.default_timeout_ms, THOROUGH_XSS) == 480_000
    for spec in CAPABILITY_REGISTRY.for_hunt_executor("worker_scanner"):
        held = agent_tools.canonical_hunt_scanner_budget(spec.name)
        assert agent_tools.hunt_scanner_timeout_ms(
            spec.default_timeout_ms, held,
        ) == int(spec.default_timeout_ms), spec.name


def test_the_lease_follows_the_thorough_wall():
    for hold, lease in (
        (THOROUGH_SQLI, 570), (THOROUGH_XSS, 510), (REGISTRY_SQLI, 330), (REGISTRY_XSS, 150),
    ):
        assert hunt_capability_lease_seconds({**hold, "agent_actions": 1}) == lease


def test_the_worker_accepts_the_current_hold_and_a_call_admitted_before_it_existed():
    assert agent_tools.hunt_scanner_dispatch_budgets(
        "sqli.verify", budget_profile="thorough",
    ) == (THOROUGH_SQLI, REGISTRY_SQLI)
    assert agent_tools.hunt_scanner_dispatch_budgets(
        "sqli.verify", budget_profile="balanced",
    ) == (REGISTRY_SQLI,)
    assert agent_tools.hunt_scanner_dispatch_budgets(
        "xss.verify", budget_profile="thorough", deep_domxss=True,
    ) == (REGISTRY_XSS,)

    current = {**THOROUGH_SQLI, "agent_actions": 1, "active_actions": 1}
    legacy = {**REGISTRY_SQLI, "agent_actions": 1, "active_actions": 1}
    pick = agent_tools.admitted_hunt_scanner_hold
    assert pick(legacy, [current, legacy]) == legacy
    assert pick(current, [current, legacy]) == current
    # Anything else is compared with the current hold, so the digest check refuses it.
    assert pick({**current, "http_requests": 901}, [current, legacy]) == current


# --- admission, through the production lifecycle ----------------------------------------------


def _scanner_admission(profile, name, values):
    store = AdmissionStore()
    store.run["budget_profile"] = profile
    store.run["budget_json"].update({
        "max_duration_seconds": 14_400, "max_http_requests": 20_000,
        "max_browser_actions": 1_000,
    })
    recorded: list[dict[str, int]] = []

    def reservation(**kwargs):
        recorded.append(dict(kwargs["amounts"]))
        return Reservation(kwargs["amounts"])

    overrides = {
        "agent_tools": SimpleNamespace(
            normalize_principal_slot=lambda _value: "anonymous", IDENTITY_HEADERS=set(),
            canonical_hunt_scanner_budget=agent_tools.canonical_hunt_scanner_budget,
        ),
        "_hunt_public": lambda *args, **kwargs: {"capabilities": [{"name": name}]},
        "DurableBudgetReservation": SimpleNamespace(request=reservation),
    }
    # The labelled double's worker_scanner placement; the capability name is what admission reads.
    lifecycle = Lifecycle("xss.verify")
    asyncio.run(admission(store, **overrides)(
        str(HUNT), name, SimpleNamespace(input=values, idempotency_key="scanner-0001"), lifecycle,
    ))
    assert len(recorded) == 1
    return recorded[0]


@pytest.mark.parametrize("profile,name,values,expected", [
    ("thorough", "sqli.verify", {"path": "/item?id=1"}, THOROUGH_SQLI),
    ("thorough", "xss.verify", {"path": "/search?q=1"}, THOROUGH_XSS),
    ("thorough", "xss.verify", {"path": "/search?q=1", "deep_domxss": True}, REGISTRY_XSS),
    ("balanced", "sqli.verify", {"path": "/item?id=1"}, REGISTRY_SQLI),
    ("balanced", "xss.verify", {"path": "/search?q=1"}, REGISTRY_XSS),
    ("fast", "xss.verify", {"path": "/search?q=1"}, REGISTRY_XSS),
])
def test_admission_reserves_the_hold_of_the_hunt_profile(profile, name, values, expected):
    charges = _scanner_admission(profile, name, values)
    assert {key: charges[key] for key in expected} == expected
    assert charges["agent_actions"] == 1 and charges["active_actions"] == 1


# --- the API wait ------------------------------------------------------------------------------


class _Clock:
    """Labelled double: the event-loop clock and sleep the API wait reads."""

    CancelledError = asyncio.CancelledError

    def __init__(self):
        self.now = 0.0

    def get_running_loop(self):
        return self

    def time(self):
        return self.now

    async def sleep(self, seconds):
        self.now += seconds


class _WorkerRedis:
    """Labelled double: Redis, with a worker that publishes its result after ``finishes_at``."""

    def __init__(self, clock, finishes_at):
        self.clock, self.finishes_at = clock, finishes_at
        self.cancelled: list[str] = []
        self.enqueued: list[dict] = []

    def hset(self, *_args, **_kwargs):
        return 1

    def expire(self, *_args, **_kwargs):
        return True

    def get(self, key):
        assert key.startswith("agent_tool_result:")
        if self.clock.now < self.finishes_at:
            return None
        return json.dumps({"status": "success", "elapsed_seconds": self.finishes_at}).encode()

    def delete(self, *_keys):
        return 1

    def set(self, key, _value, ex=None):
        self.cancelled.append(key)


def _wait_for_worker(monkeypatch, *, timeout_ms, finishes_at):
    clock = _Clock()
    redis = _WorkerRedis(clock, finishes_at)

    async def record_job(*_args, **_kwargs):
        return None

    monkeypatch.setattr(router, "asyncio", clock)
    monkeypatch.setattr(router, "get_redis", lambda: redis)
    monkeypatch.setattr(router, "record_cancellable_job_durable", record_job)
    monkeypatch.setattr(router, "_pool", lambda: None)
    monkeypatch.setattr(
        router, "enqueue_job", lambda _redis, _queue, payload: redis.enqueued.append(payload),
    )
    monkeypatch.setitem(router._deps, "AGENT_TOOL_QUEUE_NAME", lambda: "agent-tools-fixture")
    result = asyncio.run(router._enqueue_canonical_scanner_capability(
        capability_name="sqli.verify", capability_input={"path": "/item?id=1"},
        timeout_ms=timeout_ms, hunt_id=str(HUNT), action_id=str(uuid.UUID(int=7)),
        reservation_id=str(uuid.UUID(int=8)), action_digest="a" * 64,
    ))
    return result, redis, clock


def test_a_thorough_call_that_runs_500_seconds_returns_its_result(monkeypatch):
    spec = CAPABILITY_REGISTRY.require("sqli.verify")
    timeout_ms = agent_tools.hunt_scanner_timeout_ms(
        spec.default_timeout_ms, {**THOROUGH_SQLI, "agent_actions": 1},
    )
    result, redis, _clock = _wait_for_worker(monkeypatch, timeout_ms=timeout_ms, finishes_at=500)
    assert result == {"status": "success", "elapsed_seconds": 500}
    assert redis.cancelled == [] and len(redis.enqueued) == 1


def test_the_registry_wait_cancels_that_call_before_it_finishes(monkeypatch):
    """What a thorough hold would meet if the wait stayed at the spec default."""
    spec = CAPABILITY_REGISTRY.require("sqli.verify")
    result, redis, clock = _wait_for_worker(
        monkeypatch, timeout_ms=int(spec.default_timeout_ms), finishes_at=500,
    )
    assert result["status"] == "timeout" and result["error"] == "worker_result_timeout"
    assert 330 <= clock.now < 331
    assert len(redis.cancelled) == 1 and redis.cancelled[0].startswith("agent_tool_cancel:")
