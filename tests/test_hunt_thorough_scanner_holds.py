"""A Hunt's sqli.verify and xss.verify calls get a wall they can finish in.

In measured runs, 2 of 2 sqli.verify calls timed out at 300.06 s and 300.08 s after 272 and 295
requests, and 2 of 2 xss.verify calls timed out at 120 s after 400 requests. The argv paces
sqlmap at about 1 request/s and Dalfox at about 3.3 requests/s on every Hunt profile, so a
one-field sqlmap negative and one Dalfox parameter (about 1,300 requests) cannot finish inside
the registry wall. Every profile reserved the same hold.

Every named profile (fast, balanced, thorough) now reserves 1,800 requests / 1,200 s for
sqli.verify and 1,800 requests / 480 s for xss.verify, with the same argv. The sqli.verify hold is
twice what one injection point with no injection was measured to cost (up to 516 requests, about
570 s, on an endpoint that echoes the parameter): a 540 s wall stopped such a call at 490
requests without a verdict. Unprofiled historical Hunts, the passive templates.scan pack, calls
against a device target and headless (deep_domxss) xss.verify keep their 2.11.0 holds, plans and
waits byte for byte. A call the remaining budget cannot fund at its hold is refused with a
budget request a person can grant, never started at a shorter hold.
"""
from __future__ import annotations

import ast
import asyncio
import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from api import device_agent
from api.hunt import interaction_router as router
from api.hunt.capability_reservations import hunt_capability_lease_seconds
from api.hunt.device_policy import DeviceHuntPolicyState
from api.hunt.device_traffic import reserve_device_traffic
from api.hunt.fragment_xss_proof import hunt_browser_xss_proof_adapter
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.models import TargetBinding
from tests.test_hunt_authz_verification_limit import (
    HUNT,
    AdmissionStore,
    Lifecycle,
    Reservation,
    admission,
)

agent_tools = router.agent_tools
ROOT = Path(__file__).resolve().parents[1]

SQLMAP_OUTPUT = {"sqlmap_output_dir": "/tmp/shakerscan-sqlmap-fixture"}
DALFOX_SCRATCH = {"scratch_dir": "/tmp/shakerscan-dalfox-fixture"}
REGISTRY_SQLI = {"http_requests": 900, "tool_wall_seconds": 300}
REGISTRY_XSS = {"http_requests": 400, "tool_wall_seconds": 120, "browser_actions": 2}
THOROUGH_SQLI = {"http_requests": 1_800, "tool_wall_seconds": 1_200}
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
# Measured request rates behind the thorough holds (paced argv, one parameter, fast target).
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


def test_a_thorough_device_call_keeps_the_registry_hold():
    # A device's fragility allowance is charged one point per held request (thorough allows 500
    # per Hunt), so a device target keeps the registry hold for both verifiers.
    for name, registry in (("sqli.verify", REGISTRY_SQLI), ("xss.verify", REGISTRY_XSS)):
        assert agent_tools.canonical_hunt_scanner_budget(
            name, budget_profile="thorough", device_target=True,
        ) == registry


BROWSER_TARGET = TargetBinding(
    target_id="10000000-0000-0000-0000-000000000002",
    target_kind="web",
    canonical_host="app.example.test",
    allowed_origins=("http://app.example.test:8080",),
    allowed_addresses=("192.0.2.10",),
    scope_receipt_id="10000000-0000-0000-0000-000000000003",
)


@pytest.mark.parametrize("path,browser", [
    # One fragment parameter and no server query: the worker runs the pinned browser prover.
    ("/#/search?q=1", True),
    # Everything else with a fragment runs paced Dalfox, which needs the longer wall.
    ("/search?q=1#results", False),
    ("/#/a?x=1&y=2", False),
    ("/page#top", False),
    ("/page?a=1&b=2#top", False),
])
def test_a_fragment_on_the_path_does_not_change_the_thorough_xss_verify_hold(path, browser):
    """The hold is read from the profile, the device and deep_domxss only. A path the browser
    takes runs within the prover's fixed limits, which fit inside either hold; a fragment path the
    browser does not take runs paced Dalfox and gets the thorough wall."""
    context = agent_tools.hunt_scanner_budget_context(
        {"budget_profile": "thorough", "device_target_id": None}, {"path": path},
    )
    assert agent_tools.canonical_hunt_scanner_budget("xss.verify", **context) == THOROUGH_XSS
    assert agent_tools.canonical_hunt_scanner_budget("sqli.verify", **context) == THOROUGH_SQLI
    adapter = hunt_browser_xss_proof_adapter(
        capability_name="xss.verify", spec=CAPABILITY_REGISTRY.require("xss.verify"),
        target=BROWSER_TARGET, execution_target="http://app.example.test:8080" + path,
        action_id="fragment-hold",
    )
    assert (adapter is not None) is browser
    if adapter is not None:
        estimate = dict(adapter.prepared.estimated_budget)
        for hold in (THOROUGH_XSS, REGISTRY_XSS):
            assert all(estimate[name] <= hold[name] for name in estimate), (estimate, hold)


@pytest.mark.parametrize("run,values,expected", [
    ({"budget_profile": "thorough", "device_target_id": None}, {"path": "/search?q=1"},
     {"budget_profile": "thorough", "deep_domxss": False, "device_target": False}),
    ({"budget_profile": "thorough", "device_target_id": uuid.UUID(int=9)},
     {"path": "/#/search?q=1", "deep_domxss": True},
     {"budget_profile": "thorough", "deep_domxss": True, "device_target": True}),
    # Only a literal true asks for headless Dalfox.
    ({"budget_profile": "balanced"}, {"path": "/search?q=1#", "deep_domxss": "true"},
     {"budget_profile": "balanced", "deep_domxss": False, "device_target": False}),
    ({}, {}, {"budget_profile": None, "deep_domxss": False, "device_target": False}),
])
def test_admission_and_the_worker_read_the_same_hold_context(run, values, expected):
    assert agent_tools.hunt_scanner_budget_context(run, values) == expected


_CONTEXTS = [
    {"deep_domxss": deep, "device_target": device}
    for deep in (False, True) for device in (False, True)
]


@pytest.mark.parametrize("profile", [None])
def test_unprofiled_historical_hunts_keep_every_registry_hold(profile):
    for spec in CAPABILITY_REGISTRY.for_hunt_executor("worker_scanner"):
        expected = dict(spec.budget_cost)
        if spec.name == "templates.scan":
            expected["http_requests"] = 7
        for context in _CONTEXTS:
            assert agent_tools.canonical_hunt_scanner_budget(
                spec.name, budget_profile=profile, **context,
            ) == expected, (spec.name, context)
            # One hold only, whatever the ledger has left: no step-down and no second candidate.
            holds = agent_tools.hunt_scanner_dispatch_budgets(
                spec.name, budget_profile=profile, **context,
            )
            assert holds == (expected,), (spec.name, context)
            assert agent_tools.affordable_hunt_scanner_hold(
                holds, limits={"http_requests": 1, "tool_wall_seconds": 1}, used={},
            ) == expected
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
    assert thorough.timeout_ms == 1_200_000
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


FLOOR_SQLMAP = {"http_requests": 900, "tool_wall_seconds": 300}
FLOOR_DALFOX = {"http_requests": 400, "tool_wall_seconds": 120}
TIER_SQLMAP = {"http_requests": 1_800, "tool_wall_seconds": 1_200}
TIER_DALFOX = {"http_requests": 1_800, "tool_wall_seconds": 480}


@pytest.mark.parametrize("capability,reservation,expected", [
    # In between the floor and the reviewed ceiling: exactly the floor, as before.
    ("sqli.verify", {"http_requests": 900, "tool_wall_seconds": 400}, FLOOR_SQLMAP),
    ("sqli.verify", {"http_requests": 5_000, "tool_wall_seconds": 1_199}, FLOOR_SQLMAP),
    ("sqli.verify", {"http_requests": 1_799, "tool_wall_seconds": 3_600}, FLOOR_SQLMAP),
    ("xss.verify", {"http_requests": 400, "tool_wall_seconds": 480}, FLOOR_DALFOX),
    ("xss.verify", {"http_requests": 900, "tool_wall_seconds": 200}, FLOOR_DALFOX),
    ("xss.verify", {"http_requests": 1_799, "tool_wall_seconds": 3_600}, FLOOR_DALFOX),
    # Covering the whole reviewed ceiling: the ceiling, never more.
    ("sqli.verify", TIER_SQLMAP, TIER_SQLMAP),
    ("sqli.verify", {"http_requests": 5_000, "tool_wall_seconds": 3_600}, TIER_SQLMAP),
    ("xss.verify", TIER_DALFOX, TIER_DALFOX),
    ("xss.verify", {"http_requests": 9_000, "tool_wall_seconds": 3_600}, TIER_DALFOX),
])
def test_a_plan_runs_at_the_floor_or_with_a_covered_reviewed_ceiling(
    capability, reservation, expected,
):
    """Only the two reviewed shapes run, so the paced rate never meets the request hold before
    the wall: 400 requests over 480 s would reach its connection ceiling at about 120 s."""
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
    assert agent_tools.hunt_scanner_timeout_ms(sqli.default_timeout_ms, THOROUGH_SQLI) == 1_200_000
    assert agent_tools.hunt_scanner_timeout_ms(xss.default_timeout_ms, THOROUGH_XSS) == 480_000
    for spec in CAPABILITY_REGISTRY.for_hunt_executor("worker_scanner"):
        held = agent_tools.canonical_hunt_scanner_budget(spec.name)
        assert agent_tools.hunt_scanner_timeout_ms(
            spec.default_timeout_ms, held,
        ) == int(spec.default_timeout_ms), spec.name


def test_the_lease_follows_the_thorough_wall():
    for hold, lease in (
        (THOROUGH_SQLI, 1_230), (THOROUGH_XSS, 510), (REGISTRY_SQLI, 330), (REGISTRY_XSS, 150),
    ):
        assert hunt_capability_lease_seconds({**hold, "agent_actions": 1}) == lease


def test_the_worker_accepts_the_current_hold_and_a_call_admitted_before_it_existed():
    assert agent_tools.hunt_scanner_dispatch_budgets(
        "sqli.verify", budget_profile="thorough",
    ) == (THOROUGH_SQLI, REGISTRY_SQLI)
    assert agent_tools.hunt_scanner_dispatch_budgets(
        "sqli.verify", budget_profile="balanced",
    ) == (THOROUGH_SQLI, REGISTRY_SQLI)
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


# --- where the reserved hold is read --------------------------------------------------------
#
# Structural pins, for a unit run without PostgreSQL. tests/test_hunt_thorough_scanner_dispatch_
# postgres.py executes the same call sites through admission, the queue and the worker.


def _function(relative, name):
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    return next(
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    )


def _calls(node, name):
    return [
        call for call in ast.walk(node)
        if isinstance(call, ast.Call)
        and (getattr(call.func, "attr", None) or getattr(call.func, "id", None)) == name
    ]


def test_the_api_waits_for_the_wall_its_own_reservation_holds():
    lifecycle = _function("api/hunt/interaction_router.py", "_execute_hunt_capability_lifecycle")
    (enqueue,) = _calls(lifecycle, "_enqueue_canonical_scanner_capability")
    timeout = next(keyword.value for keyword in enqueue.keywords if keyword.arg == "timeout_ms")
    assert ast.unparse(timeout) == (
        "agent_tools.hunt_scanner_timeout_ms(spec.default_timeout_ms, "
        "durable_reservation.record.requested)"
    )


def test_the_worker_rederives_the_hold_from_the_hunt_row_and_runs_the_reserved_wall():
    job = _function("api/worker.py", "process_canonical_scanner_capability_job")
    (dispatch,) = _calls(job, "hunt_scanner_dispatch_budgets")
    assert ast.unparse(dispatch) == (
        "agent_tools.hunt_scanner_dispatch_budgets(capability_name, "
        "**agent_tools.hunt_scanner_budget_context(run, capability_input))"
    )
    (admitted,) = _calls(job, "admitted_hunt_scanner_hold")
    assert ast.unparse(admitted.args[0]) == "stored.record.requested"
    # Every candidate hold is offered, the registry hold included: a call stepped down at
    # admission, or admitted before per-profile holds existed, reserved that one.
    assert ast.unparse(admitted.args[1]) == "[scanner_hold(base) for base in " + ast.unparse(
        dispatch,
    ) + "]"
    assigned = [
        node for node in ast.walk(job)
        if isinstance(node, ast.Assign) and node.value is admitted
    ]
    assert [ast.unparse(node.targets[0]) for node in assigned] == ["requested_budget"]
    (digest,) = _calls(job, "hunt_capability_action_digest")
    assert ast.unparse(next(
        keyword.value for keyword in digest.keywords if keyword.arg == "requested_budget"
    )) == "requested_budget"
    payload_timeouts = [
        value for node in ast.walk(job) if isinstance(node, ast.Dict)
        for key, value in zip(node.keys, node.values)
        if isinstance(key, ast.Constant) and key.value == "timeout_ms"
    ]
    assert [ast.unparse(value) for value in payload_timeouts] == [
        "agent_tools.hunt_scanner_timeout_ms(spec.default_timeout_ms, persisted.record.requested)"
    ]


# --- admission, through the production lifecycle ----------------------------------------------


DEVICE = uuid.UUID(int=9)
DEVICE_LOCATOR = "192.0.2.5"


class _LedgerReservation(Reservation):
    """Labelled double: a durable hold, checked against the ledger the way the store checks it."""

    def reserve_against(self, *, limits, consumed, lease_seconds):
        used = router.reserve_budget_snapshot(limits, consumed, self.requested)
        self.status = "reserved"
        return self, used


class _DeviceAdmissionStore(AdmissionStore):
    """Labelled double: the admission transaction for a Hunt whose target is a device."""

    def __init__(self):
        super().__init__()
        self.run.update({
            "target_id": None, "device_target_id": DEVICE, "target_kind": "device",
            "context_pack": {"target": {"kind": "device", "locator": DEVICE_LOCATOR}},
        })

    async def fetchrow(self, sql, *args):
        if "FROM device_targets" in sql:
            assert args == (DEVICE,)
            return {"primary_locator": DEVICE_LOCATOR, "is_active": True}
        return await super().fetchrow(sql, *args)


def _scanner_admission(profile, name, values, *, budget=None, used=None, device=False):
    store = _DeviceAdmissionStore() if device else AdmissionStore()
    store.run["budget_profile"] = profile
    store.run["budget_json"].update({
        "max_duration_seconds": 14_400, "max_http_requests": 20_000,
        "max_browser_actions": 1_000,
        **({"max_device_fragility_points": 500} if device else {}),
        **(budget or {}),
    })
    store.run["budget_used_json"].update(used or {})
    recorded: list[dict[str, int]] = []
    device_admissions: list[dict[str, int]] = []

    def reservation(**kwargs):
        recorded.append(dict(kwargs["amounts"]))
        return _LedgerReservation(kwargs["amounts"])

    async def device_admission(_conn, run, *, fragility, requests, scans=0, capability_name=None):
        # Labelled double: the device ledger queries. The device policy check itself is the
        # production one, at the limits a thorough device Hunt starts with.
        device_admissions.append({"fragility": fragility, "requests": requests})
        if fragility > device_agent.MAX_FRAGILITY_PER_DEVICE_DAY:
            raise ValueError("Daily fragility budget for this device is exhausted")
        DeviceHuntPolicyState.initial(
            safety_profile="authenticated_active",
            fragility_limit=int(store.run["budget_json"]["max_device_fragility_points"]),
            request_limit=int(store.run["budget_json"]["max_http_requests"]),
        ).require_admission(request_attempts=requests, fragility_cost=fragility)

    overrides = {
        "agent_tools": SimpleNamespace(
            normalize_principal_slot=lambda _value: "anonymous", IDENTITY_HEADERS=set(),
            affordable_hunt_scanner_hold=agent_tools.affordable_hunt_scanner_hold,
            hunt_scanner_dispatch_budgets=agent_tools.hunt_scanner_dispatch_budgets,
            hunt_scanner_budget_context=agent_tools.hunt_scanner_budget_context,
        ),
        "_hunt_public": lambda *args, **kwargs: {"capabilities": [{"name": name}]},
        "DurableBudgetReservation": SimpleNamespace(request=reservation),
        "BudgetExceeded": router.BudgetExceeded,
        "require_device_admission": device_admission,
    }
    # The labelled double's worker_scanner placement; the capability name is what admission reads.
    lifecycle = Lifecycle("xss.verify")
    # What decides whether a device run charges fragility for the call's traffic.
    lifecycle.specification.placement_requirements = dict(
        CAPABILITY_REGISTRY.require(name).placement_requirements,
    )
    asyncio.run(admission(store, **overrides)(
        str(HUNT), name, SimpleNamespace(input=values, idempotency_key="scanner-0001"), lifecycle,
    ))
    assert len(recorded) == 1
    if device:
        assert len(device_admissions) == 1
        recorded[0]["_device_admission"] = device_admissions[0]
    return recorded[0]


@pytest.mark.parametrize("profile,name,values,expected", [
    ("thorough", "sqli.verify", {"path": "/item?id=1"}, THOROUGH_SQLI),
    ("thorough", "xss.verify", {"path": "/search?q=1"}, THOROUGH_XSS),
    ("thorough", "xss.verify", {"path": "/search?q=1", "deep_domxss": True}, REGISTRY_XSS),
    # A fragment on the path does not change the hold (the browser route fits inside it).
    ("thorough", "xss.verify", {"path": "/#/search?q=1"}, THOROUGH_XSS),
    ("thorough", "xss.verify", {"path": "/search?q=1#results"}, THOROUGH_XSS),
    ("thorough", "sqli.verify", {"path": "/item?id=1#details"}, THOROUGH_SQLI),
    ("balanced", "sqli.verify", {"path": "/item?id=1"}, THOROUGH_SQLI),
    ("balanced", "xss.verify", {"path": "/search?q=1"}, THOROUGH_XSS),
    ("fast", "xss.verify", {"path": "/search?q=1"}, THOROUGH_XSS),
])
def test_admission_reserves_the_hold_of_the_hunt_profile(profile, name, values, expected):
    charges = _scanner_admission(profile, name, values)
    assert {key: charges[key] for key in expected} == expected
    assert charges["agent_actions"] == 1 and charges["active_actions"] == 1


def test_a_thorough_device_xss_verify_keeps_the_registry_hold_and_is_admitted():
    """A device's fragility allowance is charged one point per held request. A thorough
    xss.verify at 1,800 requests would need 1,800 of the Hunt's 500 points (and of the device's
    2,000 a day); at the registry hold it charges the 400 it always did and is admitted."""
    charges = _scanner_admission("thorough", "xss.verify", {"path": "/search?q=1"}, device=True)
    assert {key: charges[key] for key in REGISTRY_XSS} == REGISTRY_XSS
    assert charges["device_fragility_points"] == 400
    assert charges["_device_admission"] == {"fragility": 400, "requests": 400}


def test_a_thorough_device_sqli_verify_is_refused_as_it_always_was():
    """Its registry hold (900 points) already exceeded a thorough device Hunt's 500."""
    with pytest.raises(HTTPException, match="fragility limit is exhausted") as error:
        _scanner_admission("thorough", "sqli.verify", {"path": "/item?id=1"}, device=True)
    assert error.value.status_code == 409
    assert agent_tools.hunt_scanner_dispatch_budgets(
        "sqli.verify", **agent_tools.hunt_scanner_budget_context(
            {"budget_profile": "thorough", "device_target_id": DEVICE}, {"path": "/item?id=1"},
        ),
    ) == (REGISTRY_SQLI,)


def test_the_thorough_hold_on_a_device_would_be_refused_by_the_device_policy():
    """What admission met when a device run took the thorough xss.verify hold."""
    charges = dict(THOROUGH_XSS)
    reserve_device_traffic(
        {"device_target_id": DEVICE}, CAPABILITY_REGISTRY.require("xss.verify"), charges,
    )
    assert charges["device_fragility_points"] == 1_800
    with pytest.raises(ValueError, match="fragility limit is exhausted"):
        DeviceHuntPolicyState.initial(
            safety_profile="authenticated_active", fragility_limit=500, request_limit=20_000,
        ).require_admission(request_attempts=1_800, fragility_cost=1_800)


@pytest.mark.parametrize("name,values,budget,used,expected", [
    # Remaining wall between the registry and the thorough wall.
    ("sqli.verify", {"path": "/item?id=1"}, {}, {"tool_wall_seconds": 14_000}, REGISTRY_SQLI),
    ("xss.verify", {"path": "/search?q=1"}, {}, {"tool_wall_seconds": 14_100}, REGISTRY_XSS),
    # Remaining HTTP between the registry and the thorough request hold.
    ("xss.verify", {"path": "/search?q=1"}, {}, {"http_requests": 19_000}, REGISTRY_XSS),
    # A thorough Hunt started with a request budget below the thorough xss.verify hold.
    ("xss.verify", {"path": "/search?q=1"}, {"max_http_requests": 1_500}, {}, REGISTRY_XSS),
    ("sqli.verify", {"path": "/item?id=1"}, {"max_duration_seconds": 500}, {}, REGISTRY_SQLI),
    # Exactly enough for the thorough hold: it is taken.
    ("sqli.verify", {"path": "/item?id=1"}, {}, {"tool_wall_seconds": 13_200}, THOROUGH_SQLI),
    ("xss.verify", {"path": "/search?q=1"}, {"max_http_requests": 1_800}, {}, THOROUGH_XSS),
])
def test_new_calls_require_the_useful_hold_instead_of_falling_back_to_short_timeouts(
    name, values, budget, used, expected,
):
    if expected in (REGISTRY_SQLI, REGISTRY_XSS):
        with pytest.raises(HTTPException) as refusal:
            _scanner_admission("thorough", name, values, budget=budget, used=used)
        assert refusal.value.detail['reason_code'] in {'budget_insufficient_for_action', 'budget_exhausted'}
        return
    charges = _scanner_admission("thorough", name, values, budget=budget, used=used)
    assert {key: charges[key] for key in expected} == expected


def test_a_call_neither_hold_fits_is_refused_with_what_the_thorough_hold_needs():
    with pytest.raises(HTTPException) as error:
        _scanner_admission(
            "thorough", "sqli.verify", {"path": "/item?id=1"},
            used={"tool_wall_seconds": 14_200},
        )
    detail = error.value.detail
    assert detail["reason_code"] in {"budget_exhausted", "budget_insufficient_for_action"}
    assert detail["shortages"] == {"tool_wall_seconds": 14_200 + 1_200 - 14_400}


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
