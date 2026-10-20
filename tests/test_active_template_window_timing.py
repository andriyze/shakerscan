"""Every planned active-template window finishes inside its slice at the zoo's measured timing.

Unit fixture, no scanner process: the real batch adapter runs synthetic slices whose attempts are
answered by a timing model of the finding-zoo run on d0a8d43c8 (thorough, state-changing HTTP).
There, 23 of 169 active-template slices ended ``timed_out`` on the 16 of 57 hosts with three to
five endpoints, and those hosts reported 37 or 38 of 39 template windows run. The receipts show
the slices did not run out of wall (round 2 used about 1,230 of its 1,485 s); single attempts did:

* nuclei paces at the attempt's requests over its wall. The wall earlier attempts left unspent was
  carried to the next one but its request hold stayed an even split, so a carried wall halved the
  rate to 1 request/s and a 100-request window could not finish in what it was given.
* A slice's first attempt has no carried wall: 45 s at 2 requests/s is 90 requests, and the
  heaviest windows send 94-102 (window 3 opened round 2 on three-endpoint hosts, window 37
  opened round 3 on four-endpoint hosts).
* A cut-off window that had already reported a match was not retried, so its other templates
  never ran on that host.

The model's per-window request counts are the zoo's (derived from the slices' consumed requests
at each endpoint count; windows not separable there send 63, the zoo's mean); a window takes its
requests over the attempt's rate plus a second, and an attempt whose wall is shorter is cut off
after reporting a match.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
import math
import uuid

import pytest

from hunt.capability_executor import CapabilityAdapterResult
import scan.action_adapter as action_adapter_module
from scan.action_adapter import DatabaseNeutralScanActionDispatcher
from scan.action_plan import ScanActionPlan
from scan.execution_backend import ActionLease
from scan.external_process import (
    ACTIVE_TEMPLATE_WINDOW_RETRY_SECONDS,
    window_template_attempt_hold,
)
from scan.nuclei_execution import active_template_window

from tests.test_active_template_window_attempts import (  # noqa: F401  (bundle is a fixture)
    AUTHORIZED,
    TARGET,
    _Host,
    _allowlist,
    _windows_record,
    bundle,
)

#: Requests each window sent on the zoo (endpoint-independent: most active templates address
#: the host with absolute paths).
ZOO_WINDOW_REQUESTS = {
    0: 66, 1: 45, 2: 41, 3: 94, 4: 32, 5: 102, 6: 102, 7: 58,
    34: 49, 35: 60, 36: 50, 37: 96, 38: 46,
}
ZOO_MEAN_WINDOW_REQUESTS = 63
NUCLEI_RATE_CEILING = 10


def _rate(budget):
    """nuclei's rate for one attempt, as agent_tools derives it from the hold."""
    return min(
        NUCLEI_RATE_CEILING,
        max(1, int(budget["http_requests"]) // max(1, int(budget["tool_wall_seconds"]))),
    )


def _dispatch(monkeypatch, host, bundle_dir, action, execute):
    plan = ScanActionPlan(
        scan_id=host.scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    async def answer(_executor, context, adapter, **_kwargs):
        return await execute(context, adapter)

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", answer)
    monkeypatch.setattr(action_adapter_module, "nuclei_templates_directory", lambda: bundle_dir)

    async def process_runner(*_a, **_k):
        raise AssertionError("process runner must not be used")

    async def heartbeat():
        return None

    dispatcher = DatabaseNeutralScanActionDispatcher(
        target_url="https://app.example.test/", options={}, target=TARGET, policy=AUTHORIZED,
        scan_id=plan.scan_id, job_id="job-1", worker_id="broker:worker-1", plan=plan,
        backend=host.backend, process_runner=process_runner, cancelled=lambda: False,
    )
    lease = ActionLease(
        lease_id=str(uuid.uuid4()), lease_token="x" * 32, scan_id=plan.scan_id,
        plan_digest=plan.plan_digest, execution_plan_digest=plan.execution_plan_digest,
        target_binding_digest=plan.target_binding_digest, action=action,
        backend="broker", worker_id="broker:worker-1", lease_seconds=60, attempt=1,
    )
    return asyncio.run(dispatcher(action, lease, heartbeat))


class _ZooTiming:
    """Answers each attempt as the zoo's windows ran, and records what each attempt held."""

    def __init__(self, bundle_dir, requests=None):
        allowlist = _allowlist(bundle_dir, state_changing=True)
        self.index_of = {
            active_template_window(allowlist, position).template_ids: position
            for position in range(39)
        }
        self.requests = dict(ZOO_WINDOW_REQUESTS if requests is None else requests)
        self.attempts: list[dict] = []

    async def __call__(self, context, adapter):
        budget = dict(context.requested_budget)
        window = self.index_of[adapter._process_payload["scanner_options"]["template_ids"]]
        need = self.requests.get(window, ZOO_MEAN_WINDOW_REQUESTS)
        rate = _rate(budget)
        wall = int(budget["tool_wall_seconds"])
        seconds = math.ceil(need / rate) + 1
        self.attempts.append({"window": window, "budget": budget, "rate": rate, "seconds": seconds})
        match = ({
            "kind": "template_match", "template_id": f"synthetic-window-{window}",
            "matched_at": "https://app.example.test/",
        },)
        if seconds > wall or need > int(budget["http_requests"]):
            sent = min(int(budget["http_requests"]), rate * wall)
            return CapabilityAdapterResult(
                status="partial", partial=True, timed_out=seconds > wall,
                actual_budget={
                    "http_requests": sent, "state_changing_requests": sent,
                    "tool_wall_seconds": wall,
                },
                observations=match, execution_started=True, parser_version="nuclei-jsonl/v1",
            )
        return CapabilityAdapterResult(
            status="success",
            actual_budget={
                "http_requests": need, "state_changing_requests": need, "tool_wall_seconds": seconds,
            },
            observations=match, execution_started=True, parser_version="nuclei-jsonl/v1",
        )


def _planned_slices(endpoints):
    """The thorough rounds' slices: the endpoints' own positions, then 33 windows a round."""
    slices = [(0, endpoints)]
    start = endpoints
    while start < 39:
        count = min(33, 39 - start)
        slices.append((start, count))
        start += count
    return slices


def _slice_action(host, number, start, count, endpoints):
    """A slice as the planner holds it: 120 requests / 45 s a position, and one retry's wall on
    a slice of further windows (the planner's holds are pinned in test_active_template_windows)."""
    action = host.action(f"active.templates.r{number:02d}", start=start, count=count)
    if start < endpoints:
        return action
    return replace(
        action,
        capability_args={
            **action.capability_args, "window_retry_seconds": ACTIVE_TEMPLATE_WINDOW_RETRY_SECONDS,
        },
        requested_budget={
            **action.requested_budget,
            "tool_wall_seconds": int(action.requested_budget["tool_wall_seconds"])
            + ACTIVE_TEMPLATE_WINDOW_RETRY_SECONDS,
        },
        action_digest=None,
    )


def _run_host(monkeypatch, bundle_dir, endpoints, timing):
    host = _Host(tuple(["/"] + [f"/p{index}" for index in range(1, endpoints)]))
    actions = [
        _slice_action(host, number, start, count, endpoints)
        for number, (start, count) in enumerate(_planned_slices(endpoints), start=1)
    ]
    receipts = [_dispatch(monkeypatch, host, bundle_dir, action, timing) for action in actions]
    return host, actions, receipts


@pytest.mark.parametrize("endpoints", [1, 2, 3, 4, 5, 7, 8])
def test_every_window_finishes_at_the_zoo_timing(monkeypatch, bundle, endpoints):  # noqa: F811
    timing = _ZooTiming(bundle)
    _host, actions, receipts = _run_host(monkeypatch, bundle, endpoints, timing)
    assert [receipt.status for receipt in receipts] == ["success"] * len(receipts)
    assert not any(receipt.timed_out for receipt in receipts)
    run = set()
    for receipt in receipts:
        run |= set(_windows_record(receipt)["windows_run"])
    assert run == set(range(39))
    # No attempt was cut off, and none ran below the 2 requests/s its position was planned at.
    assert all(item["seconds"] <= item["budget"]["tool_wall_seconds"] for item in timing.attempts)
    assert min(item["rate"] for item in timing.attempts) == 2
    # Every slice stayed inside its own holds.
    for action, receipt in zip(actions, receipts):
        for name, amount in receipt.budget_consumed.items():
            assert int(amount) <= int(action.requested_budget[name])


def test_a_cut_off_window_that_reported_a_match_is_retried_and_counted(monkeypatch, bundle):  # noqa: F811
    """A window heavier than anything a slice can carry to it is cut off; its retry, funded by the
    slice's retry wall, finishes it. The first attempt's identity is the planned position's."""
    timing = _ZooTiming(bundle, requests={**ZOO_WINDOW_REQUESTS, 3: 150})
    host, actions, receipts = _run_host(monkeypatch, bundle, 3, timing)
    second = receipts[1]
    assert second.status == "success"
    assert 3 in _windows_record(second)["windows_run"]
    assert second.redacted_execution["retried_count"] == 1
    assert second.redacted_execution["recovered_count"] == 1
    window_three = [item for item in timing.attempts if item["window"] == 3]
    assert len(window_three) == 2
    assert window_three[0]["seconds"] > window_three[0]["budget"]["tool_wall_seconds"]
    assert window_three[1]["seconds"] <= window_three[1]["budget"]["tool_wall_seconds"]
    attempts = host.backend.attempts[actions[1].action_id]
    assert {
        position for position in range(3, 36) if host.attempt_id(position) in attempts
    } == set(range(3, 36))
    # Resumed, the slice re-sends nothing: both attempts are checkpointed.
    sent = len(timing.attempts)
    resumed = _dispatch(monkeypatch, host, bundle, actions[1], timing)
    assert len(timing.attempts) == sent
    assert resumed.status == "success"
    assert 3 in _windows_record(resumed)["windows_run"]


def test_an_endpoints_own_slice_without_planned_windows_keeps_its_retry_rule(monkeypatch, bundle):  # noqa: F811
    """A fast or balanced slice (no ``endpoint_entries``) is planned and run as before: an
    attempt the wall cut off after reporting a match is not retried."""
    host = _Host(("/", "/a"))
    action = host.action("active.templates.r01", start=0, count=2, windows=False)
    timing = _ZooTiming(bundle, requests={0: 150, 1: 45})
    receipt = _dispatch(monkeypatch, host, bundle, action, timing)
    assert [item["window"] for item in timing.attempts] == [0, 1]
    assert receipt.redacted_execution["retried_count"] == 0
    assert receipt.timed_out
    # The even split of 2.11.0, unchanged: 120 requests / 45 s, then what is left.
    assert [item["budget"]["http_requests"] for item in timing.attempts] == [120, 150]


def test_a_window_attempt_keeps_its_planned_rate_inside_the_slice_holds():
    planned = {"http_requests": 3960, "state_changing_requests": 3960, "tool_wall_seconds": 1620}
    # A carried wall now carries the requests that keep 2 requests/s.
    hold = window_template_attempt_hold(
        {"http_requests": 122, "state_changing_requests": 122, "tool_wall_seconds": 74},
        remaining_budget={"http_requests": 3928, "state_changing_requests": 3928, "tool_wall_seconds": 1604},
        remaining_attempts=32, requested_budget=planned, first_pass=33, planned_wall_share=45,
    )
    assert hold == {"http_requests": 148, "state_changing_requests": 148, "tool_wall_seconds": 74}
    assert _rate(hold) == 2
    # Every later attempt keeps its planned share of the requests.
    assert 3928 - hold["http_requests"] >= 31 * 120
    # When no requests are left to carry, the wall shrinks to what they pace at the planned rate.
    first = window_template_attempt_hold(
        {"http_requests": 120, "state_changing_requests": 120, "tool_wall_seconds": 135},
        remaining_budget=planned, remaining_attempts=33,
        requested_budget=planned, first_pass=33, planned_wall_share=45,
    )
    assert first == {"http_requests": 120, "state_changing_requests": 120, "tool_wall_seconds": 60}
    # Never more than the slice has left, and never below the planned share of wall.
    last = window_template_attempt_hold(
        {"http_requests": 30, "state_changing_requests": 30, "tool_wall_seconds": 135},
        remaining_budget={"http_requests": 30, "state_changing_requests": 30, "tool_wall_seconds": 135},
        remaining_attempts=1, requested_budget=planned, first_pass=33, planned_wall_share=45,
    )
    assert last == {"http_requests": 30, "state_changing_requests": 30, "tool_wall_seconds": 45}
