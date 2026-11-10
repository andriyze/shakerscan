"""Every planned active-template window finishes inside its slice under a zoo-derived timing model.

Unit fixture, no scanner process: the real batch adapter runs synthetic slices whose attempts are
answered by a timing MODEL built from the finding-zoo run on d0a8d43c8 (thorough, state-changing
HTTP). It is not a replay: the run's per-attempt checkpoints were not available, only each
slice's holds and consumption. There, 23 of 169 active-template slices ended ``timed_out`` on the
16 of 57 hosts with three to five endpoints, and those hosts reported 37 or 38 of 39 template
windows run. The slices did not run out of wall (round 2 used about 1,230 of its 1,485 s); the
model attributes the losses to single attempts:

* nuclei paces at the attempt's requests over its wall. The wall earlier attempts left unspent was
  carried to the next one but its request hold stayed an even split, so a carried wall halved the
  rate to 1 request/s and a 100-request window could not finish in what it was given.
* A slice's first attempt has no carried wall: 45 s at 2 requests/s is 90 requests, and the
  heaviest windows send 94-102 (window 3 opened round 2 on three-endpoint hosts, window 37
  opened round 3 on four-endpoint hosts).
* A cut-off window that had already reported a match was not retried, so its other templates
  never ran on that host.

The per-window request counts are reconstructed from the slices' consumed requests at each
endpoint count (windows not separable there are given 63, the run's mean). A window takes its
requests over the attempt's rate plus a second. The model is pessimistic against the zoo: every
attempt reports a match before any cut-off, so the existing retry of an empty cut-off never
rescues one (on the zoo, hosts with one or two endpoints recovered such windows that way).
"""

from __future__ import annotations

import asyncio
import math
import uuid
from dataclasses import replace

import pytest
import scan.action_adapter as action_adapter_module
from hunt.capability_executor import CapabilityAdapterResult
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
    _allowlist,
    _Host,
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


#: What the planner holds for a window retry beside a slice's positions when the ledger has room
#: (``action_plan.window_retry_hold``; the planner's own holds are pinned in
#: test_active_template_windows): the share multiple's wall at the positions' 2 requests/s.
RETRY_HOLD = {
    "tool_wall_seconds": ACTIVE_TEMPLATE_WINDOW_RETRY_SECONDS,
    "http_requests": 2 * ACTIVE_TEMPLATE_WINDOW_RETRY_SECONDS,
    "state_changing_requests": 2 * ACTIVE_TEMPLATE_WINDOW_RETRY_SECONDS,
}


def _slice_action(host, number, start, count, endpoints, retry_hold=RETRY_HOLD):
    """A slice as the planner holds it: 120 requests / 45 s a position, plus the retry hold on a
    slice of further windows."""
    action = host.action(f"active.templates.r{number:02d}", start=start, count=count)
    if start < endpoints or not retry_hold:
        return action
    return replace(
        action,
        capability_args={**action.capability_args, "window_retry_hold": dict(retry_hold)},
        requested_budget={
            name: int(amount) + int(retry_hold.get(name, 0))
            for name, amount in action.requested_budget.items()
        },
        action_digest=None,
    )


def _host(endpoints):
    return _Host(tuple(["/"] + [f"/p{index}" for index in range(1, endpoints)]))


def _run_host(monkeypatch, bundle_dir, endpoints, timing):
    host = _host(endpoints)
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


def test_a_heavy_window_opening_a_two_position_final_slice_finishes(monkeypatch, bundle):  # noqa: F811
    """A four-endpoint host's round 3 is windows 37 and 38 (240 requests / 90 s of positions).
    With a wall-only retry hold, a 125-request window 37 got 120 requests / 60 s, was cut off,
    and its retry was shortened to the few requests left and never ran. The slice now holds the
    retry's requests with its wall, so window 37's first attempt can use that headroom at the
    planned 2 requests/s and finishes without a retry."""
    timing = _ZooTiming(bundle, requests={**ZOO_WINDOW_REQUESTS, 37: 125})
    host = _host(4)
    action = _slice_action(host, 3, 37, 2, 4)
    assert dict(action.requested_budget) == {
        "http_requests": 510, "state_changing_requests": 510, "tool_wall_seconds": 225,
    }
    receipt = _dispatch(monkeypatch, host, bundle, action, timing)
    assert receipt.status == "success" and not receipt.timed_out
    assert _windows_record(receipt)["windows_run"] == [37, 38]
    assert all(item["seconds"] <= item["budget"]["tool_wall_seconds"] for item in timing.attempts)
    # The retry hold is headroom, not a faster pace: window 37 runs at its planned rate.
    first = next(item for item in timing.attempts if item["window"] == 37)
    assert first["rate"] == 2
    for name, amount in receipt.budget_consumed.items():
        assert int(amount) <= int(action.requested_budget[name])
    # The same slice holding the retry's wall alone loses the window, as 2.11.1's first fix did.
    wall_only = _ZooTiming(bundle, requests={**ZOO_WINDOW_REQUESTS, 37: 125})
    other = _host(4)
    lost = _dispatch(
        monkeypatch, other, bundle,
        _slice_action(other, 3, 37, 2, 4, retry_hold={"tool_wall_seconds": 135}), wall_only,
    )
    assert _windows_record(lost)["windows_run"] == [38]
    assert lost.redacted_execution["retried_count"] == 0


def test_a_cut_off_window_is_retried_once_and_its_reproduced_match_kept_once(monkeypatch, bundle):  # noqa: F811
    """A slice the ledger left no retry hold still retries a window its wall cut off after a
    match, from what the slice's other windows left. First-pass identities are the planned
    positions'; the match the retry reproduced is recorded once; a resume re-sends nothing."""
    timing = _ZooTiming(bundle)
    host = _host(3)
    action = _slice_action(host, 2, 3, 33, 3, retry_hold=None)
    receipt = _dispatch(monkeypatch, host, bundle, action, timing)
    window_three = [item for item in timing.attempts if item["window"] == 3]
    assert len(window_three) == 2
    assert window_three[0]["budget"]["tool_wall_seconds"] == 45
    assert window_three[0]["seconds"] > 45
    assert window_three[1]["seconds"] <= window_three[1]["budget"]["tool_wall_seconds"]
    assert receipt.status == "success" and not receipt.timed_out
    assert 3 in _windows_record(receipt)["windows_run"]
    assert receipt.redacted_execution["retried_count"] == 1
    assert receipt.redacted_execution["recovered_count"] == 1
    matches = [
        item for item in receipt.observations
        if item.get("kind") == "template_match" and item.get("template_id") == "synthetic-window-3"
    ]
    assert len(matches) == 1
    attempts = host.backend.attempts[action.action_id]
    assert {
        position for position in range(3, 36) if host.attempt_id(position) in attempts
    } == set(range(3, 36))
    sent = len(timing.attempts)
    resumed = _dispatch(monkeypatch, host, bundle, action, timing)
    assert len(timing.attempts) == sent
    assert resumed.status == "success"
    assert 3 in _windows_record(resumed)["windows_run"]


def _own_slice(host, number, start, count, retry_hold=None):
    """A slice of a host's own endpoint positions (no ``endpoint_entries``): what a host with
    39 or more endpoints, or any fast or balanced Scan, is planned. A later round's slice also
    holds the window retry when the ledger has room."""
    action = host.action(f"active.templates.r{number:02d}", start=start, count=count, windows=False)
    if not retry_hold:
        return action
    return replace(
        action,
        capability_args={**action.capability_args, "window_retry_hold": dict(retry_hold)},
        requested_budget={
            name: int(amount) + int(retry_hold.get(name, 0))
            for name, amount in action.requested_budget.items()
        },
        action_digest=None,
    )


def _inside_the_reservation(actions, receipts):
    """Every slice, and the family as a whole, consumed no more than the plan reserved."""
    for name in ("http_requests", "state_changing_requests", "tool_wall_seconds"):
        for action, receipt in zip(actions, receipts):
            assert int(receipt.budget_consumed.get(name, 0)) <= int(action.requested_budget[name])
        assert sum(int(receipt.budget_consumed.get(name, 0)) for receipt in receipts) <= sum(
            int(action.requested_budget[name]) for action in actions
        )


def test_a_carried_wall_keeps_the_planned_rate_on_an_endpoints_own_slice(monkeypatch, bundle):  # noqa: F811
    """A host with 39 or more endpoints plans its windows as the endpoints' own positions, with
    no ``endpoint_entries``. Three light windows left wall for the fourth, but its request hold
    stayed the even split: 127 requests on 84 s paced at 1 request/s, and a 111-request window
    was cut off with a match already reported. The carried wall now carries the requests that
    keep the planned 2 requests/s there too, and the window finishes in its first attempt."""
    timing = _ZooTiming(bundle, requests={0: 66, 1: 44, 2: 38, 3: 111})
    host = _host(45)
    actions = [
        _own_slice(host, 1, 0, 33),
        _own_slice(host, 3, 33, 12, retry_hold=RETRY_HOLD),
    ]
    receipts = [_dispatch(monkeypatch, host, bundle, action, timing) for action in actions]
    assert [receipt.status for receipt in receipts] == ["success", "success"]
    assert not any(receipt.timed_out for receipt in receipts)
    run = set()
    for receipt in receipts:
        run |= set(_windows_record(receipt)["windows_run"])
    assert run == set(range(39))
    # No attempt was cut off, none was retried, and none ran below its planned 2 requests/s.
    assert all(item["seconds"] <= item["budget"]["tool_wall_seconds"] for item in timing.attempts)
    assert [receipt.redacted_execution["retried_count"] for receipt in receipts] == [0, 0]
    assert min(item["rate"] for item in timing.attempts) == 2
    fourth = next(item for item in timing.attempts if item["window"] == 3)
    assert fourth["budget"]["http_requests"] >= 2 * fourth["budget"]["tool_wall_seconds"]
    # A slice's opening attempt holds its planned share, 120 requests / 45 s. Where the slice
    # holds a retry beside its positions, that hold is headroom for the opening attempt at the
    # same 2 requests/s, and the positions' shares are still counted without it.
    opening = next(item for item in timing.attempts if item["window"] == 0)
    assert (opening["budget"]["http_requests"], opening["budget"]["tool_wall_seconds"]) == (120, 45)
    later = next(item for item in timing.attempts if item["window"] == 33)
    assert later["budget"]["tool_wall_seconds"] == ACTIVE_TEMPLATE_WINDOW_RETRY_SECONDS
    assert later["rate"] == 2
    _inside_the_reservation(actions, receipts)


def test_a_window_cut_off_after_a_match_is_retried_on_an_endpoints_own_slice(monkeypatch, bundle):  # noqa: F811
    """A slice's opening attempt has no carried wall: 45 s at 2 requests/s is 90 requests, and
    a 100-request window is cut off. It had reported a match, so on a slice of the endpoints'
    own positions it was never retried and its other templates never ran. It is now retried
    once, from what the slice's other windows left, and its match is recorded once."""
    timing = _ZooTiming(bundle, requests={0: 100})
    host = _host(45)
    action = _own_slice(host, 1, 0, 33)
    receipt = _dispatch(monkeypatch, host, bundle, action, timing)
    opening = [item for item in timing.attempts if item["window"] == 0]
    assert len(opening) == 2
    assert opening[0]["budget"]["tool_wall_seconds"] == 45 < opening[0]["seconds"]
    assert opening[1]["seconds"] <= opening[1]["budget"]["tool_wall_seconds"]
    assert opening[1]["rate"] >= 2
    assert receipt.status == "success" and not receipt.timed_out
    assert _windows_record(receipt)["windows_run"] == list(range(33))
    assert receipt.redacted_execution["retried_count"] == 1
    assert receipt.redacted_execution["recovered_count"] == 1
    matches = [
        item for item in receipt.observations
        if item.get("kind") == "template_match" and item.get("template_id") == "synthetic-window-0"
    ]
    assert len(matches) == 1
    _inside_the_reservation([action], [receipt])
    # A resume re-sends nothing and keeps the recovered window.
    sent = len(timing.attempts)
    resumed = _dispatch(monkeypatch, host, bundle, action, timing)
    assert len(timing.attempts) == sent
    assert resumed.status == "success"
    assert 0 in _windows_record(resumed)["windows_run"]


def test_every_window_cut_off_at_once_stays_inside_the_reservation(monkeypatch, bundle):  # noqa: F811
    """The worst case for the holds: every window needs more than any attempt can be given, so
    every first attempt is cut off and the retries take whatever is left. The slices and the
    family never consume more requests, mutations or wall than the plan reserved."""
    timing = _ZooTiming(bundle, requests={window: 400 for window in range(39)})
    host = _host(45)
    actions = [
        _own_slice(host, 1, 0, 33),
        _own_slice(host, 3, 33, 12, retry_hold=RETRY_HOLD),
    ]
    receipts = [_dispatch(monkeypatch, host, bundle, action, timing) for action in actions]
    assert all(receipt.timed_out for receipt in receipts)
    _inside_the_reservation(actions, receipts)
    # Every window was tried, and each at most twice: one attempt and one retry.
    tried = [item["window"] for item in timing.attempts]
    assert set(tried) == set(range(39))
    assert max(tried.count(window) for window in set(tried)) <= 2


def test_a_short_endpoints_own_slice_with_nothing_left_is_not_retried(monkeypatch, bundle):  # noqa: F811
    """A two-position slice whose first window is cut off and whose second leaves less wall
    than the first attempt had: the retry would get no more wall than the attempt that was cut
    off, so it is not run and the window is reported as not finished. The positions' holds are
    the even split, as before."""
    host = _Host(("/", "/a"))
    action = host.action("active.templates.r01", start=0, count=2, windows=False)
    timing = _ZooTiming(bundle, requests={0: 150, 1: 45})
    receipt = _dispatch(monkeypatch, host, bundle, action, timing)
    assert [item["window"] for item in timing.attempts] == [0, 1]
    assert receipt.redacted_execution["retried_count"] == 0
    assert receipt.timed_out
    assert _windows_record(receipt)["windows_run"] == [1]
    assert [item["budget"]["http_requests"] for item in timing.attempts] == [120, 150]
    _inside_the_reservation([action], [receipt])


def test_a_window_attempt_keeps_its_planned_rate_inside_the_slice_holds():
    planned = {"http_requests": 3960, "state_changing_requests": 3960, "tool_wall_seconds": 1485}
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
    # An even split already above the planned pace is kept, never cut back to it.
    even = window_template_attempt_hold(
        {"http_requests": 150, "state_changing_requests": 150, "tool_wall_seconds": 45},
        remaining_budget={"http_requests": 300, "state_changing_requests": 300, "tool_wall_seconds": 90},
        remaining_attempts=2, requested_budget=planned, first_pass=33, planned_wall_share=45,
    )
    assert even == {"http_requests": 150, "state_changing_requests": 150, "tool_wall_seconds": 45}
