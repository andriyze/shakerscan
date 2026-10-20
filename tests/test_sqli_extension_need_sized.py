"""A request-bound thorough SQLi extension holds the wall its remaining technique needs.

A SQLi slice paces twice, and both pacers divide its wall by its request hold: sqlmap's delay is
``wall / (0.9 x requests)`` (``external_process.paced_request_delay``) and the slice's shared
request gate admits ``0.9 x requests / wall`` per second (``sqli_concurrency.slice_rate_ceiling``).
An extension of a slice its request hold stopped (partial, ``http_request_budget_exhausted``)
held the lane's whole share of the profile wall -- 2,700 s on thorough -- for the 480 requests
its last technique needed, so it ran at 6.25 s per request: on lab test targets every such
extension spent 1,181-1,219 s on 189-195 requests that the first slice's pace would have sent
in about 100 s. On thorough and deep the extension now holds what its remaining units are
predicted to need, never paced faster than a first slice (0.5 s per request), so the
target sees the first slice's load.

These are planner fixtures: synthetic settled results, no scanner process.
"""

from __future__ import annotations

import math
from types import SimpleNamespace

import pytest

from api.scan.external_process import BATCH_ATTEMPT_REQUEST_HEADROOM, paced_request_delay
from api.scan.sqli_concurrency import slice_rate_ceiling
from api.scan.external_process import batch_attempt_floor
from api.scan.verification_extension import (
    SQLI_EXTENSION_MINIMUM_SECONDS_PER_REQUEST,
    _with_slack,
    plan_verification_extensions,
)

THOROUGH = {"http_requests": 60_000, "state_changing_requests": 6_000, "tool_wall_seconds": 10_800}
DEEP = {"http_requests": 150_000, "state_changing_requests": 15_000, "tool_wall_seconds": 21_600}
BALANCED = {"http_requests": 20_000, "state_changing_requests": 2_000, "tool_wall_seconds": 3_600}
LIMITS = {"thorough": THOROUGH, "deep": DEEP, "balanced": BALANCED}
# A lab test target's query candidate, first slice: U, B and E settled in 136 s with 285 requests, then the
# 400-request hold stopped it before its time-based unit.
RESERVED = {"http_requests": 400, "tool_wall_seconds": 180}
CONSUMED = {"http_requests": 285, "tool_wall_seconds": 136}
SLICE = "verify.sqli.r01"


def _slice():
    return SimpleNamespace(
        action_id=SLICE, capability_name="sqli.verify_batch", stage="verify_candidates",
        capability_args={
            "slice": {"start": 0, "count": 1}, "continuation_work_key": "verify.sqli",
            "candidate_manifest_ref": {"kind": "candidate"},
        },
        dependencies=(), requested_budget=dict(RESERVED),
    )


def _request_bound(consumed=CONSUMED):
    return SimpleNamespace(
        status=SimpleNamespace(value="partial"),
        reason_code=SimpleNamespace(value="http_request_budget_exhausted"),
        budget_reserved=dict(RESERVED), budget_consumed=dict(consumed),
    )


def _extend(profile, *, remaining_wall, remaining_requests, resume_wall=None,
            consumed=CONSUMED):
    planned = plan_verification_extensions(
        parent_plan=SimpleNamespace(actions=(_slice(),)),
        parent_results={SLICE: _request_bound(consumed)},
        profile_limits=LIMITS[profile],
        residual=dict(LIMITS[profile]),
        stage_resume_walls={SLICE: resume_wall or remaining_wall},
        stage_remaining_walls={SLICE: remaining_wall},
        stage_remaining_requests={SLICE: remaining_requests},
        budget_profile=profile,
    )
    assert [item["action_id"] for item in planned] == [f"{SLICE}.ext"]
    return planned[0]["budget"]


# The time-based unit left: 189 requests at the measured 0.477 s per request, plus start-up.
TIME_BASED_UNIT = dict(remaining_wall=math.ceil(189 * 0.477) + 20, remaining_requests=189)


def test_the_pace_floor_is_a_first_slices_pace():
    assert SQLI_EXTENSION_MINIMUM_SECONDS_PER_REQUEST == pytest.approx(0.5)
    assert TIME_BASED_UNIT["remaining_wall"] == 111


def test_a_thorough_request_bound_extension_holds_what_its_technique_needs():
    budget = _extend("thorough", **TIME_BASED_UNIT)
    # Its remaining unit with slack is 171 s; 480 requests at a first slice's pace is 216 s.
    assert budget == {"http_requests": 480, "tool_wall_seconds": 216}
    delay, ceiling = paced_request_delay(480, 216, minimum_seconds=0.05)
    assert delay == pytest.approx(0.5) and ceiling == 480
    rate = slice_rate_ceiling(
        budget, candidates=1, floors=[batch_attempt_floor("sqli.verify_batch")],
    )
    assert rate == pytest.approx(2.0)


def test_before_the_change_the_same_slice_held_the_lane_share():
    """The 2.11.0 sizing, still what a Scan planned without a sufficiency profile gets."""
    planned = plan_verification_extensions(
        parent_plan=SimpleNamespace(actions=(_slice(),)),
        parent_results={SLICE: _request_bound()},
        profile_limits=THOROUGH, residual=dict(THOROUGH),
        stage_resume_walls={SLICE: 111}, stage_remaining_walls={SLICE: 111},
        stage_remaining_requests={SLICE: 189},
    )
    budget = planned[0]["budget"]
    assert budget == {"http_requests": 480, "tool_wall_seconds": 2_700}
    delay, _ceiling = paced_request_delay(480, 2_700, minimum_seconds=0.05)
    assert delay == pytest.approx(6.25)
    assert slice_rate_ceiling(
        budget, candidates=1, floors=[batch_attempt_floor("sqli.verify_batch")],
    ) == pytest.approx(0.16)


def test_deep_holds_the_same_need_instead_of_its_larger_share():
    assert _extend("deep", **TIME_BASED_UNIT) == {"http_requests": 480, "tool_wall_seconds": 216}


def test_balanced_keeps_its_lane_share():
    assert _extend("balanced", **TIME_BASED_UNIT)["tool_wall_seconds"] == 900


def test_a_slower_unit_gets_its_predicted_wall_with_slack():
    # A GraphQL test target: 333 requests left at 0.65 s.
    remaining_wall = math.ceil(333 * 0.65) + 20
    budget = _extend("thorough", remaining_wall=remaining_wall, remaining_requests=333)
    assert budget["http_requests"] == 480
    assert budget["tool_wall_seconds"] == _with_slack(remaining_wall) < 2_700


@pytest.mark.parametrize("profile", ["thorough", "deep"])
@pytest.mark.parametrize("latency", [0.0, 0.25, 0.477, 1.0, 2.0, 3.7, 5.0])
@pytest.mark.parametrize("remaining_requests", [53, 100, 189, 333, 500, 756])
def test_an_extension_is_never_paced_faster_than_a_first_slice_nor_held_past_its_need(
    profile, latency, remaining_requests,
):
    remaining_wall = math.ceil(remaining_requests * latency) + 20
    resume_wall = max(30, remaining_wall // 2)
    budget = _extend(
        profile, remaining_wall=remaining_wall, remaining_requests=remaining_requests,
        resume_wall=resume_wall,
        consumed={"http_requests": 285, "tool_wall_seconds": max(1, min(180, math.ceil(285 * latency)))},
    )
    http, wall = budget["http_requests"], budget["tool_wall_seconds"]
    pace = SQLI_EXTENSION_MINIMUM_SECONDS_PER_REQUEST * BATCH_ATTEMPT_REQUEST_HEADROOM
    assert wall >= pace * http, "never faster than 0.5 s per request"
    assert wall <= max(resume_wall, _with_slack(remaining_wall), math.ceil(pace * http))
    assert http == max(480, math.ceil(remaining_requests / BATCH_ATTEMPT_REQUEST_HEADROOM) + 1)
