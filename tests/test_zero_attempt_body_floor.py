"""A request-body candidate a thorough slice could never fund is funded, or extended at its floor.

Two shapes of the same fault, from 2.11 lab runs (these tests use planner fixtures, not live
Scans; the adapter half is ``test_body_floor_attempts.py``):

* A tier-shaped slice is sized linearly from its tier: a thorough SQLi slice holding one
  request-body candidate held 400 requests and 180 s, under the body floor of 480 requests,
  480 mutations and 420 s. The adapter refused the candidate before any traffic, the slice
  settled partial with nothing sent, and -- with no latency measured -- it was never extended
  (DVGA: 10 of 10 runs).
* A slice that fell to the floor tier holds one query attempt (160 requests, 30 s, no mutation
  hold), so every body candidate in it is refused the same way (VAmPI: 0 of 14 SQLi bodies).

On thorough and deep the first slice now holds one body attempt beside its query candidates
when its tier can afford it, and a slice whose holds funded no attempt is extended once at the
body floor of the body candidates it holds, as far as the residual funds them.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from api.scan.action_plan import slice_body_attempt_floor
from api.scan.external_process import batch_attempt_floor
from api.scan.verification_extension import (
    EXTENDS_ARG,
    _zero_attempt_floor,
    plan_verification_extensions,
)
from tests.scan_round_fixtures import (
    admitted_round_fixture,
    appended_actions,
    compile_round,
    settle_round,
)

VERIFIERS = ("recon", "nuclei_passive", "xss", "sqli")
THOROUGH = {"http_requests": 60_000, "state_changing_requests": 6_000, "tool_wall_seconds": 10_800}
BALANCED = {"http_requests": 20_000, "state_changing_requests": 2_000, "tool_wall_seconds": 3_600}
DIGEST = "d" * 64


def _first_round(profile, **shape):
    fixture = admitted_round_fixture(profile, families=VERIFIERS, **shape)
    settle_round(fixture)
    parent_count = len(fixture["parent_plan"].actions)
    return appended_actions(compile_round(fixture, 1), parent_count)


def _by_capability(actions, capability):
    return [action for action in actions if action.capability_name == capability]


def test_a_thorough_slice_holding_one_body_candidate_holds_a_body_attempt():
    sqli, = _by_capability(_first_round("thorough", endpoints=2, queries=0, body=1), "sqli.verify_batch")
    assert dict(sqli.requested_budget) == {
        "http_requests": 480, "state_changing_requests": 480, "tool_wall_seconds": 420,
    }
    # Its tier (3,200 requests / 1,440 s per eight candidates) had already been found
    # affordable; the slice holds the body floor within it, not more.
    assert dict(sqli.requested_budget) == batch_attempt_floor("sqli.verify_batch", body_candidate=True)


def test_a_mixed_slice_holds_its_query_floors_and_one_body_attempt():
    floor = slice_body_attempt_floor(
        "sqli.verify_batch",
        {"candidate_manifest_ref": {"manifest_digest": DIGEST}, "slice": {"start": 0, "count": 3}},
        (DIGEST, frozenset({2})),
    )
    query = batch_attempt_floor("sqli.verify_batch")
    body = batch_attempt_floor("sqli.verify_batch", body_candidate=True)
    assert floor == {
        name: 2 * query[name] + body[name] for name in ("http_requests", "tool_wall_seconds")
    }
    # A slice of query candidates, or one of unknown composition, needs nothing more.
    assert slice_body_attempt_floor(
        "sqli.verify_batch",
        {"candidate_manifest_ref": {"manifest_digest": DIGEST}, "slice": {"start": 0, "count": 3}},
        (DIGEST, frozenset({7})),
    ) == {}
    assert slice_body_attempt_floor(
        "sqli.verify_batch",
        {"candidate_manifest_ref": {"manifest_digest": "e" * 64}, "slice": {"start": 0, "count": 1}},
        (DIGEST, frozenset({0})),
    ) == {}


def test_a_tier_shaped_xss_slice_already_funds_its_body_candidate():
    """Dalfox's per-candidate tier cost (700 requests, 200 s) is above its body floor (240,
    120 s), so a tier-shaped XSS slice never needed the raise; it is what it was."""
    xss, = _by_capability(_first_round("thorough", endpoints=2, queries=0, body=1), "xss.verify_batch")
    assert dict(xss.requested_budget) == {
        "http_requests": 700, "state_changing_requests": 240, "tool_wall_seconds": 200,
    }


def test_a_floor_shaped_lane_stays_at_the_query_floor():
    """Fourteen body candidates behind a required active sweep: the SQLi lane falls to the floor
    tier, whose shape has no room for a body attempt, and its slices keep that shape."""
    fixture = admitted_round_fixture(
        "thorough", endpoints=30, queries=0, body=14,
        families=("recon", "nuclei_passive", "nuclei_active", "xss", "sqli"),
    )
    settle_round(fixture)
    parent_count = len(fixture["parent_plan"].actions)
    actions = appended_actions(compile_round(fixture, 1), parent_count)
    floor_shaped = [
        action for action in _by_capability(actions, "sqli.verify_batch")
        if dict(action.requested_budget) == batch_attempt_floor("sqli.verify_batch")
    ]
    assert len(floor_shaped) >= 10


def _floor_slice(action_id="verify.sqli.r01", capability="sqli.verify_batch", *, count=1,
                 extends=None):
    args = {
        "slice": {"start": 0, "count": count},
        "candidate_manifest_ref": {"kind": "candidate", "manifest_digest": DIGEST},
        "continuation_work_key": "verify.sqli",
    }
    if extends:
        args[EXTENDS_ARG] = extends
    return SimpleNamespace(
        action_id=action_id, capability_name=capability, stage="verify_candidates",
        capability_args=args, dependencies=(),
        requested_budget=dict(batch_attempt_floor(capability)),
    )


def _refused(capability="sqli.verify_batch"):
    return SimpleNamespace(
        status=SimpleNamespace(value="partial"),
        reason_code=SimpleNamespace(value="state_changing_budget_exhausted"),
        budget_reserved=dict(batch_attempt_floor(capability)),
        budget_consumed={name: 0 for name in batch_attempt_floor(capability)},
    )


def _extend(actions, results, *, profile="thorough", residual=None, bodies=frozenset({0})):
    limits = THOROUGH if profile in {"thorough", "deep"} else BALANCED
    return plan_verification_extensions(
        parent_plan=SimpleNamespace(actions=tuple(actions)), parent_results=results,
        profile_limits=limits, residual=dict(residual or limits),
        budget_profile=profile, body_positions=(DIGEST, bodies),
    )


@pytest.mark.parametrize("capability", ["sqli.verify_batch", "xss.verify_batch"])
def test_a_slice_that_funded_no_attempt_is_extended_at_the_body_floor(capability):
    action = _floor_slice(capability=capability)
    planned = _extend([action], {action.action_id: _refused(capability)})
    assert [item["action_id"] for item in planned] == [f"{action.action_id}.ext"]
    assert planned[0]["capability_args"][EXTENDS_ARG] == action.action_id
    # The mutation hold is there although the slice held none.
    assert planned[0]["budget"] == batch_attempt_floor(capability, body_candidate=True)


def test_the_floor_extension_funds_as_many_body_attempts_as_the_residual_does():
    action = _floor_slice(count=3)
    results = {action.action_id: _refused()}
    every = _extend([action], results, bodies=frozenset({0, 1, 2}))
    assert every[0]["budget"] == {"http_requests": 1_440, "state_changing_requests": 1_440,
                                  "tool_wall_seconds": 1_260}
    bounded = _extend(
        [action], results, bodies=frozenset({0, 1, 2}),
        residual={**THOROUGH, "state_changing_requests": 1_000},
    )
    # 1,000 // 480: two body attempts.
    assert bounded[0]["budget"] == {"http_requests": 960, "state_changing_requests": 960,
                                    "tool_wall_seconds": 840}
    assert _extend(
        [action], results, bodies=frozenset({0, 1, 2}),
        residual={**THOROUGH, "state_changing_requests": 479},
    ) == ()


def test_how_many_body_attempts_a_floor_extension_asks_for_is_what_the_residual_funds():
    """Before the round's lanes share anything, a floor extension asks only for the body
    attempts the Scan's residual requests, mutations and the lane's round share fund."""
    action = _floor_slice(count=3)
    floor = batch_attempt_floor("sqli.verify_batch", body_candidate=True)

    def attempts(*, wall_ceiling=2_700, **remaining):
        return _zero_attempt_floor(
            action, _refused(), body_positions=(DIGEST, frozenset({0, 1, 2})),
            remaining={"http_requests": 60_000, "state_changing_requests": 6_000, **remaining},
            wall_ceiling=wall_ceiling,
        )

    assert attempts() == (floor, 3)
    assert attempts(state_changing_requests=960) == (floor, 2)
    assert attempts(state_changing_requests=479) is None
    assert attempts(http_requests=959) == (floor, 1)
    assert attempts(wall_ceiling=839) == (floor, 1)
    assert attempts(wall_ceiling=419) is None


def test_a_slice_of_query_candidates_or_one_that_sent_traffic_is_not_floor_extended():
    action = _floor_slice()
    assert _extend([action], {action.action_id: _refused()}, bodies=frozenset()) == ()
    # A slice that sent traffic measured the target: it is extended, if at all, by the
    # latency rules, never at the floor (Dalfox restarts, so an XSS one is not).
    xss = _floor_slice("verify.xss.r01", "xss.verify_batch")
    measured = SimpleNamespace(**{
        **vars(_refused("xss.verify_batch")),
        "budget_consumed": {"http_requests": 12, "tool_wall_seconds": 30},
    })
    assert _extend([xss], {xss.action_id: measured}) == ()


def test_a_floor_extension_is_planned_once_per_slice():
    original = _floor_slice()
    extension = _floor_slice("verify.sqli.r01.ext.r02", extends=original.action_id)
    results = {original.action_id: _refused(), extension.action_id: _refused()}
    # The slice is already extended, and a chained link is never floor-extended again.
    assert _extend([original, extension], results) == ()
    xss = _floor_slice("verify.xss.r01", "xss.verify_batch")
    xss_link = _floor_slice("verify.xss.r01.ext.r02", "xss.verify_batch", extends=xss.action_id)
    assert _extend([xss, xss_link], {
        xss.action_id: _refused("xss.verify_batch"),
        xss_link.action_id: _refused("xss.verify_batch"),
    }) == ()


@pytest.mark.parametrize("profile", ["fast", "balanced"])
def test_fast_and_balanced_keep_such_a_slice_unextended(profile):
    action = _floor_slice()
    assert _extend([action], {action.action_id: _refused()}, profile=profile) == ()


def test_the_round_compiler_floor_extends_a_body_heavy_api():
    """Fourteen SQLi body candidates in floor-shaped slices, none attempted in round 1: round
    2 extends them at the body floor while the mutation residual lasts."""
    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
    from tests.scan_round_fixtures import settle_lightly

    fixture = admitted_round_fixture(
        "thorough", endpoints=30, queries=0, body=14,
        families=("recon", "nuclei_passive", "nuclei_active", "xss", "sqli"),
    )
    settle_round(fixture)
    compile_round(fixture, 1)

    def refused(action):
        if action.capability_name in {"sqli.verify_batch", "xss.verify_batch"}:
            return (CapabilityResultStatus.PARTIAL,
                    CapabilityResultReason.STATE_CHANGING_BUDGET_EXHAUSTED, {})
        if action.capability_name == "templates.active_batch":
            return (CapabilityResultStatus.SUCCESS, None, dict(action.requested_budget))
        return settle_lightly(action)

    settle_round(fixture, refused)
    parent_count = len(fixture["parent_plan"].actions)
    appended = appended_actions(compile_round(fixture, 2), parent_count)
    floors = [
        action for action in appended
        if action.capability_name == "sqli.verify_batch" and action.capability_args.get(EXTENDS_ARG)
    ]
    assert floors
    assert all(
        dict(action.requested_budget) == batch_attempt_floor("sqli.verify_batch", body_candidate=True)
        for action in floors
    )
