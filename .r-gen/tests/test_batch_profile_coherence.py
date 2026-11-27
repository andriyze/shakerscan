"""A batch must be able to pay for the slice it declares.

The slice sizes and the reservations were sized independently, so every profile
promised more candidates per batch than its own budget funded at the
per-attempt floor: thorough declared 50 XSS candidates on a budget for 8, fast
declared 5 on a budget for 1. A required verifier therefore always left most of
its slice unattempted, reported its family partial, and marked the grade
unreliable -- on every scan, on every profile, not just on one benchmark.
"""
from __future__ import annotations

import pytest

from api.scan.action_plan import _BATCH_PROFILES, batch_profile_shape
from api.scan.contracts import BUDGET_PROFILES, resolve_scan_contract
from api.scan.external_process import (
    BATCH_ATTEMPT_BODY_FLOORS,
    BATCH_ATTEMPT_FLOORS,
    batch_attempt_capacity,
)


_CASES = [
    (profile, capability)
    for profile in sorted(_BATCH_PROFILES)
    for capability in sorted(BATCH_ATTEMPT_FLOORS)
]


@pytest.mark.parametrize("profile,capability", _CASES, ids=lambda v: str(v))
def test_a_slice_is_fundable_by_its_own_reservation(profile, capability):
    slice_size, budget = _BATCH_PROFILES[profile][capability]
    floor = BATCH_ATTEMPT_FLOORS[capability]
    for dimension, per_attempt in floor.items():
        required = slice_size * per_attempt
        assert budget.get(dimension, 0) >= required, (
            f"{profile}/{capability} declares {slice_size} candidates but its "
            f"{dimension} reservation ({budget.get(dimension, 0)}) funds only "
            f"{budget.get(dimension, 0) // per_attempt}"
        )


@pytest.mark.parametrize("profile,capability", _CASES, ids=lambda v: str(v))
def test_the_declared_slice_matches_what_the_budget_buys(profile, capability):
    """No silent waste either: an oversized reservation starves other families."""
    slice_size, budget = _BATCH_PROFILES[profile][capability]
    assert batch_attempt_capacity(capability, dict(budget)) >= slice_size


@pytest.mark.parametrize("profile", sorted(_BATCH_PROFILES))
def test_one_batch_of_each_verifier_fits_the_profile_wall(profile):
    """The verifiers a standard active scan selects must fit the ceiling together."""
    contract = resolve_scan_contract(
        budget_profile=profile,
        policy={
            "active_testing": True,
            "preset": "custom",
            "include_families": ["recon", "xss", "sqli"],
        },
        approval_receipt_id="a" * 32,
    )
    ceiling = contract.budget.ledger_limits()["tool_wall_seconds"]
    needed = sum(
        _BATCH_PROFILES[profile][capability][1]["tool_wall_seconds"]
        for capability in ("xss.verify_batch", "sqli.verify_batch")
    )
    assert needed <= ceiling, (
        f"{profile}: one XSS and one SQLi batch need {needed}s of a {ceiling}s wall"
    )


def test_batch_occurrences_project_to_the_action_the_parent_authorised():
    """A child may slice its work into more batches than the parent did.

    Two suffixes are occurrence markers rather than distinct authority: a
    five-digit per-endpoint occurrence and a three-digit batch index. Only the
    first was recognised, so once slices were sized to what their reservation
    funds a child produced `verify.xss.001` and the whole partition was rejected
    as introducing an action outside parent authority.
    """
    from api.scan.parallel_compiler import _projection_id

    assert _projection_id("verify.xss") == "verify.xss"
    assert _projection_id("verify.xss.001") == "verify.xss"
    assert _projection_id("verify.xss.00000") == "verify.xss"
    assert _projection_id("verify.xss.001.00000") == "verify.xss"
    # Ids that merely end in digits are not occurrence markers.
    assert _projection_id("baseline.http") == "baseline.http"
    assert _projection_id("verify.xss.1") == "verify.xss.1"
    assert _projection_id("verify.xss.0001") == "verify.xss.0001"


# --- A slice must be able to fund the most expensive candidate it can contain -----------------
# The rule above sizes each slice to the QUERY floor exactly, which is coherent only while every
# candidate costs the same. A body-field candidate does not: measured, it needs 480 requests and
# 420 seconds against 160 and 30 for a query parameter. A slice sized to the query floor therefore
# could not fund a single body attempt, so the scanner planned body candidates it could never run
# and reported them unattempted forever.

# Every profile from `balanced` up is sized for a body attempt; only `fast` (a 25-minute tool
# wall) deliberately is not.
_BODY_CASES = [(profile, "sqli.verify_batch") for profile in ("balanced", "thorough", "deep")]


@pytest.mark.parametrize("profile,capability", _BODY_CASES, ids=lambda v: str(v))
def test_a_slice_can_fund_at_least_one_body_attempt(profile, capability):
    """One body attempt plus the rest at the query floor must fit the reservation.

    Guaranteeing one -- not all -- is the deliberate trade. A slice sized for every candidate being
    a body attempt would collapse breadth, and the manifest is ranked, so the expensive work that
    does run is the work most likely to matter. Anything beyond that is reported unattempted.
    """
    slice_size, budget = batch_profile_shape(
        profile, capability, allow_state_changing_http=True,
    )
    query_floor = BATCH_ATTEMPT_FLOORS[capability]
    body_floor = BATCH_ATTEMPT_BODY_FLOORS[capability]
    for dimension, body_amount in body_floor.items():
        required = (slice_size - 1) * query_floor.get(dimension, 0) + body_amount
        assert budget.get(dimension, 0) >= required, (
            f"{profile}/{capability} reserves {budget.get(dimension, 0)} {dimension} but funding "
            f"one body attempt beside {slice_size - 1} query attempts needs {required}"
        )


def test_body_attempts_are_funded_once_mutation_is_authorized():
    """A verifier slice never pre-holds a body attempt: `fast` stays a short query slice, and no
    profile carries the 420-second body cost in its base shape. Once state-changing HTTP is
    authorized the slice is expanded to fund at least one body attempt on every profile, so a
    ranked login body is attempted instead of reported unattempted forever.
    """
    body_wall = BATCH_ATTEMPT_BODY_FLOORS["sqli.verify_batch"]["tool_wall_seconds"]
    assert _BATCH_PROFILES["fast"]["sqli.verify_batch"][1]["tool_wall_seconds"] < body_wall
    for profile in sorted(_BATCH_PROFILES):
        _size, budget = batch_profile_shape(
            profile, "sqli.verify_batch", allow_state_changing_http=True,
        )
        assert budget["tool_wall_seconds"] >= body_wall, profile
        assert budget["state_changing_requests"] >= BATCH_ATTEMPT_BODY_FLOORS["sqli.verify_batch"]["state_changing_requests"], profile


def test_every_raised_batch_still_fits_its_profile_wall():
    # Raising a batch budget past what the plan can hold would fail admission outright, which is
    # how "reserved_budget exceeds the plan budget" is produced.
    for profile in ("balanced", "thorough", "deep"):
        ceiling = BUDGET_PROFILES[profile].max_tool_wall_seconds
        for capability in ("sqli.verify_batch", "xss.verify_batch"):
            _size, budget = _BATCH_PROFILES[profile][capability]
            assert budget["tool_wall_seconds"] <= ceiling, (profile, capability)


def test_every_candidate_holds_its_measured_time_on_every_profile():
    """Bigger profiles buy more candidates, never less time per candidate."""
    from api.scan.action_plan import _BATCH_ATTEMPT_COSTS

    for profile, shapes in _BATCH_PROFILES.items():
        for capability, (size, budget) in shapes.items():
            cost = _BATCH_ATTEMPT_COSTS[capability]
            for dimension, per_attempt in cost.items():
                assert budget[dimension] >= size * per_attempt, (profile, capability, dimension)
    # The external verifiers hold what the tools were measured to need, not the 30 s floor.
    for profile in _BATCH_PROFILES:
        size, budget = _BATCH_PROFILES[profile]["xss.verify_batch"]
        assert budget["tool_wall_seconds"] // size >= 200, profile
        size, budget = _BATCH_PROFILES[profile]["sqli.verify_batch"]
        assert budget["tool_wall_seconds"] // size >= 180, profile


def test_larger_profiles_fund_more_external_verifier_candidates_and_wall():
    for capability in ("xss.verify_batch", "sqli.verify_batch"):
        shapes = [_BATCH_PROFILES[name][capability] for name in BUDGET_PROFILES]
        assert [shape[0] for shape in shapes] == sorted(shape[0] for shape in shapes)
        assert [shape[1]["tool_wall_seconds"] for shape in shapes] == sorted(
            shape[1]["tool_wall_seconds"] for shape in shapes
        )
    assert _BATCH_PROFILES["thorough"]["xss.verify_batch"][0] > _BATCH_PROFILES["balanced"]["xss.verify_batch"][0]
    assert _BATCH_PROFILES["deep"]["sqli.verify_batch"][0] > _BATCH_PROFILES["thorough"]["sqli.verify_batch"][0]


def test_one_batch_of_everything_fits_and_leaves_the_rounds_something_to_spend():
    """One batch per capability plus a second active sweep never exceeds the ceiling.

    The root plan is deliberately not sized to consume the whole wall in one pass: the
    bounded continuation rounds keep planning further slices until the reconciled
    residual cannot fund a fast-tier batch, so a large profile spends its ceiling on
    breadth across rounds instead of front-loading one oversized slice per lane.
    """
    for profile, shapes in _BATCH_PROFILES.items():
        wall = sum(
            int(budget.get("tool_wall_seconds", 0))
            for _size, budget in shapes.values()
        ) + int(shapes["templates.active_batch"][1]["tool_wall_seconds"])
        ceiling = BUDGET_PROFILES[profile].max_tool_wall_seconds
        assert wall <= ceiling, (profile, wall, ceiling)
        assert wall * 100 >= ceiling * 50, (profile, wall, ceiling)
