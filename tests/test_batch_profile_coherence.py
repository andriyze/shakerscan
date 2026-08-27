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

from api.scan.action_plan import _BATCH_PROFILES
from api.scan.contracts import resolve_scan_contract
from api.scan.external_process import BATCH_ATTEMPT_FLOORS, batch_attempt_capacity


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
