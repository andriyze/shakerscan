"""A scan must be submittable on every profile it is offered on.

`POST /scans` pre-reserves a hold for the required capabilities before compiling the plan.
That hold was the SUM of every required capability's registry cost, which worked only
while no capability declared a mutation cost. The moment `xss.verify_batch` (1,000) and
`sqli.verify_batch` (1,800) declared theirs, the sum reached 3,000 against ceilings of
200 / 800 / 2,000 -- and every state-changing scan on every profile was rejected at
submission with "reserved_budget exceeds the plan budget", including the body-injection
path those costs were added to enable.

Two invariants, both missing before: the hold is the largest single required capability,
not the sum, and it never exceeds what the profile can actually set aside.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from runtime.capability_registry import CAPABILITY_REGISTRY  # noqa: E402
from scan.contracts import (  # noqa: E402
    BUDGET_PROFILES,
    SCAN_V2_FAMILY_NAMES,
    scan_family_required_capability,
)

API = (ROOT / "api" / "api.py").read_text(encoding="utf-8")


def _required_capabilities():
    named = [
        scan_family_required_capability(family) for family in SCAN_V2_FAMILY_NAMES
    ]
    return [name for name in named if name] + ["scan.finalize"]


def _costs():
    return {
        spec.name: dict(getattr(spec, "budget_cost", {}) or {})
        for spec in CAPABILITY_REGISTRY.list()
    }


def test_the_hold_fits_every_profile_in_every_dimension():
    costs = _costs()
    required = _required_capabilities()
    for profile, budget in BUDGET_PROFILES.items():
        limits = budget.ledger_limits()
        for dimension, ceiling in limits.items():
            largest = max(
                (int(costs.get(name, {}).get(dimension, 0)) for name in required),
                default=0,
            )
            held = min(largest, int(ceiling))
            assert held <= int(ceiling), (
                f"{profile}: holding {held} {dimension} against a {ceiling} ceiling"
            )


def test_the_submission_path_holds_the_maximum_not_the_sum():
    from scan.continuation import scan_submission_hold_budget

    class _Registry:
        pass

    import scan.continuation as continuation
    original = continuation.policy_constrained_hold_budget
    try:
        holds = {
            "a": {"state_changing_requests": 1_800, "http_requests": 100},
            "b": {"state_changing_requests": 1_000, "http_requests": 900},
        }
        continuation.policy_constrained_hold_budget = (
            lambda registry, name, **kw: holds[name]
        )
        held = scan_submission_hold_budget(
            _Registry(), ("a", "b"),
            allow_state_changing_http=True,
            limits={"state_changing_requests": 2_000, "http_requests": 20_000},
        )
        # The largest of each dimension, never their sum (2,800 / 1,000).
        assert held == {"state_changing_requests": 1_800, "http_requests": 900}

        # And capped at what the profile owns.
        capped = scan_submission_hold_budget(
            _Registry(), ("a", "b"),
            allow_state_changing_http=True,
            limits={"state_changing_requests": 200, "http_requests": 1_000},
        )
        assert capped == {"state_changing_requests": 200, "http_requests": 900}
    finally:
        continuation.policy_constrained_hold_budget = original


def test_required_capabilities_are_verified_independently_not_cumulatively():
    """The second loop consumed the residual as it went, re-imposing the sum.

    Each required capability must be shown to fit; they are not required to fit
    simultaneously, which no profile sizes the mutation dimension for.
    """
    block = API[API.index('for capability_name in required_holds:'):]
    block = block[:block.index("parent_plan = parent_allocation.plan")]
    assert "raise ScanBudgetAllocationError(capability_name, shortages)" in block
    assert "remaining[name] = remaining.get(name, 0) - amount" not in block, (
        "the residual is consumed per capability again, which enforces the sum"
    )


def test_a_costly_new_capability_cannot_make_a_profile_unsubmittable():
    """The regression in one line: a capability far above every ceiling."""
    costs = dict(_costs())
    costs["hypothetical.expensive"] = {"state_changing_requests": 10_000}
    required = _required_capabilities() + ["hypothetical.expensive"]
    for profile, budget in BUDGET_PROFILES.items():
        ceiling = int(budget.ledger_limits()["state_changing_requests"])
        largest = max(
            int(costs.get(name, {}).get("state_changing_requests", 0))
            for name in required
        )
        assert min(largest, ceiling) <= ceiling, profile


# --- A bounded active scan that also replays a request collection ---------------
#
# The hold kept for the deferred verifier (sqli/xss.verify_batch) is the whole
# state-changing budget on a small profile. A request-collection replay is a
# REQUIRED admission action that runs in the parent plan, not the continuation, so
# the hold must leave room for it -- otherwise `inputs.collection_00 exceeds the
# plan budget: {'state_changing_requests': 1}` rejects the scan. And the deferred
# verifier's own registry cost (1,800) exceeds every bounded ceiling, so the
# continuation check must accept the reviewed scaled tier instead of the full cost.


def test_a_bounded_active_verifier_is_satisfied_by_its_reviewed_scaled_tier():
    """sqli.verify_batch costs 1,800 state-changing; no bounded profile owns that.

    The continuation check must accept the reviewed query-only tier (zero
    state-changing) so a bounded active scan is not rejected for a verifier it can
    still run at reduced breadth. Without that, every active sqli/xss scan under a
    ceiling below 1,800 is refused at submission.
    """
    from scan.external_process import fit_reservation_scaled_profile

    cost = dict(CAPABILITY_REGISTRY.require("sqli.verify_batch").budget_cost)
    assert int(cost.get("state_changing_requests", 0)) > 200, (
        "the premise is a verifier cost larger than any bounded ceiling"
    )
    # A tight residual: one state-changing request already spent by a required
    # collection replay, with http headroom intact.
    residual = {
        "http_requests": 1_990,
        "state_changing_requests": 9,
        "tool_wall_seconds": 800,
    }
    tier = fit_reservation_scaled_profile(
        "sqli.verify_batch", requested=cost, available=residual,
    )
    assert tier is not None, "no reviewed tier fits the bounded residual"
    assert int(tier.get("state_changing_requests", 0)) == 0, (
        "the query-only tier must not require state-changing budget"
    )
    assert all(int(tier[d]) <= int(residual.get(d, 0)) for d in tier)


def test_the_continuation_check_admits_a_scaled_tier_not_only_the_full_cost():
    """The check compared the full registry cost to the residual; on a small profile
    that is always short, so it must first try a reviewed scaled tier."""
    block = API[API.index('for capability_name in required_holds:'):]
    block = block[:block.index("parent_plan = parent_allocation.plan")]
    assert "fit_reservation_scaled_profile(" in block, (
        "the continuation check rejects any bounded active verifier because it does "
        "not fall back to the reviewed scaled tier"
    )
    assert "effective_hold" in block


def test_the_hold_is_reduced_by_required_parent_admission_traffic():
    """The reserve must subtract the required admission cost so a required
    request-collection replay is never starved by the deferred verifier hold."""
    authority = API[API.index("def _compile_scan_admission_action_authority"):]
    authority = authority[:authority.index("parent_plan = parent_allocation.plan")]
    assert "required_admission_cost" in authority
    assert "MANDATORY_ACTION_IDS" in authority
    # The reserve is capped at ledger room AFTER required admission, not the raw hold.
    assert "ledger_limits.get(name, 0) - required_admission_cost.get(name, 0)" in authority


def test_reserve_arithmetic_leaves_room_for_a_required_collection_replay():
    """Demonstrate the reduction: a capped 10/10 hold minus a 1-request replay
    admission leaves 9 reserved, and 9 + 1 fits the 10-request ceiling."""
    import scan.continuation as continuation

    original = continuation.policy_constrained_hold_budget
    try:
        continuation.policy_constrained_hold_budget = (
            lambda registry, name, **kw: {
                "state_changing_requests": 1_800, "http_requests": 1_800,
            }
        )
        limits = {"state_changing_requests": 10, "http_requests": 2_000}
        hold = continuation.scan_submission_hold_budget(
            object(), ("sqli.verify_batch",),
            allow_state_changing_http=True, limits=limits,
        )
        assert hold["state_changing_requests"] == 10  # the whole bounded budget
        required_admission = {"state_changing_requests": 1, "http_requests": 3}
        reserved = {
            name: min(
                amount,
                max(0, limits.get(name, 0) - required_admission.get(name, 0)),
            )
            for name, amount in hold.items()
        }
        assert reserved["state_changing_requests"] == 9
        assert (
            reserved["state_changing_requests"]
            + required_admission["state_changing_requests"]
        ) <= limits["state_changing_requests"]
    finally:
        continuation.policy_constrained_hold_budget = original
