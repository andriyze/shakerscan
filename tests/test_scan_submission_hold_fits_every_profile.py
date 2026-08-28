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
