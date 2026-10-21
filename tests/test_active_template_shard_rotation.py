"""Parallel endpoint children rotate the active-template windows instead of interleaving them.

Planner fixtures through the real ParallelActionPlanCompiler.plan_parent, with the sweep mapping
the adapter uses (``nuclei_execution.active_sweep_index``); no scanner process runs. 2.11.0 ran
window p % 39 at every child's position p, so each child ran its first min(E, 39) windows and the
children of a lane together ran the windows of the largest one. An interleaved split (pair
p x n + k) ran fewer: n counts the global child at index 0, the family children that never sweep
and every lane. Each endpoint child now starts at its own offset around the pairs: alone it runs
as many windows as 2.11.0 gave it, and the children of a lane together run at least as many.
"""

from __future__ import annotations

import pytest

from api.runtime.models import TargetBinding
from api.scan.action_plan import ScanActionPlanCompiler
from api.scan.budget_allocator import allocate_scan_action_plan
from api.scan.contracts import resolve_scan_contract
from api.scan.nuclei_execution import active_sweep_index
from api.scan.parallel_compiler import (
    ParallelActionPlanCompiler,
    ParallelPlacementCapacity,
    ParallelPrincipalLane,
)
from api.scan.work_manifests import build_canonical_scan_nuclei_template_manifest

PARENT_ID = "10000000-0000-4000-8000-000000000001"
WINDOWS = 39
TARGET = TargetBinding(
    target_id="target-1", target_kind="web", canonical_host="example.test",
    allowed_origins=("https://example.test",), allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("example.test",),
)
LANES = {
    "scope": (ParallelPrincipalLane("anonymous"),),
    "family": (ParallelPrincipalLane("anonymous"),),
    "two-lane": (
        ParallelPrincipalLane("primary", ("profile-primary",)),
        ParallelPrincipalLane("secondary", ("profile-secondary",)),
    ),
}


def _authority():
    contract = resolve_scan_contract(
        budget_profile="thorough",
        policy={"active_testing": True, "include_families": ["xss", "sqli", "nuclei_active"]},
    )
    templates = build_canonical_scan_nuclei_template_manifest(
        scan_id=PARENT_ID, target_binding_digest=TARGET.digest, include_active=True,
    )
    raw = ScanActionPlanCompiler().compile(
        scan_id=PARENT_ID, execution_plan=contract.execution_plan, target_binding=TARGET,
        template_manifest_ref=templates.reference().canonical_dict(),
    )
    return contract.execution_plan, allocate_scan_action_plan(raw, contract.budget).plan


def _plan(endpoints, topology):
    execution, parent = _authority()
    return ParallelActionPlanCompiler().plan_parent(
        parent_execution_plan=execution, parent_action_plan=parent, target_binding=TARGET,
        endpoint_manifest_entries=tuple(f"GET /p{index}" for index in range(endpoints)),
        principal_lanes=LANES[topology],
        placements=(ParallelPlacementCapacity("local", 5, {"node_scope": "local"}),),
        scheduling_hint="family" if topology == "family" else "scope",
    )


def _sweeps(child):
    return child.role == "endpoint" and (not child.family_scope or "nuclei_active" in child.family_scope)


def _coverage(planned):
    """Per lane: windows 2.11.0 ran, windows the rotation runs, and the rotation's repeats."""
    count = len(planned.children)
    lanes: dict[str, dict[str, object]] = {}
    for child in planned.children:
        if not _sweeps(child):
            continue
        lane = lanes.setdefault(child.principal_lane.name, {"old": set(), "new": set(), "runs": 0})
        positions = range(len(child.endpoints))
        lane["old"] |= {position % WINDOWS for position in positions}
        mine = [
            active_sweep_index(position, shard_index=child.index, shard_count=count, pair_count=WINDOWS)
            for position in positions
        ]
        ran = [index for index in mine if index is not None]
        # Alone, a child never runs a pair twice and runs min(E, 39) of them.
        assert len(ran) == len(set(ran)) == min(len(child.endpoints), WINDOWS)
        lane["new"] |= set(ran)
        lane["runs"] += len(ran)
    return {
        name: (len(lane["old"]), len(lane["new"]), lane["runs"] - len(lane["new"]))
        for name, lane in lanes.items()
    }


# Measured with this compiler (thorough, 5 local slots): per lane, (windows 2.11.0 ran, windows
# the rotation runs, pairs two children of the lane both ran).
MEASURED = {
    (20, "scope"): {"anonymous": (5, 20, 0)},
    (40, "scope"): {"anonymous": (10, 37, 3)},
    (60, "scope"): {"anonymous": (15, 39, 21)},
    (138, "scope"): {"anonymous": (35, 39, 99)},
    (215, "scope"): {"anonymous": (39, 39, 117)},
    (20, "family"): {"anonymous": (20, 20, 0)},
    (40, "family"): {"anonymous": (39, 39, 0)},
    (60, "family"): {"anonymous": (39, 39, 0)},
    (138, "family"): {"anonymous": (39, 39, 0)},
    (215, "family"): {"anonymous": (39, 39, 0)},
    (20, "two-lane"): {"primary": (10, 19, 1), "secondary": (10, 19, 1)},
    (40, "two-lane"): {"primary": (20, 29, 11), "secondary": (20, 29, 11)},
    (60, "two-lane"): {"primary": (30, 39, 21), "secondary": (30, 39, 21)},
    (138, "two-lane"): {"primary": (39, 39, 39), "secondary": (39, 39, 39)},
    (215, "two-lane"): {"primary": (39, 39, 39), "secondary": (39, 39, 39)},
}


@pytest.mark.parametrize(("endpoints", "topology"), sorted(MEASURED))
def test_rotated_children_never_run_fewer_windows_than_2_11_0(endpoints, topology):
    planned = _plan(endpoints, topology)
    coverage = _coverage(planned)
    assert coverage == MEASURED[(endpoints, topology)]
    for _lane, (old, new, _repeated) in coverage.items():
        assert new >= old
        assert new <= WINDOWS


def test_the_global_child_and_a_direct_scan_run_pairs_from_the_start():
    assert [active_sweep_index(p, shard_index=None, shard_count=None, pair_count=39) for p in (0, 38, 39)] == [0, 38, None]
    assert active_sweep_index(5, shard_index=0, shard_count=4, pair_count=39) == 5


def test_endpoint_children_start_apart_and_wrap_without_repeating_themselves():
    # Three endpoint children (shard count 4): offsets 0, 13, 26.
    assert [active_sweep_index(0, shard_index=k, shard_count=4, pair_count=39) for k in (1, 2, 3)] == [0, 13, 26]
    assert [active_sweep_index(p, shard_index=3, shard_count=4, pair_count=39) for p in (12, 13, 38, 39)] == [38, 0, 25, None]
