"""A continuation lane appends a contiguous prefix of its slices in each round.

The next round resumes a lane after the furthest slice the previous round appended
(``continuation_manifest_offsets``). When the residual funded a small trailing slice
behind larger skipped ones, the offset moved past the skipped slices and their manifest
entries were never scheduled: a thorough Scan's passive pack stopped at 101 of 201
discovered routes.
"""

from __future__ import annotations

import pytest



def _slice_action(action_id, ordinal, start, count, *, status="planned"):
    import dataclasses

    from tests.test_scan_orchestrator import _action

    return dataclasses.replace(
        _action(action_id, ordinal, capability_name="templates.passive_batch"),
        capability_args={
            "slice": {"start": start, "count": count},
            "continuation_work_key": "passive.templates",
        },
        admission_status=status,
        reason_code=None if status == "planned" else "insufficient_plan_budget",
        action_digest=None,
    )


@pytest.mark.parametrize("skipped", [1, 2])
def test_a_slice_behind_a_skipped_one_waits_for_the_next_round(skipped):
    from api.scan.action_plan import ScanActionPlan
    from api.scan.continuation import continuation_manifest_offsets
    from api.scan.continuation_rounds import select_continuation_actions
    from tests.test_scan_orchestrator import SCAN_ID

    slices = [
        _slice_action(
            f"passive.templates{'' if index == 0 else f'.{index:03d}'}.r02", index,
            index * 50, 50 if index < 3 else 1,
            status="skipped" if index == skipped else "planned",
        )
        for index in range(4)
    ]
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64, target_binding_digest="a" * 64,
        actions=tuple(slices),
    )

    selected = select_continuation_actions(
        plan, parent_action_count=0, include_finalizer=False, finalize_only=False,
    )

    kept = [action.capability_args["slice"]["start"] for action in selected.actions]
    assert kept == [index * 50 for index in range(skipped)]
    # The next round resumes at the first slice this one could not fund.
    assert continuation_manifest_offsets(selected) == {"passive.templates": skipped * 50}
