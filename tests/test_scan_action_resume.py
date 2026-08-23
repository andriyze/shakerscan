from __future__ import annotations

import pytest


@pytest.mark.xfail(
    strict=True,
    reason="V2-P2: action-level durable resume still needs the immutable plan and terminal receipts",
)
def test_resume_schedules_only_nonterminal_actions_from_the_persisted_plan():
    from scan.orchestrator import resumable_action_ids

    assert resumable_action_ids(
        plan_action_ids=("a", "b", "c"),
        terminal_receipts={"a": "completed", "b": "failed"},
    ) == ("c",)
