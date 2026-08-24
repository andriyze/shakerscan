from __future__ import annotations


def test_resume_schedules_only_nonterminal_actions_from_the_persisted_plan():
    from api.scan.orchestrator import resumable_action_ids

    assert resumable_action_ids(
        plan_action_ids=("a", "b", "c"),
        terminal_receipts={"a": "completed", "b": "failed"},
    ) == ("c",)
