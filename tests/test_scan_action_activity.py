from api.scan.activity import scan_action_activity_event
from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus

from tests.test_scan_orchestrator import _plan, _result


def test_scan_action_activity_is_content_free_and_progresses_across_the_plan():
    plan = _plan()
    first = plan.actions[0]
    final = plan.actions[-1]

    started = scan_action_activity_event(
        plan=plan, action=first, event="running",
    )
    finished = scan_action_activity_event(
        plan=plan,
        action=final,
        event="settled",
        result=_result(final, status=CapabilityResultStatus.SUCCESS),
    )

    assert started == {
        "phase": "baseline.http",
        "progress": 5,
        "line": "[scan] Started Baseline HTTP · 5%",
    }
    assert finished == {
        "phase": "finalize.report",
        "progress": 95,
        "line": "[scan] Finished Finalize Report · success · 95%",
    }


def test_scan_action_activity_supports_two_phase_progress_ranges():
    plan = _plan()
    final = plan.actions[-1]
    event = scan_action_activity_event(
        plan=plan,
        action=final,
        event="settled",
        result=_result(
            final,
            status=CapabilityResultStatus.PARTIAL,
            reason=CapabilityResultReason.OUTPUT_TRUNCATED,
        ),
        progress_start=5,
        progress_end=45,
    )
    assert event["progress"] == 45
    assert "partial" in event["line"]
