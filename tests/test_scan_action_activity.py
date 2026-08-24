from api.scan.activity import parallel_scan_activity_lines, scan_action_activity_event
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


def test_parallel_scan_activity_combines_child_logs_and_status_fallbacks():
    lines = parallel_scan_activity_lines(
        shards=(
            {
                "id": "shard-a",
                "shard_index": 0,
                "status": "running",
                "current_phase": "discover.web_crawl",
            },
            {
                "id": "shard-b",
                "shard_index": 1,
                "status": "queued",
                "current_phase": "queued",
            },
        ),
        child_logs={
            "shard-a": (
                b"[scan] Started Discover Web Crawl \xc2\xb7 15%",
                "[scan] Finished Discover Web Crawl \u00b7 success \u00b7 23%",
            ),
        },
        limit=10,
    )

    assert lines == [
        "[Shard 1] [scan] Started Discover Web Crawl \u00b7 15%",
        "[Shard 1] [scan] Finished Discover Web Crawl \u00b7 success \u00b7 23%",
        "[Shard 2] queued \u00b7 Queued",
    ]


def test_parallel_scan_activity_is_bounded_to_the_requested_tail():
    lines = parallel_scan_activity_lines(
        shards=({"id": "shard-a", "shard_index": 2, "status": "running"},),
        child_logs={"shard-a": ("one", "two", "three")},
        limit=2,
    )

    assert lines == ["[Shard 3] two", "[Shard 3] three"]
