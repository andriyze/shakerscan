from api.scan.activity import (
    parallel_scan_activity_lines,
    scan_action_activity_event,
    scan_action_diagnostic_line,
)
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


def test_scan_action_diagnostic_line_exposes_only_bounded_telemetry():
    plan = _plan()
    action = plan.actions[0]
    result = _result(
        action,
        status=CapabilityResultStatus.TIMED_OUT,
        reason=CapabilityResultReason.TIMED_OUT,
    )
    line = scan_action_diagnostic_line(
        action=action,
        result=result,
        receipt={
            "errors": ["external_process_contract: target secret must not leak"],
            "redacted_execution": {
                "target_url": "https://secret.example/path?token=never",
                "process_enforcement": {
                    "hard_budget": {
                        "http_requests": 9,
                        "tool_wall_seconds": 5,
                    },
                },
                "wire_telemetry": {
                    "observed_http_requests_minimum": 7,
                    "wall_seconds": 5,
                    "connections_attempted": 8,
                    "connections_opened": 7,
                    "limiter_status": "failed",
                },
            },
        },
    )

    assert line is not None
    assert "outcome=timed_out" in line
    assert "reason=timed_out" in line
    assert "error=external_process_contract" in line
    assert "http=7/9/" in line
    assert "wall=5s/5s" in line
    assert "connections=7/8 opened/attempted" in line
    assert "limiter=failed" in line
    assert "secret" not in line
    assert "token" not in line


def test_scan_action_diagnostic_line_explains_prelaunch_failure_without_raw_error():
    plan = _plan()
    action = plan.actions[0]
    result = _result(
        action,
        status=CapabilityResultStatus.FAILED,
        reason=CapabilityResultReason.ADAPTER_FAILED,
    )

    line = scan_action_diagnostic_line(
        action=action,
        result=result,
        receipt={
            "errors": ["private exception text with https://secret.example"],
            "redacted_execution": {"execution_started": False},
        },
    )

    assert line is not None
    assert "outcome=failed" in line
    assert "reason=adapter_failed" in line
    assert "error=unclassified_adapter_error" in line
    assert "execution=not_started" in line
    assert "secret.example" not in line


def test_budget_skip_does_not_claim_an_adapter_error():
    plan = _plan()
    action = plan.actions[0]
    result = _result(
        action,
        status=CapabilityResultStatus.SKIPPED,
        reason=CapabilityResultReason.INSUFFICIENT_PLAN_BUDGET,
    )

    line = scan_action_diagnostic_line(
        action=action,
        result=result,
        receipt={
            "errors": ["private allocator diagnostic"],
            "redacted_execution": {"execution_started": False},
        },
    )

    assert line is not None
    assert "outcome=skipped" in line
    assert "reason=insufficient_plan_budget" in line
    assert "error=none" in line


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
