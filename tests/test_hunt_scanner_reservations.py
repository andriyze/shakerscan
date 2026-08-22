from __future__ import annotations

from pathlib import Path

from api.hunt.capability_reservations import (
    DURABLE_SCANNER_HUNT_CAPABILITIES,
)


ROOT = Path(__file__).resolve().parents[1]


def test_durable_scanner_capability_set_is_explicit():
    assert DURABLE_SCANNER_HUNT_CAPABILITIES == {
        "sqli.verify",
        "templates.scan",
        "web.content_discover",
        "web.crawl",
        "web.probe",
        "xss.verify",
    }


def test_scanner_queue_carries_identity_not_target_authority():
    source = (ROOT / "api" / "api.py").read_text()
    start = source.index("async def _enqueue_canonical_scanner_capability(")
    end = source.index("\n\nasync def _agent_tool_run_tool", start)
    enqueue = source[start:end]

    for field in (
        '"hunt_id"',
        '"action_id"',
        '"budget_reservation_id"',
        '"action_digest"',
        '"capability_input"',
    ):
        assert field in enqueue
    for forbidden in (
        '"registered_target"',
        '"execution_target"',
        '"pinned_address"',
        '"authorized_addresses"',
        '"approval_receipt_id"',
        '"oob_interactsh_token"',
    ):
        assert forbidden not in enqueue


def test_api_routes_scanners_through_worker_owned_durable_settlement():
    source = (ROOT / "api" / "api.py").read_text()
    start = source.index("async def execute_hunt_capability(")
    end = source.index(
        '\n\n@app.post("/hunts/{hunt_id}/shell-plans',
        start,
    )
    handler = source[start:end]

    assert "DURABLE_SCANNER_HUNT_CAPABILITIES" in handler
    assert "await _enqueue_canonical_scanner_capability(" in handler
    scanner_branch = handler[handler.index(
        "elif name in DURABLE_SCANNER_HUNT_CAPABILITIES:"
    ):handler.index("elif spec.legacy_tool_name:")]
    assert "reservation_id=durable_reservation.record.reservation_id" in scanner_branch
    assert "action_digest=durable_action_digest" in scanner_branch
    assert "_agent_tool_run_tool" not in scanner_branch


def test_scanner_worker_rebuilds_authority_and_settles_atomically():
    source = (ROOT / "api" / "worker.py").read_text()
    start = source.index("async def process_canonical_scanner_capability_job(")
    end = source.index(
        "\n\nasync def process_canonical_network_capability_job(",
        start,
    )
    handler = source[start:end]

    assert 'SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE' in handler
    assert 'context = _worker_json_object(run["context_pack"])' in handler
    assert 'hunt_policy = _worker_json_object(run["policy_json"])' in handler
    assert "_worker_scanner_execution_target(" in handler
    assert "validate_pinned_scanner_address(" in handler
    assert "hunt_capability_action_digest(" in handler
    assert "stored.record.start(" in handler
    assert handler.index("stored.record.start(") < handler.index(
        "CapabilityExecutor().execute("
    )
    assert "heartbeat_reservation" in handler
    assert "CapabilityExecutor().execute(" in handler
    assert "ScannerExecutionAdapter(" in handler
    assert "capability_input=execution.redacted_execution" in handler
    assert "terminalize_hunt_capability(" in handler
    assert "_record_hunt_network_tool_receipt(" in handler
    assert "persist_terminal(" in handler
    assert "UPDATE hunt_runs SET budget_used_json" in handler
    assert "UPDATE hunt_actions" in handler
    assert "idempotent_redelivery_running" in handler
    assert "publish_result = False" in handler
    assert "if job_id and publish_result:" in handler


def test_scanner_process_heartbeats_and_kills_on_worker_fault():
    source = (ROOT / "api" / "worker.py").read_text()
    start = source.index("async def _execute_agent_scanner_process(")
    end = source.index("\n\nasync def process_agent_scanner_tool_job(", start)
    executor = source[start:end]

    assert "heartbeat: Callable[[], Awaitable[None]] | None" in executor
    assert "await heartbeat()" in executor
    assert "execution_uncertain = process_started" in executor
    generic_fault = executor[executor.index(
        "except Exception as exc:"
    ):executor.index("\n    finally:")]
    assert "_terminate_agent_tool_process_group(proc)" in generic_fault
    assert "await proc.wait()" in generic_fault


def test_timed_out_partial_tool_receipt_is_labeled_timeout():
    source = (ROOT / "api" / "worker.py").read_text()
    start = source.index("async def _record_hunt_network_tool_receipt(")
    end = source.index("\n\ndef _worker_scanner_execution_target(", start)
    helper = source[start:end]

    timeout_position = helper.index('"timeout" if timed_out')
    success_position = helper.index('"success" if status')
    assert timeout_position < success_position
