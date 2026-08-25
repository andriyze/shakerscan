from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _handler_source() -> str:
    source = (ROOT / "api" / "api.py").read_text()
    start = source.index("async def execute_hunt_capability(")
    end = source.index(
        '\n\n@app.post("/hunts/{hunt_id}/shell-plans',
        start,
    )
    return source[start:end]


def test_device_http_probe_is_single_flight_and_durably_reserved_before_socket():
    handler = _handler_source()

    assert 'is_device_http = placement == "device_http"' in handler
    assert "DeviceExecutionAdapter(" in handler
    assert "dispatch_registered_adapter(" in handler
    assert "pg_advisory_xact_lock" in handler
    assert "h.device_target_id=$1" in handler
    assert "A device HTTP probe is already in flight" in handler
    assert handler.index("create_requested(") < handler.index(
        "_execute_device_capability_operation("
    )


def test_device_http_attempt_is_charged_and_persisted_even_when_transport_fails():
    handler = _handler_source()

    assert "device_http_attempted = bool(" in handler
    blocked_start = handler.index('if status == "blocked":')
    blocked = handler[blocked_start:handler.index(
        "elif is_device_http:",
        blocked_start,
    )]
    assert 'actual_charges["http_requests"]' in blocked
    assert 'actual_charges["device_fragility_points"]' in blocked
    assert 'actual_charges["tool_wall_seconds"]' in blocked
    assert "_merge_hunt_device_http_context" in handler
    assert 'context.get("device_policy_state")' in handler


def test_device_http_guard_reason_survives_durable_action_replay():
    handler = _handler_source()

    assert 'capability_execution.errors' in handler
    assert 'receipt_contract_payload["error"]' in handler
    assert 'receipt_payload["error"]' in handler
    assert 'receipt_payload["observations"]' in handler
    assert 'existing_summary.get("error")' in handler


def test_device_http_receipts_strip_query_values_but_keep_digest_binding():
    handler = _handler_source()

    assert "_hunt_redacted_capability_input(name, request.input)" in handler
    assert '"input": _hunt_redacted_capability_input(name, request.input)' in handler
    assert '"input_digest": capability_input_digest' in handler
    assert "capability_input=receipt_capability_input" in handler
    assert "redacted_argv=[receipt_capability_input]" in handler
    assert "action_digest=durable_action_digest" in handler


def test_device_http_planner_observation_uses_redacted_path_and_body_preview():
    source = (ROOT / "api" / "api.py").read_text()
    start = source.index('if name == "device_http_request":')
    end = source.index('\n    if name == "verify_service_state":', start)
    adapter = source[start:end]

    assert '"path": _redact_hunt_path_query(args["path"])' in adapter
    assert '"body_preview": _redact_device_http_body_preview(' in adapter
