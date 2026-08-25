from __future__ import annotations

from pathlib import Path

from api.runtime.capability_registry import CAPABILITY_REGISTRY


ROOT = Path(__file__).resolve().parents[1]


def _api_source() -> str:
    return (ROOT / "api" / "api.py").read_text()


def _handler_source() -> str:
    source = _api_source()
    start = source.index("async def execute_hunt_capability(")
    end = source.index(
        '\n\n@app.post("/hunts/{hunt_id}/shell-plans',
        start,
    )
    return source[start:end]


def test_device_queue_actions_reserve_before_downstream_submission():
    handler = _handler_source()

    assert 'is_device_queue = placement == "device_queue"' in handler
    assert "DeviceExecutionAdapter(" in handler
    assert "dispatch_registered_adapter(" in handler
    assert handler.index("create_requested(") < handler.index(
        "_execute_device_capability_operation("
    )
    assert "_merge_hunt_device_queue_context" in handler
    assert 'context["device_state"] = device_state' in handler


def test_device_queue_job_carries_server_owned_hunt_correlation():
    source = _api_source()
    handler = _handler_source()

    assert "_HUNT_DEVICE_QUEUE_CORRELATION.set({" in handler
    assert '"hunt_action_id": str(action_id)' in handler
    assert '"budget_reservation_id": (' in handler
    assert '"action_digest": durable_action_digest' in handler
    assert source.count('options["hunt_dispatch"] = hunt_dispatch') == 2


def test_device_queue_recovers_a_job_accepted_before_response_failure():
    handler = _handler_source()

    assert "options->'hunt_dispatch'->>'hunt_action_id'=$2" in handler
    assert "_scan_queue_handoff_confirmed(correlated_scan)" in handler
    assert "Device queue action created more than one downstream scan" in handler
    assert "device_queue_state_advanced and not device_queue_enqueued" in handler
    assert "device_queue_enqueued and not device_queue_state_advanced" in handler
    assert 'status = "partial"' in handler


def test_device_queue_row_without_handoff_proof_is_never_charged_as_accepted():
    handler = _handler_source()

    queue_recovery = handler[handler.index("correlated_scans = await conn.fetch("):]
    queue_recovery = queue_recovery[:queue_recovery.index("proposed_ssh_plan:")]
    assert "run_kind, options" in queue_recovery
    assert "_scan_queue_handoff_confirmed(correlated_scan)" in queue_recovery
    assert "enqueue failed" not in queue_recovery


def test_blocked_device_queue_refunds_everything_except_planner_action():
    handler = _handler_source()

    refund = handler[handler.index("and not device_queue_enqueued"):]
    refund = refund[:refund.index("elif is_device_http")]
    assert "actual_charges = _hunt_nonexecuting_actual(charges)" in refund


def test_service_verification_reserves_only_the_selected_transport():
    handler = _handler_source()

    assert 'if name == "device.service.verify":' in handler
    assert '"udp_ports_attempted"' in handler
    assert '"tcp_ports_attempted"' in handler
    assert "charges[transport_dimension] = 1" in handler
    assert "and device_queue_enqueued" in handler
    assert 'actual_charges[dimension] = int(charges[dimension])' in handler

    spec = CAPABILITY_REGISTRY.require("device.service.verify")
    assert spec.budget_cost["tcp_ports_attempted"] == 1
    assert spec.budget_cost["udp_ports_attempted"] == 1
    assert spec.budget_cost["device_fragility_points"] == 6


def test_device_queue_receipt_binds_the_exact_downstream_scan():
    handler = _handler_source()

    assert '"kind": "scan_receipt"' in handler
    assert '"scan_id": str(queued_result["scan_id"])' in handler
    assert '"downstream": downstream_receipt or None' in handler
    assert "receipt_contract_payload" in handler
    settlement = handler[handler.index("receipt_contract_payload"):]
    assert settlement.index("_record_tool_receipt(") < settlement.index(
        "durable_store.persist_terminal("
    )
