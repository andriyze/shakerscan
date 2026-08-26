from __future__ import annotations

from pathlib import Path

from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)

from api.hunt.contracts import capability_manifest
from api.hunt.start_contract import normalize_hunt_start_payload
from api.runtime.capability_registry import CAPABILITY_REGISTRY


ROOT = Path(__file__).resolve().parents[1]


def _api_source() -> str:
    return api_tree_source()


def _handler_source() -> str:
    return definition_source("confirm_hunt_shell_plan")


def test_confirmed_ssh_is_registry_owned_but_never_planner_callable():
    spec = CAPABILITY_REGISTRY.require("device.ssh.execute_confirmed")
    contract = normalize_hunt_start_payload({
        "schema_version": "hunt-start/v2",
        "target_id": "target-1",
        "target_kind": "device",
        "goal": "Inspect the device",
        "budget_profile": "balanced",
        "budgets": {},
        "policy": {
            "active_testing": True,
            "authorization_confirmed": True,
            "approval_receipt_id": "receipt",
        },
        "credential_refs": {"ssh_credential_profile_id": "credential-1"},
        "capabilities": [],
        "request_collection_ids": [],
    })

    assert spec.planner_visible is False
    assert spec.budget_cost == {
        "active_actions": 1,
        "tool_wall_seconds": 30,
        "device_fragility_points": 12,
    }
    assert "device.ssh.execute_confirmed" not in {
        item["name"] for item in capability_manifest(
            contract, credentials_available=True,
        )
    }


def test_native_v2_allowlist_honors_confirmation_only_visibility():
    source = (ROOT / "api" / "hunt" / "contracts.py").read_text()
    assert "def capability_is_allowed(" in source
    assert "if not spec.planner_visible or spec.hunt_executor is None:" in source
    assert "return False" in source


def test_confirmation_reserves_and_starts_before_downstream_submission():
    handler = _handler_source()

    assert 'require(capability_name)' in handler
    assert "DeviceExecutionAdapter(" in handler
    assert "CapabilityExecutor().execute(" in handler
    assert 'target_kind="device"' in handler
    assert handler.index("create_requested(") < handler.index("scan_device(")
    assert handler.index(".reserve_against(") < handler.index("scan_device(")
    assert handler.index(".start(") < handler.index("scan_device(")
    assert '"status": "queueing"' in handler
    assert '"budget_reservation_id"' in handler
    assert '"action_digest"' in handler


def test_confirmation_job_carries_only_server_owned_durable_correlation():
    handler = _handler_source()

    assert "_HUNT_DEVICE_QUEUE_CORRELATION.set({" in handler
    assert '"hunt_action_id": str(action_id)' in handler
    assert '"budget_reservation_id": durable_reservation.record.reservation_id' in handler
    assert '"action_digest": durable_action_digest' in handler
    assert '"capability_name": capability_name' in handler


def test_confirmation_recovers_an_accepted_job_before_settlement():
    source = _api_source()
    handler = _handler_source()

    dispatch = definition_source("_hunt_confirmed_shell_dispatch")
    assert "options->'hunt_dispatch'->>'hunt_action_id'" in dispatch
    assert "options->'hunt_dispatch'->>'budget_reservation_id'" in dispatch
    assert "options->'hunt_dispatch'->>'action_digest'" in dispatch
    assert "Confirmed SSH action created more than one downstream scan" in dispatch
    assert "target_url, options" in dispatch
    assert "_scan_queue_handoff_confirmed(row)" in dispatch
    assert "enqueue failed" not in dispatch
    assert "recovered_after_response_failure" in handler
    assert "dispatch_required = False" in handler
    expiry_check = handler[handler.index("if (") :]
    assert 'plan.get("status") == "proposed"' in expiry_check


def test_successful_retry_clears_stale_queue_failure_metadata():
    handler = _handler_source()
    settlement = handler[handler.index("settled_plans = []") :]
    settlement = settlement[settlement.index("if accepted_scan is not None:") :]
    success = settlement[: settlement.index("else:")]

    assert '"last_queue_error", "last_queue_receipt_id"' in success


def test_unaccepted_confirmation_refunds_every_execution_dimension():
    handler = _handler_source()

    failure = handler[handler.index("if accepted_scan is not None:"):]
    assert "actual_charges = _hunt_nonexecuting_actual(charges)" in failure
    assert '"status": "not_enqueued"' in failure
    assert '"status": "proposed"' in failure
    assert "last_queue_receipt_id" in failure


def test_confirmation_receipt_binds_user_consent_plan_and_downstream_scan():
    source = _api_source()
    handler = _handler_source()

    confirmation_input = source[
        source.index("def _hunt_confirmed_shell_capability_input("):
    ]
    confirmation_input = confirmation_input[
        :confirmation_input.index("\n\nasync def _hunt_confirmed_shell_dispatch")
    ]
    assert "confirmation_phrase_sha256" in confirmation_input
    assert '"confirmation_phrase":' not in confirmation_input
    assert '"kind": "confirmed_ssh_execution_queue"' in handler
    assert '"exact_commands_confirmed": True' in handler
    assert '"remote_device_effects_confirmed": True' in handler
    assert '"scan_id": accepted_scan["scan_id"]' in handler
    assert '"plan_digest": request.plan_digest' in handler
    settlement = handler[handler.index("_record_tool_receipt("):]
    assert settlement.index("_record_tool_receipt(") < settlement.index(
        "terminalize_hunt_capability("
    )
    assert settlement.index("terminalize_hunt_capability(") < settlement.index(
        "durable_store.persist_terminal("
    )
    assert "parser_version=(" in settlement
    assert "receipt_id=$4" in handler
