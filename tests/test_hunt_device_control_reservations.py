from __future__ import annotations

from pathlib import Path
from tests.api_sources import definition_source


ROOT = Path(__file__).resolve().parents[1]


def test_device_control_actions_use_atomic_durable_settlement():
    handler = definition_source("execute_hunt_capability") + definition_source("_execute_hunt_capability_lifecycle")

    assert 'is_device_control = placement == "device_control"' in handler
    assert "DeviceExecutionAdapter(" in handler
    assert "dispatch_registered_adapter(" in handler
    assert "inline_device_target_binding()" in handler
    assert "_merge_hunt_device_control_context" in handler
    assert "merge_device_context = (" in handler
    assert '"context_pack=$3, updated_at=NOW() WHERE id=$1"' in handler
    assert handler.index("create_requested(") < handler.index(
        "_execute_device_capability_operation("
    )
    assert handler.index("persist_terminal(") < handler.index(
        "UPDATE hunt_actions"
    )


def test_device_control_context_merge_is_limited_to_read_only_evidence():
    helper = definition_source("_merge_hunt_device_control_context")

    assert '"evidence": persisted_evidence' in helper
    assert 'persisted_runtime["next_evidence_ref"]' in helper
    assert "execution_context_before" in helper
    assert "execution_context_after" in helper
    assert "DeviceHuntPolicyState.from_mapping" in helper
