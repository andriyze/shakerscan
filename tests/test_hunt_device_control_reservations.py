from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_device_control_actions_use_atomic_durable_settlement():
    source = (ROOT / "api" / "api.py").read_text()
    start = source.index("async def execute_hunt_capability(")
    end = source.index(
        '\n\n@app.post("/hunts/{hunt_id}/shell-plans',
        start,
    )
    handler = source[start:end]

    assert "DURABLE_DEVICE_CONTROL_HUNT_CAPABILITIES" in handler
    assert "_merge_hunt_device_control_context(" in handler
    assert '"context_pack=$3, updated_at=NOW() WHERE id=$1"' in handler
    assert handler.index("create_requested(") < handler.index(
        "_execute_device_agent_tool("
    )
    assert handler.index("persist_terminal(") < handler.index(
        "UPDATE hunt_actions"
    )


def test_device_control_context_merge_is_limited_to_read_only_evidence():
    source = (ROOT / "api" / "api.py").read_text()
    start = source.index("def _merge_hunt_device_control_context(")
    end = source.index("\n\ndef _hunt_ledger_limits", start)
    helper = source[start:end]

    assert 'persisted_state["evidence"] = persisted_evidence' in helper
    assert 'persisted_state["next_evidence_ref"]' in helper
    assert "execution_context_before" in helper
    assert "execution_context_after" in helper
    assert "traffic_frozen" not in helper
