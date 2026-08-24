from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from api.hunt.capability_reservations import (
    DURABLE_DEVICE_CONTROL_HUNT_CAPABILITIES,
    DURABLE_DEVICE_HTTP_HUNT_CAPABILITIES,
    DURABLE_DEVICE_QUEUE_HUNT_CAPABILITIES,
    DURABLE_DEVICE_SSH_PROPOSAL_HUNT_CAPABILITIES,
    DURABLE_INLINE_HUNT_CAPABILITIES,
    hunt_capability_action_digest,
    hunt_capability_lease_seconds,
    terminalize_hunt_capability,
)
from api.runtime.budget_reservations import DurableBudgetReservation


NOW = datetime(2026, 8, 22, 15, 0, tzinfo=timezone.utc)


def _running_reservation():
    requested = DurableBudgetReservation.request(
        owner_kind="hunt",
        owner_id="hunt-1",
        capability_name="http.request",
        amounts={
            "agent_actions": 1,
            "http_requests": 1,
            "tool_wall_seconds": 10,
        },
        now=NOW,
        reservation_id="reservation-1",
    )
    reserved, held = requested.reserve_against(
        limits={
            "agent_actions": 10,
            "http_requests": 20,
            "tool_wall_seconds": 100,
        },
        consumed={
            "agent_actions": 0,
            "http_requests": 0,
            "tool_wall_seconds": 0,
        },
        now=NOW,
        lease_seconds=90,
    )
    return reserved.start(worker_id="api:test", now=NOW, lease_seconds=90), held


def test_inline_hunt_capability_set_is_explicit_and_bounded():
    assert DURABLE_INLINE_HUNT_CAPABILITIES == {
        "collections.inspect",
        "collections.select",
        "http.request",
        "tls.inspect",
    }
    assert hunt_capability_lease_seconds({"tool_wall_seconds": 10}) == 90
    assert hunt_capability_lease_seconds({"tool_wall_seconds": 4_000}) == 3_600


def test_read_only_device_control_capability_set_is_explicit():
    assert DURABLE_DEVICE_CONTROL_HUNT_CAPABILITIES == {
        "device.capabilities.inspect",
        "device.inspect",
    }


def test_device_http_capability_set_is_explicit():
    assert DURABLE_DEVICE_HTTP_HUNT_CAPABILITIES == {"device.http.probe"}


def test_device_queue_capability_set_is_explicit():
    assert DURABLE_DEVICE_QUEUE_HUNT_CAPABILITIES == {
        "device.scan",
        "device.service.verify",
    }


def test_device_ssh_proposal_capability_set_is_explicit():
    assert DURABLE_DEVICE_SSH_PROPOSAL_HUNT_CAPABILITIES == {
        "device.ssh.propose",
    }


def test_hunt_action_digest_binds_target_input_budget_and_authority():
    base = dict(
        hunt_id="hunt-1",
        action_id="action-1",
        capability_name="http.request",
        target_kind="web",
        target_id="target-1",
        capability_input={"method": "GET", "path": "/health"},
        requested_budget={"agent_actions": 1, "http_requests": 1},
        scope_receipt_id="scope-1",
        approval_receipt_id=None,
    )
    digest = hunt_capability_action_digest(**base)

    assert len(digest) == 64
    assert digest == hunt_capability_action_digest(**base)
    assert digest != hunt_capability_action_digest(
        **{**base, "capability_input": {"method": "GET", "path": "/ready"}}
    )
    assert digest != hunt_capability_action_digest(
        **{**base, "target_id": "target-2"}
    )


def test_successful_inline_hunt_capability_commits_matching_redacted_receipt():
    running, held = _running_reservation()
    digest = "a" * 64
    terminal, receipt = terminalize_hunt_capability(
        running,
        action_digest=digest,
        capability_name="http.request",
        adapter_name="pinned_http",
        adapter_version="1",
        target_id="target-1",
        target_kind="web",
        capability_input={"method": "GET", "path": "/health?token=worker-only"},
        action_status="completed",
        actual_budget={
            "agent_actions": 1,
            "http_requests": 1,
            "tool_wall_seconds": 1,
        },
        worker_id="api:test",
        started_at=NOW.isoformat(),
        finished_at=NOW.isoformat(),
        receipt_id="receipt-1",
        result={"ok": True},
    )

    public = receipt.public_dict()
    assert terminal.status == "committed"
    assert terminal.execution_receipt_hash == receipt.receipt_hash
    assert receipt.budget_reservation_state == "committed"
    assert receipt.input_digest == digest
    assert terminal.reconcile_consumed(held) == {
        "agent_actions": 1,
        "http_requests": 1,
        "tool_wall_seconds": 1,
    }
    assert "worker-only" not in str(public)
    assert public["redacted_execution"]["input"]["path"].endswith("token=***")


def test_failed_inline_hunt_capability_keeps_measured_usage_and_receipt():
    running, held = _running_reservation()
    terminal, receipt = terminalize_hunt_capability(
        running,
        action_digest="b" * 64,
        capability_name="http.request",
        adapter_name="pinned_http",
        adapter_version="1",
        target_id="target-1",
        target_kind="web",
        capability_input={"method": "GET", "path": "/"},
        action_status="failed",
        actual_budget={
            "agent_actions": 1,
            "http_requests": 1,
            "tool_wall_seconds": 1,
        },
        worker_id="api:test",
        started_at=NOW.isoformat(),
        finished_at=NOW.isoformat(),
        receipt_id="receipt-2",
        result={"ok": False, "error": "transport_failed"},
    )

    assert terminal.status == "failed"
    assert terminal.execution_uncertain is False
    assert terminal.actual["http_requests"] == 1
    assert terminal.execution_receipt_hash == receipt.receipt_hash
    assert receipt.budget_reservation_state == "failed"
    assert receipt.errors == ("transport_failed",)
    assert terminal.reconcile_consumed(held)["http_requests"] == 1


def test_real_hunt_route_uses_transactional_durable_inline_reservations():
    root = Path(__file__).resolve().parents[1]
    source = (root / "api" / "api.py").read_text()
    start = source.index("async def execute_hunt_capability(")
    end = source.index("\n\n@app.post(\"/hunts/{hunt_id}/shell-plans", start)
    handler = source[start:end]
    migrations = (root / "api" / "retest_contract.py").read_text()

    assert "DURABLE_INLINE_HUNT_CAPABILITIES" in handler
    assert "create_requested" in handler
    assert "reserve_against" in handler
    assert "record.start(" in handler
    assert "persist_transition" in handler
    assert "terminalize_hunt_capability" in handler
    assert "persist_terminal" in handler
    assert handler.index("create_requested") < handler.index("record.start(")
    assert handler.index("record.start(") < handler.index("if name == \"collections.inspect\"")
    assert "status='reserved'" in handler
    assert "1 + MAX_REDIRECT_HOPS" in handler
    assert "record_receipt=False" in handler
    assert "HttpRequestExecutionAdapter(" in handler
    assert "TlsInspectionExecutionAdapter(" in handler
    assert "ControlPlaneExecutionAdapter(" in handler
    assert handler.count("CapabilityExecutor().execute(") >= 4
    assert "elif spec.process_tool_name:" not in handler
    assert "receipt_observations" in handler
    assert "scope_receipt_id=validated_scope_receipt_id" in handler
    assert "'reserved','running','completed','blocked','cancelled','failed','partial'" in migrations
