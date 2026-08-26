from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)
import re

from api.hunt.capability_reservations import terminalize_hunt_capability
from api.runtime.budget_reservations import DurableBudgetReservation
from api.runtime.capability_registry import CAPABILITY_REGISTRY


NOW = datetime(2026, 8, 22, 16, 0, tzinfo=timezone.utc)


def _running_network_reservation() -> DurableBudgetReservation:
    requested = DurableBudgetReservation.request(
        owner_kind="hunt",
        owner_id="hunt-1",
        capability_name="ports.discover",
        amounts={
            "agent_actions": 1,
            "active_actions": 1,
            "hosts_attempted": 1,
            "tcp_ports_attempted": 2,
            "tool_wall_seconds": 120,
        },
        reservation_id="reservation-1",
        now=NOW,
    )
    reserved = requested.reserve(now=NOW, lease_seconds=180)
    return reserved.start(worker_id="worker:test", now=NOW, lease_seconds=180)


def test_worker_network_capability_set_is_explicit():
    assert {spec.name for spec in CAPABILITY_REGISTRY.for_hunt_executor("worker_network")} == {
        "ports.discover",
        "service.fingerprint",
        "subdomains.discover",
    }


def test_partial_network_receipt_preserves_typed_observations_and_timeout():
    running = _running_network_reservation()
    finished = NOW.replace(second=1)
    terminal, receipt = terminalize_hunt_capability(
        running,
        action_digest="a" * 64,
        capability_name="ports.discover",
        adapter_name="naabu",
        adapter_version="1",
        parser_version="naabu-jsonl/v1",
        target_id="target-1",
        target_kind="web",
        capability_input={"ports": [80, 443], "token": "worker-only"},
        action_status="partial",
        actual_budget={
            "agent_actions": 1,
            "active_actions": 1,
            "hosts_attempted": 1,
            "tcp_ports_attempted": 2,
            "tool_wall_seconds": 1,
        },
        worker_id="worker:test",
        started_at=NOW.isoformat(),
        finished_at=finished.isoformat(),
        receipt_id="receipt-1",
        result={
            "timed_out": True,
            "receipt_observations": [
                {"kind": "open_port", "address": "192.0.2.10", "port": 443}
            ],
        },
    )

    public = receipt.public_dict()
    assert terminal.status == "committed"
    assert receipt.status == "partial"
    assert receipt.partial is True
    assert receipt.timed_out is True
    assert receipt.parser_version == "naabu-jsonl/v1"
    assert public["observations"] == [
        {"kind": "open_port", "address": "192.0.2.10", "port": 443}
    ]
    assert "worker-only" not in str(public)


def test_api_admits_network_hold_before_queue_and_never_double_settles():
    enqueue = definition_source("_enqueue_canonical_network_capability")
    handler = (
        definition_source("execute_hunt_capability")
        + definition_source("_execute_hunt_capability_lifecycle")
    )

    for field in (
        '"hunt_id"',
        '"action_id"',
        '"budget_reservation_id"',
        '"action_digest"',
    ):
        assert field in enqueue
    assert 'is_network = placement == "worker_network"' in handler
    assert 'is_scanner = placement == "worker_scanner"' in handler
    assert "durable_budget = api_managed_budget or worker_durable_budget" in handler
    assert 'admission_action_status = "reserved"' in handler
    assert handler.index("create_requested") < handler.index(
        "await _enqueue_canonical_network_capability("
    )
    admission_commit = handler.index("if admission_error is not None:")
    assert "admission_error = HTTPException(" in handler[:admission_commit]
    assert "raise admission_error" in handler[admission_commit:]
    assert "budget_reservation_state" in handler[:admission_commit]
    assert '"active", "awaiting_planner", "budget_exhausted"' in handler
    worker_branch_start = handler.index("elif worker_durable_budget:")
    legacy_branch_start = handler.index("\n            else:", worker_branch_start)
    worker_branch = handler[worker_branch_start:legacy_branch_start]
    assert "durable_budget_settled" in worker_branch
    assert "internally consistent" in worker_branch
    assert "_record_tool_receipt" not in worker_branch


def test_worker_rebuilds_authority_starts_heartbeats_and_settles_atomically():
    source = (Path(__file__).resolve().parents[1] / "api" / "worker.py").read_text()
    start = source.index("async def process_canonical_network_capability_job(")
    end = source.index("\n\nasync def process_job(", start)
    handler = source[start:end]

    assert 'SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE' in handler
    assert 'context = _worker_json_object(run["context_pack"])' in handler
    assert 'hunt_policy = _worker_json_object(run["policy_json"])' in handler
    assert "raw_target" not in handler
    assert "raw_policy" not in handler
    assert "hunt_capability_action_digest(" in handler
    assert "stored.action_digest != queued_action_digest" in handler
    assert "stored.record.start(" in handler
    assert handler.index("stored.record.start(") < handler.index("_dispatch_registered_hunt_adapter(")
    assert "heartbeat_reservation" in handler
    assert "_dispatch_registered_hunt_adapter(" in handler
    assert "NetworkExecutionAdapter(" in handler
    assert "capability_input=execution.redacted_execution" in handler
    assert "terminalize_hunt_capability(" in handler
    assert "_record_hunt_network_tool_receipt(" in handler
    assert "persist_terminal(" in handler
    assert "UPDATE hunt_runs SET budget_used_json" in handler
    assert "UPDATE hunt_actions" in handler
    assert "idempotent_redelivery_running" in handler
    assert "publish_result = False" in handler
    assert "if job_id and publish_result:" in handler
    assert '"active", "awaiting_planner", "budget_exhausted"' in handler
    assert "_worker_terminal_network_result" in source[:start]


def test_worker_tool_receipt_insert_uses_contiguous_asyncpg_parameters():
    source = (Path(__file__).resolve().parents[1] / "api" / "worker.py").read_text()
    start = source.index("async def _record_hunt_network_tool_receipt(")
    end = source.index(
        "\n\nasync def process_canonical_network_capability_job(", start
    )
    helper = source[start:end]
    positions = sorted({int(value) for value in re.findall(r"\$(\d+)", helper)})
    assert positions == list(range(1, 27))
    assert "budget_json" in helper
    assert "capability_name" in helper
    assert "hunt_id" in helper
