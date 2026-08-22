from __future__ import annotations

import asyncio
from datetime import timedelta
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import types


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

import worker
from runtime.budget_reservations import DurableBudgetReservation
from runtime.capability_settlement import terminalize_capability_reservation
from runtime.models import ScanBudget, ScanPolicy, TargetBinding
from runtime.reservation_store import StoredBudgetReservation
from scan.execution import ScanExecutionPlan


def _authority(*, enabled: bool = True):
    plan = ScanExecutionPlan(
        policy=ScanPolicy(
            subdomain_discovery=enabled,
            scope_receipt_id="scope-1",
        ),
        budget_profile="balanced",
        budget=ScanBudget(1_200, 100, 50, 20, 10, 60, 2),
    )
    target = TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
        scope_receipt_id="scope-1",
    )
    options = plan.option_metadata()
    options.update({
        "scan_compatibility": {
            "legacy_executor_alias": "deep",
            "temporary": True,
        },
        "scan_type": "deep",
        "active": False,
        "network_discovery": False,
        "subfinder": enabled,
        "_canonical_target_binding": target.canonical_dict(),
    })
    return plan, target, options


class _Transaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class _Connection:
    def __init__(self, plan):
        canonical = plan.canonical_dict()
        self.row = {
            "status": "running",
            "policy_json": canonical["policy"],
            "budget_json": canonical["budget"],
            "budget_used_json": {},
        }

    def transaction(self):
        return _Transaction()

    async def fetchrow(self, query, *_args):
        if "policy_json" in query:
            return dict(self.row)
        if "budget_used_json" in query:
            return {"budget_used_json": dict(self.row["budget_used_json"])}
        if "SELECT status" in query:
            return {"status": self.row["status"]}
        raise AssertionError(query)

    async def execute(self, query, *_args):
        if "UPDATE scans SET budget_used_json" in query:
            self.row["budget_used_json"] = json.loads(_args[1])
            return "UPDATE 1"
        raise AssertionError(query)


class _Acquire:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *_args):
        return False


class _Pool:
    def __init__(self, connection):
        self.connection = connection

    def acquire(self):
        return _Acquire(self.connection)


class _ReservationStore:
    def __init__(self, events):
        self.events = events
        self.current = None

    async def create_requested(
        self, _conn, *, action_id, action_digest, record,
    ):
        self.events.append(("create", record.status))
        self.current = StoredBudgetReservation(
            action_id=action_id,
            action_digest=action_digest,
            record=record,
        )
        return self.current

    async def load(self, _conn, _reservation_id, *, for_update=False):
        assert for_update is True
        return self.current

    async def persist_transition(
        self, _conn, *, previous, current, ledger_after_hold=None,
    ):
        assert previous.record.state_digest == self.current.record.state_digest
        self.events.append(("transition", current.status))
        self.current = StoredBudgetReservation(
            action_id=previous.action_id,
            action_digest=previous.action_digest,
            record=current,
            ledger_after_hold=(
                dict(ledger_after_hold)
                if ledger_after_hold is not None
                else previous.ledger_after_hold
            ),
            ledger_after_settlement=previous.ledger_after_settlement,
            receipt=previous.receipt,
        )
        return self.current

    async def persist_terminal(
        self, _conn, *, previous, terminal, ledger_after_settlement, receipt,
    ):
        assert previous.record.state_digest == self.current.record.state_digest
        self.events.append(("terminal", terminal.status))
        self.current = StoredBudgetReservation(
            action_id=previous.action_id,
            action_digest=previous.action_digest,
            record=terminal,
            ledger_after_hold=previous.ledger_after_hold,
            ledger_after_settlement=dict(ledger_after_settlement),
            receipt=receipt.public_dict() if receipt else None,
        )
        return self.current


def test_policy_disabled_scan_never_opens_a_database_or_executes(monkeypatch):
    _plan, _target, options = _authority(enabled=False)

    class _NoPool:
        def acquire(self):
            raise AssertionError("policy-disabled discovery touched persistence")

    monkeypatch.setattr(worker, "db_pool", _NoPool())
    summary = asyncio.run(worker._execute_scan_subdomain_discovery(
        options, "00000000-0000-0000-0000-000000000001", job_id="job-1",
    ))

    assert summary["status"] == "skipped"
    assert summary["reason"] == "policy_disabled"
    assert summary["observation_count"] == 0


def test_scan_subdomain_discovery_reserves_before_target_traffic_and_settles(
    monkeypatch,
):
    plan, _target, options = _authority(enabled=True)
    connection = _Connection(plan)
    events = []
    store = _ReservationStore(events)

    async def run_streaming(argv, **kwargs):
        events.append(("traffic", store.current.record.status))
        assert argv == [
            "subfinder", "-d", "example.test", "-silent", "-json",
            "-disable-update-check", "-timeout", "10", "-max-time", "2",
        ]
        assert kwargs["hard_timeout"] == 60.0
        return SimpleNamespace(
            stdout='{"host":"api.example.test"}\n',
            returncode=0,
            timed_out=False,
            partial=False,
            stdout_truncated=False,
            cancelled=False,
        )

    monkeypatch.setattr(worker, "db_pool", _Pool(connection))
    monkeypatch.setattr(worker, "PostgresBudgetReservationStore", lambda: store)
    monkeypatch.setattr(worker, "run_streaming", run_streaming)
    monkeypatch.setattr(worker, "_worker_runtime_identity", lambda: "worker:test")
    monkeypatch.setattr(worker, "_scan_cancel_requested", lambda _scan_id: False)

    summary = asyncio.run(worker._execute_scan_subdomain_discovery(
        options, "00000000-0000-0000-0000-000000000001", job_id="job-1",
    ))

    assert events[:3] == [
        ("create", "requested"),
        ("transition", "reserved"),
        ("transition", "running"),
    ]
    assert ("traffic", "running") in events
    assert events[-1] == ("terminal", "committed")
    assert summary["status"] == "success"
    assert summary["observations"] == [{
        "kind": "subdomain",
        "host": "api.example.test",
        "root_domain": "example.test",
    }]
    assert summary["automatically_scanned_discovered_hosts"] is False
    assert summary["receipt"]["budget_reservation_state"] == "committed"
    assert store.current.receipt["scan_id"] == (
        "00000000-0000-0000-0000-000000000001"
    )
    assert connection.row["budget_used_json"]["hosts_attempted"] == 1


def test_parent_standalone_reuses_verified_placed_discovery_without_traffic(
    monkeypatch,
):
    parent_id = "00000000-0000-0000-0000-000000000001"
    source_id = "00000000-0000-0000-0000-000000000002"
    requested = DurableBudgetReservation.request(
        owner_kind="scan",
        owner_id=source_id,
        capability_name="subdomains.discover",
        amounts={"hosts_attempted": 1, "tool_wall_seconds": 60},
        reservation_id="reservation-1",
    )
    running = requested.reserve(lease_seconds=90).start(
        worker_id="worker:test", lease_seconds=90,
    )
    terminal, receipt = terminalize_capability_reservation(
        running,
        action_digest="a" * 64,
        capability_name="subdomains.discover",
        adapter_name="subfinder",
        adapter_version="1",
        parser_version="subfinder-lines/v1",
        target_id="target-1",
        target_kind="web",
        capability_input={"root_domain": "example.test"},
        action_status="completed",
        actual_budget={"hosts_attempted": 1, "tool_wall_seconds": 1},
        worker_id="worker:test",
        started_at=running.started_at.isoformat(),
        finished_at=(running.started_at + timedelta(seconds=1)).isoformat(),
        receipt_id="receipt-1",
        result={
            "receipt_observations": [{
                "kind": "subdomain",
                "host": "api.example.test",
                "root_domain": "example.test",
            }],
        },
    )
    stored = StoredBudgetReservation(
        action_id="discover_surface.subdomains",
        action_digest="a" * 64,
        record=terminal,
        ledger_after_settlement={
            "hosts_attempted": 1,
            "tool_wall_seconds": 1,
        },
        receipt=receipt.public_dict(),
    )
    summary = worker._scan_subdomain_summary_from_stored(
        stored, root_domain="example.test",
    )

    class _SourceConnection:
        async def fetchrow(self, query, *_args):
            assert "scan_role" in query
            return {
                "status": "completed",
                "result": {"subdomain_discovery": summary},
            }

    class _SourceStore:
        async def load(self, _conn, reservation_id, *, for_update=False):
            assert reservation_id == "reservation-1"
            assert for_update is False
            return stored

    monkeypatch.setattr(worker, "db_pool", _Pool(_SourceConnection()))
    monkeypatch.setattr(
        worker, "PostgresBudgetReservationStore", lambda: _SourceStore(),
    )
    reused = asyncio.run(worker._reuse_placed_scan_subdomain_discovery(
        parent_scan_id=parent_id,
        source_scan_id=source_id,
        expected_summary=summary,
    ))

    assert reused["reused_from_placed_discovery"] is True
    assert reused["source_scan_id"] == source_id
    assert reused["observations"] == summary["observations"]


def test_worker_wires_discovery_before_credentials_and_only_once_per_scan_role():
    source = (Path(__file__).resolve().parents[1] / "api" / "worker.py").read_text()
    helper_start = source.index("async def _execute_scan_subdomain_discovery(")
    helper_end = source.index("\n\ndef _attach_scan_subdomain_summary", helper_start)
    helper = source[helper_start:helper_end]
    standalone_start = source.index("async def process_scan_job(")
    standalone_end = source.index("\n\nasync def process_scan_plan_job", standalone_start)
    standalone = source[standalone_start:standalone_end]
    shard_start = source.index("async def process_scan_shard_job(")
    shard_end = source.index("\n\nasync def process_scan_merge_job", shard_start)
    shard = source[shard_start:shard_end]
    plan_start = source.index("async def process_scan_plan_job(")
    plan = source[plan_start:shard_start]
    merge = source[shard_end:source.index("\n\nasync def process_exploit_batch_job", shard_end)]

    assert "network_capability_adapter(\"subdomains.discover\")" in helper
    assert "PostgresBudgetReservationStore" in helper
    assert helper.index("reserve_against(") < helper.index(
        "CapabilityExecutor().execute("
    )
    assert "heartbeat_reservation" in helper
    assert "terminalize_capability_reservation(" in helper
    assert "persist_terminal(" in helper
    assert "automatically_scanned_discovered_hosts" in source
    assert standalone.index("_execute_scan_subdomain_discovery(") < standalone.index(
        "_hydrate_generic_scan_credentials("
    ) < standalone.index("run_scan(")
    assert "parallel_discovery" in shard
    assert shard.index("_execute_scan_subdomain_discovery(") < shard.index(
        "result = await run_scan("
    )
    assert "canonical_subdomain_discovery" in plan
    assert "needs_placed_discovery" in plan
    assert "canonical_subdomain_discovery" in merge
    assert "_attach_scan_subdomain_summary(" in merge
