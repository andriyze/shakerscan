from __future__ import annotations

import asyncio
import json
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from runtime.models import ScanBudget, ScanPolicy, TargetBinding
from runtime.reservation_store import StoredBudgetReservation
from scan.broker_execution import (
    heartbeat_broker_scan_execution,
    reserve_broker_scan_execution,
    settle_broker_scan_execution,
)
from scan.execution import ScanExecutionPlan
from scan.executor import build_native_scan_execution


SCAN_ID = "11111111-1111-4111-8111-111111111111"


def _authority():
    plan = ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=True,
            allow_state_changing_http=True,
            scope_receipt_id="scope-1",
            approval_receipt_id="approval-1",
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
    options["_canonical_target_binding"] = target.canonical_dict()
    return plan, build_native_scan_execution(plan, options)


class _Connection:
    def __init__(self, plan):
        canonical = plan.canonical_dict()
        self.row = {
            "status": "pending",
            "policy_json": canonical["policy"],
            "budget_json": canonical["budget"],
            "budget_used_json": {
                "http_requests": 7,
                "state_changing_requests": 2,
                "browser_actions": 1,
                "tcp_ports_attempted": 0,
                "hosts_attempted": 1,
                "tool_wall_seconds": 5,
            },
        }

    async def fetchrow(self, query, *_args):
        if "policy_json" in query:
            return dict(self.row)
        if "SELECT status, budget_used_json" in query:
            return {
                "status": self.row["status"],
                "budget_used_json": dict(self.row["budget_used_json"]),
            }
        raise AssertionError(query)

    async def fetchval(self, query, *_args):
        if "SELECT status FROM scans" in query:
            return self.row["status"]
        raise AssertionError(query)

    async def execute(self, query, *_args):
        if "UPDATE scans SET budget_used_json" in query:
            self.row["budget_used_json"] = json.loads(_args[1])
            return "UPDATE 1"
        raise AssertionError(query)


class _Store:
    def __init__(self):
        self.current = None
        self.events = []

    async def load_by_action(
        self, _conn, *, owner_kind, owner_id, action_id, for_update=False,
    ):
        assert owner_kind == "scan"
        assert owner_id == SCAN_ID
        assert for_update is True
        if self.current is None or self.current.action_id != action_id:
            return None
        return self.current

    async def create_requested(
        self, _conn, *, action_id, action_digest, record,
    ):
        self.events.append(record.status)
        self.current = StoredBudgetReservation(
            action_id=action_id,
            action_digest=action_digest,
            record=record,
        )
        return self.current

    async def persist_transition(
        self, _conn, *, previous, current, ledger_after_hold=None,
    ):
        self.events.append(current.status)
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

    async def load(self, _conn, reservation_id, *, for_update=False):
        assert for_update is True
        if (
            self.current is None
            or self.current.record.reservation_id != reservation_id
        ):
            return None
        return self.current

    async def persist_terminal(
        self,
        _conn,
        *,
        previous,
        terminal,
        ledger_after_settlement,
        receipt,
    ):
        self.events.append(terminal.status)
        self.current = StoredBudgetReservation(
            action_id=previous.action_id,
            action_digest=previous.action_digest,
            record=terminal,
            ledger_after_hold=previous.ledger_after_hold,
            ledger_after_settlement=dict(ledger_after_settlement),
            receipt=receipt.public_dict() if receipt is not None else None,
        )
        return self.current


def test_broker_scan_reserves_before_lease_heartbeats_and_settles_exact_http():
    plan, execution = _authority()
    conn = _Connection(plan)
    store = _Store()

    admission = asyncio.run(reserve_broker_scan_execution(
        conn,
        scan_id=SCAN_ID,
        plan=plan,
        execution=execution,
        worker_id="broker:worker-1",
        lease_seconds=90,
        allocation_limits={
            "http_requests": 40,
            "state_changing_requests": 40,
        },
        store=store,
    ))

    assert admission.lease is not None
    assert store.events == ["requested", "reserved", "running"]
    assert admission.lease.runtime_budget == {
        "http_requests": 40,
        "state_changing_requests": 40,
        "browser_actions": 19,
        "tcp_ports_attempted": 0,
        "hosts_attempted": 49,
        "tool_wall_seconds": 55,
    }
    assert conn.row["budget_used_json"]["http_requests"] == 47
    metadata = admission.lease.storage_payload()

    conn.row["status"] = "running"
    heartbeat = asyncio.run(heartbeat_broker_scan_execution(
        conn, metadata=metadata, lease_seconds=90, store=store,
    ))
    assert heartbeat.record.status == "running"
    assert store.events[-1] == "running"

    result = {
        "scan_id": SCAN_ID,
        "job_id": "job-1",
        "findings": [{"id": "finding-1"}],
        "coverage": {"status": "complete"},
        "discovery": {"browser_crawl": {"pages_visited": 2}},
        "tls": {
            "canonical_runtime": {
                "schema_version": "canonical-tls-runtime/v1",
                "tcp_ports_attempted": 1,
            },
        },
        "request_budget": {
            "schema_version": "request_meter_v1",
            "mode": "enforce",
            "fully_metered": True,
            "attempted_requests": 3,
            "state_changing_attempted_requests": 1,
        },
        "scan_metadata": {"schema_version": "scan-report/v2"},
    }
    settled, summary = asyncio.run(settle_broker_scan_execution(
        conn, metadata=metadata, result=result, store=store,
    ))

    assert settled.record.status == "committed"
    assert settled.record.actual == {
        "http_requests": 3,
        "state_changing_requests": 1,
        "browser_actions": 2,
        "hosts_attempted": 1,
        # Remote elapsed time is not independently trusted.
        "tool_wall_seconds": 55,
    }
    assert conn.row["budget_used_json"]["http_requests"] == 10
    assert conn.row["budget_used_json"]["state_changing_requests"] == 3
    assert summary["durable_budget_settled"] is True
    assert summary["transport"] == "broker"

    replayed, replay_summary = asyncio.run(settle_broker_scan_execution(
        conn, metadata=metadata, result=result, store=store,
    ))
    assert replayed.record.state_digest == settled.record.state_digest
    assert replay_summary["idempotent_redelivery"] is True
    assert store.events.count("committed") == 1

    redelivery = asyncio.run(reserve_broker_scan_execution(
        conn,
        scan_id=SCAN_ID,
        plan=plan,
        execution=execution,
        worker_id="broker:worker-2",
        lease_seconds=90,
        allocation_limits={
            "http_requests": 40,
            "state_changing_requests": 40,
        },
        store=store,
    ))
    assert redelivery.lease is None
    assert redelivery.idempotent_redelivery is True
    assert store.events.count("requested") == 1


def test_broker_scan_refuses_to_lease_when_mandatory_budget_is_exhausted():
    plan, execution = _authority()
    conn = _Connection(plan)
    conn.row["budget_used_json"]["http_requests"] = 100
    store = _Store()

    admission = asyncio.run(reserve_broker_scan_execution(
        conn,
        scan_id=SCAN_ID,
        plan=plan,
        execution=execution,
        worker_id="broker:worker-1",
        lease_seconds=90,
        allocation_limits={
            "http_requests": 0,
            "state_changing_requests": 0,
        },
        store=store,
    ))

    assert admission.lease is None
    assert admission.stored.record.status == "failed"
    assert admission.stored.record.actual["http_requests"] == 0
    assert store.events == ["requested", "failed"]
