"""Budget exhaustion keeps gathered leads recordable, and hosts are counted once.

Regression for soak defect 11 (2026-10-07, network Hunt 8fe2f65d, max_hosts=1): one
``ports.discover`` charged the single host, the next action on that same host was refused as
``budget_exhausted:hosts_attempted`` and terminated the Hunt, after which every candidate was
refused with 409 although the candidate budget was 0/20.
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from capabilities.network import (
    NetworkExecutionAdapter,
    PortsDiscoverAdapter,
    ServiceFingerprintAdapter,
)
from hunt import host_accounting
from hunt import interaction_router as router
from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from hunt.capability_reservations import hunt_capability_action_digest
from runtime.budget_reservations import DurableBudgetReservation
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy, TargetBinding
from runtime.reservation_store import PostgresBudgetReservationStore

ADDRESS = "192.0.2.10"
TARGET = TargetBinding(
    target_id="target-1", target_kind="network", canonical_host=None,
    allowed_addresses=(ADDRESS,), scope_receipt_id="scope-1",
)
POLICY = ScanPolicy(active_testing=True, network_discovery=True, approval_receipt_id="approval-1")
LIMITS = {"hosts_attempted": 1, "tcp_ports_attempted": 200, "tool_wall_seconds": 600,
          "agent_actions": 10, "active_actions": 4}


class RecordingConnection:
    def __init__(self):
        self.updates = []

    async def execute(self, sql, *args):
        self.updates.append((sql, args))
        return "UPDATE 1"


async def _run_fingerprint(prepared, requested):
    async def run_command(argv, **_kwargs):
        return SimpleNamespace(stdout="", returncode=0, timed_out=False, partial=False,
                               stdout_truncated=False, cancelled=False)
    return await CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=CAPABILITY_REGISTRY.require("service.fingerprint"),
            target=TARGET, requested_budget=requested,
        ),
        NetworkExecutionAdapter(prepared=prepared, parser=ServiceFingerprintAdapter(),
                                command_runner=run_command, max_stdout_bytes=10_000,
                                max_stderr_bytes=1_000),
        heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False,
    )


HUNT_ID = str(uuid.uuid4())
WORKER = "network-worker-1"
RECEIPT_HASH = "a" * 64
DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")


def _digest(prepared, args, action_id, requested):
    return hunt_capability_action_digest(
        hunt_id=HUNT_ID, action_id=action_id, capability_name=prepared.capability_name,
        target_kind="network", target_id="target-1", capability_input=args,
        requested_budget=requested, scope_receipt_id="scope-1", approval_receipt_id="approval-1",
    )


def _admit(adapter, args, context):
    """The admission sequence of the network branch (interaction_router lines ~1894-2117)."""
    prepared = adapter.prepare(target=TARGET, args=args, policy=POLICY)
    charges = host_accounting.distinct_host_charge(context, prepared, {
        key: int(value) for key, value in prepared.estimated_budget.items() if key in LIMITS
    })
    charges["agent_actions"] = 1
    charges["active_actions"] = 1
    action_id = str(uuid.uuid4())
    record = DurableBudgetReservation.request(
        owner_kind="hunt", owner_id=HUNT_ID, capability_name=prepared.capability_name,
        amounts=charges,
    )
    return action_id, _digest(prepared, args, action_id, charges), record


def _worker_reconstruction(adapter, args, action_id, stored_requested, context):
    """The worker's rebuild and comparison (process_canonical_network_capability_job)."""
    prepared = adapter.prepare(target=TARGET, args=args, policy=POLICY)
    requested = {
        key: int(value) for key, value in prepared.estimated_budget.items() if key in LIMITS
    }
    requested["agent_actions"] = 1
    requested["active_actions"] = 1
    hosts = host_accounting.action_hosts(prepared)
    requested, prepared = host_accounting.bound_distinct_hosts(
        requested, prepared, stored_requested, context,
    )
    return hosts, requested, prepared, _digest(prepared, args, action_id, requested)


def _settle_first_discovery(context):
    discover_args = {"profile": "top_100"}
    action_id, digest, record = _admit(PortsDiscoverAdapter(), discover_args, context)
    assert record.requested["hosts_attempted"] == 1
    hosts, requested, _prepared, recomputed = _worker_reconstruction(
        PortsDiscoverAdapter(), discover_args, action_id, record.requested, context,
    )
    assert recomputed == digest and dict(record.requested) == requested
    reserved, used = record.reserve_against(limits=LIMITS, consumed={key: 0 for key in LIMITS})
    running = reserved.start(worker_id=WORKER)
    terminal = running.commit(actual={**requested, "hosts_attempted": 1},
                              execution_receipt_hash=RECEIPT_HASH)
    conn = RecordingConnection()
    asyncio.run(host_accounting.record_attempted_hosts(
        conn, hunt_id=HUNT_ID, run={"context_pack": context}, hosts=hosts,
        reserved=terminal.requested, actual=terminal.actual,
    ))
    (sql, args), = conn.updates
    assert "jsonb_set" in sql and args[1] == ["hosts_attempted_addresses"]
    return {"hosts_attempted_addresses": json.loads(args[2])}, used


def test_second_network_action_on_an_attempted_host_round_trips_through_the_reservation():
    context, used = _settle_first_discovery({})
    assert context == {"hosts_attempted_addresses": [ADDRESS]}

    args = {"ports": [22]}
    action_id, digest, record = _admit(ServiceFingerprintAdapter(), args, context)
    # The canonical durable shape omits the zero host grant; admission digests that shape.
    assert "hosts_attempted" not in record.requested
    reserved, _held = record.reserve_against(limits=LIMITS, consumed=used)

    _hosts, requested, bounded, recomputed = _worker_reconstruction(
        ServiceFingerprintAdapter(), args, action_id, reserved.requested, context,
    )
    # Exactly the worker's ReservationConflict predicate.
    assert recomputed == digest
    assert dict(reserved.requested) == requested
    assert "hosts_attempted" not in bounded.estimated_budget

    running = reserved.start(worker_id=WORKER)
    result = asyncio.run(_run_fingerprint(bounded, running.requested))
    assert result.status in {"success", "partial"}
    assert not any("budget_contract_violation" in error for error in result.errors)
    assert "hosts_attempted" not in result.actual_budget
    assert result.actual_budget["tcp_ports_attempted"] == 1
    terminal = running.commit(actual=result.actual_budget, execution_receipt_hash=RECEIPT_HASH)
    assert terminal.reconcile_consumed(used)["hosts_attempted"] == 1


def test_worker_refuses_a_zero_host_hold_for_a_host_this_hunt_has_not_attempted():
    args = {"ports": [22]}
    action_id, digest, record = _admit(
        ServiceFingerprintAdapter(), args, {"hosts_attempted_addresses": [ADDRESS]},
    )
    assert "hosts_attempted" not in record.requested
    # The worker's run row does not show the host as attempted: adopting the zero hold would let
    # it run uncounted, so the reconstruction keeps the full charge and the digests disagree.
    _hosts, requested, bounded, recomputed = _worker_reconstruction(
        ServiceFingerprintAdapter(), args, action_id, record.requested, {},
    )
    assert requested["hosts_attempted"] == 1
    assert bounded.estimated_budget["hosts_attempted"] == 1
    assert recomputed != digest and dict(record.requested) != requested


def test_partial_host_hold_charges_and_records_only_the_new_host():
    second = "192.0.2.11"
    target = TargetBinding(
        target_id="target-1", target_kind="network", canonical_host=None,
        allowed_addresses=(ADDRESS, second), scope_receipt_id="scope-1",
    )
    prepared = ServiceFingerprintAdapter().prepare(target=target, args={"ports": [22]}, policy=POLICY)
    context = {"hosts_attempted_addresses": [ADDRESS]}
    charges = host_accounting.distinct_host_charge(context, prepared, dict(prepared.estimated_budget))
    assert charges["hosts_attempted"] == 1
    record = DurableBudgetReservation.request(
        owner_kind="hunt", owner_id=HUNT_ID, capability_name="service.fingerprint",
        amounts={**charges, "agent_actions": 1},
    )
    hosts = host_accounting.action_hosts(prepared)
    requested, bounded = host_accounting.bound_distinct_hosts(
        dict(prepared.estimated_budget), prepared, record.requested, context,
    )
    assert requested["hosts_attempted"] == bounded.estimated_budget["hosts_attempted"] == 1
    conn = RecordingConnection()
    asyncio.run(host_accounting.record_attempted_hosts(
        conn, hunt_id=HUNT_ID, run={"context_pack": context}, hosts=hosts,
        reserved=record.requested, actual={"hosts_attempted": 1},
    ))
    (_sql, args), = conn.updates
    assert json.loads(args[2]) == [ADDRESS, second]


@pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")
def test_zero_host_hold_survives_postgres_reservation_persistence():
    import asyncpg

    context, _used = _settle_first_discovery({})

    async def scenario():
        assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
        schema = "hunt_host_hold_" + uuid.uuid4().hex
        conn = await asyncpg.connect(DSN)
        try:
            await conn.execute(f'CREATE SCHEMA "{schema}"')
            await conn.execute(f'SET search_path TO "{schema}"')
            store = PostgresBudgetReservationStore()
            await store.ensure_schema(conn)
            args = {"ports": [22]}
            action_id, digest, record = _admit(ServiceFingerprintAdapter(), args, context)
            await store.create_requested(conn, action_id=action_id, action_digest=digest, record=record)
            stored = await store.load(conn, record.reservation_id)
            _hosts, requested, _bounded, recomputed = _worker_reconstruction(
                ServiceFingerprintAdapter(), args, action_id, stored.record.requested, context,
            )
            assert recomputed == stored.action_digest == digest
            assert dict(stored.record.requested) == requested
        finally:
            await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            await conn.close()

    asyncio.run(scenario())


def test_unknown_host_identity_keeps_the_conservative_full_charge():
    prepared = SimpleNamespace(commands=(), estimated_budget={"hosts_attempted": 1})
    charges = host_accounting.distinct_host_charge(
        {"hosts_attempted_addresses": [ADDRESS]}, prepared, {"hosts_attempted": 1},
    )
    assert charges["hosts_attempted"] == 1
    budget, same = host_accounting.bound_distinct_hosts(
        {"hosts_attempted": 1}, prepared, {}, {"hosts_attempted_addresses": [ADDRESS]},
    )
    assert budget["hosts_attempted"] == 1 and same is prepared


def test_hosts_are_recorded_only_after_their_whole_hold_was_measured():
    discover = PortsDiscoverAdapter().prepare(target=TARGET, args={"profile": "top_100"}, policy=POLICY)
    conn = RecordingConnection()
    asyncio.run(host_accounting.record_attempted_hosts(
        conn, hunt_id="h", run={"context_pack": {}}, hosts=host_accounting.action_hosts(discover),
        reserved={"hosts_attempted": 1}, actual={"hosts_attempted": 0},
    ))
    assert conn.updates == []


def test_worker_network_job_adopts_and_records_the_distinct_host_hold():
    # The behavior is exercised above; this pins that the worker job uses those helpers in order.
    root = Path(__file__).resolve().parents[1]
    source = (root / "api" / "worker.py").read_text(encoding="utf-8")
    job = source[source.index("async def process_canonical_network_capability_job"):]
    job = job[:job.index("\nasync def ", 10)]
    hosts = job.index("attempted_hosts = action_hosts(prepared)")
    adopt = job.index(
        "bound_distinct_hosts(requested_budget, prepared, stored.record.requested, context)"
    )
    assert hosts < adopt < job.index("recomputed_digest = hunt_capability_action_digest(")
    assert adopt < job.index("build_network_execution(prepared=prepared")
    assert "record_attempted_hosts(conn, hunt_id=hunt_id, run=locked, hosts=attempted_hosts" in job
    admission = Path(router.__file__).read_text(encoding="utf-8")
    assert "charges = distinct_host_charge(context, prepared_network, {" in admission


@pytest.mark.asyncio
@pytest.mark.parametrize("status,allowed", [
    ("budget_exhausted", True), ("active", True), ("completed", False), ("cancelled", False),
])
async def test_candidates_are_recordable_after_budget_exhaustion(monkeypatch, status, allowed):
    action = str(uuid.uuid4())
    hunt = str(uuid.uuid4())
    writes = []

    class Store:
        @asynccontextmanager
        async def acquire(self):
            yield self

        @asynccontextmanager
        async def transaction(self, **_kwargs):
            yield self

        async def fetch(self, _sql, *args):
            return [{"id": action, "kind": "action"}] if action in args[0] else []

        async def execute(self, sql, *args):
            writes.append(sql)

    run = {"id": hunt, "target_id": str(uuid.uuid4()), "device_target_id": None, "status": status,
           "objective": "o", "context_pack": {}, "budget_used_json": {"candidates": 0},
           "budget_json": {"max_candidates": 20}}

    async def lookup(_conn, _hunt_id, for_update=False):
        return run

    async def upsert(_conn, candidate, **_kwargs):
        return {"id": str(uuid.uuid4()), "outcome": "inserted", "inserted": True}

    monkeypatch.setattr(router, "_pool", lambda: Store())
    monkeypatch.setattr(router, "_hunt_run_or_404", lookup)
    monkeypatch.setattr(router.investigation_candidates, "upsert_candidate", upsert)
    request = router.HuntCandidateRequest(
        family="device_service_exposure", locus={"transport": "tcp", "port": 22},
        title="SSH exposed", claim="22/tcp open", evidence_refs=[action],
    )
    if allowed:
        result = await router.create_hunt_candidate(hunt, request)
        assert result["candidate"]["outcome"] == "inserted"
        assert any("budget_used_json" in sql for sql in writes)
    else:
        with pytest.raises(router.HTTPException) as exc:
            await router.create_hunt_candidate(hunt, request)
        assert exc.value.status_code == 409
