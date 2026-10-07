"""Budget exhaustion keeps gathered leads recordable, and hosts are counted once.

Regression for soak defect 11 (2026-10-07, network Hunt 8fe2f65d, max_hosts=1): one
``ports.discover`` charged the single host, the next action on that same host was refused as
``budget_exhausted:hosts_attempted`` and terminated the Hunt, after which every candidate was
refused with 409 although the candidate budget was 0/20.
"""
from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

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
from runtime.budgets import reserve_budget_snapshot
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy, TargetBinding

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


def test_second_action_on_the_same_single_host_charges_no_new_host():
    discover = PortsDiscoverAdapter().prepare(target=TARGET, args={"profile": "top_100"}, policy=POLICY)
    first = host_accounting.distinct_host_charge({}, discover, dict(discover.estimated_budget))
    assert first["hosts_attempted"] == 1
    used = reserve_budget_snapshot(LIMITS, {key: 0 for key in LIMITS}, first)

    conn = RecordingConnection()
    asyncio.run(host_accounting.record_attempted_hosts(
        conn, hunt_id="h", run={"context_pack": {}}, prepared=discover,
        reserved=first, actual={"hosts_attempted": 1},
    ))
    (sql, args), = conn.updates
    assert "jsonb_set" in sql and args[1] == ["hosts_attempted_addresses"]
    context = {"hosts_attempted_addresses": [ADDRESS]}

    fingerprint = ServiceFingerprintAdapter().prepare(target=TARGET, args={"ports": [22]}, policy=POLICY)
    charges = host_accounting.distinct_host_charge(
        context, fingerprint, {**fingerprint.estimated_budget, "agent_actions": 1, "active_actions": 1},
    )
    assert charges["hosts_attempted"] == 0
    # Admission no longer reports a shortage on the dimension the first action already paid.
    reserve_budget_snapshot(LIMITS, used, charges)

    # The worker recomputes the full estimate, adopts the admitted hold, and both digests agree.
    worker_requested = {**fingerprint.estimated_budget, "agent_actions": 1, "active_actions": 1}
    bounded_requested, bounded = host_accounting.bound_distinct_hosts(worker_requested, fingerprint, charges)
    assert bounded_requested == charges
    digest = {"hunt_id": uuid.uuid4(), "action_id": uuid.uuid4(),
              "capability_name": "service.fingerprint", "target_kind": "network",
              "target_id": "target-1", "capability_input": {"ports": [22]},
              "scope_receipt_id": "scope-1", "approval_receipt_id": "approval-1"}
    assert hunt_capability_action_digest(**digest, requested_budget=charges) == \
        hunt_capability_action_digest(**digest, requested_budget=bounded_requested)

    # The adapter measures hosts against the bounded hold, so settlement is not a contract violation.
    result = asyncio.run(_run_fingerprint(bounded, bounded_requested))
    assert result.status in {"success", "partial"}
    assert not any("budget_contract_violation" in error for error in result.errors)
    assert result.actual_budget["hosts_attempted"] == 0
    assert result.actual_budget["tcp_ports_attempted"] == 1


def test_unknown_host_identity_keeps_the_conservative_full_charge():
    prepared = SimpleNamespace(commands=(), estimated_budget={"hosts_attempted": 1})
    charges = host_accounting.distinct_host_charge(
        {"hosts_attempted_addresses": [ADDRESS]}, prepared, {"hosts_attempted": 1},
    )
    assert charges["hosts_attempted"] == 1
    budget, same = host_accounting.bound_distinct_hosts({"hosts_attempted": 1}, prepared, {"hosts_attempted": 0})
    assert budget["hosts_attempted"] == 1 and same is prepared


def test_hosts_are_recorded_only_after_their_whole_hold_was_measured():
    discover = PortsDiscoverAdapter().prepare(target=TARGET, args={"profile": "top_100"}, policy=POLICY)
    conn = RecordingConnection()
    asyncio.run(host_accounting.record_attempted_hosts(
        conn, hunt_id="h", run={"context_pack": {}}, prepared=discover,
        reserved={"hosts_attempted": 1}, actual={"hosts_attempted": 0},
    ))
    assert conn.updates == []


def test_worker_network_job_adopts_and_records_the_distinct_host_hold():
    root = Path(__file__).resolve().parents[1]
    source = (root / "api" / "worker.py").read_text(encoding="utf-8")
    job = source[source.index("async def process_canonical_network_capability_job"):]
    job = job[:job.index("\nasync def ", 10)]
    adopt = job.index("bound_distinct_hosts(requested_budget, prepared, stored.record.requested)")
    assert adopt < job.index("recomputed_digest = hunt_capability_action_digest(")
    assert adopt < job.index("build_network_execution(prepared=prepared")
    assert "record_attempted_hosts(conn, hunt_id=hunt_id, run=locked, prepared=prepared" in job
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
