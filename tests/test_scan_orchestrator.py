from __future__ import annotations

import asyncio
import hashlib
import uuid

import pytest

from api.runtime.observation_manifests import ObservationManifest
from api.scan.action_plan import ScanAction, ScanActionPlan
from api.scan.capability_result import (
    CapabilityReceiptReference,
    CapabilityResultReason,
    CapabilityResultReference,
    CapabilityResultStatus,
)
from api.scan.execution_backend import (
    ActionAlreadyTerminal,
    ActionLease,
    ActionLeaseLost,
    PostgresScanExecutionBackend,
)
from api.scan.orchestrator import ScanOrchestrator


SCAN_ID = "30000000-0000-4000-8000-000000000001"


def _action(
    action_id: str,
    ordinal: int,
    *,
    dependencies: tuple[str, ...] = (),
    capability_name: str = "http.request",
) -> ScanAction:
    return ScanAction(
        action_id=action_id,
        stage="finalize_evidence" if action_id == "finalize.report" else "deterministic_baseline",
        ordinal=ordinal,
        capability_name="scan.execute" if action_id == "finalize.report" else capability_name,
        capability_args={"report_only": True} if action_id == "finalize.report" else {"method": "GET"},
        target_binding_digest="a" * 64,
        input_binding_digest=hashlib.sha256(action_id.encode()).hexdigest(),
        requested_budget={"http_requests": 1, "tool_wall_seconds": 2},
        placement={
            "eligible_backends": ["local", "broker"],
            "adapter_name": "scanner.dast" if action_id == "finalize.report" else "httpx",
            "adapter_version": "1",
        },
        dependencies=dependencies,
        required=True,
        supporting=False,
        output_schema="scan-report/v1" if action_id == "finalize.report" else "http-observation/v1",
    )


def _plan() -> ScanActionPlan:
    first = _action("baseline.http", 0)
    second = _action("baseline.security_txt", 1, dependencies=(first.action_id,))
    final = _action(
        "finalize.report", 2, dependencies=(first.action_id, second.action_id),
    )
    return ScanActionPlan(
        scan_id=SCAN_ID,
        execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64,
        actions=(first, second, final),
    )


def _result(
    action: ScanAction,
    *,
    status: CapabilityResultStatus,
    reason: CapabilityResultReason | None = None,
    charge_full: bool = False,
    namespace: str = "shared",
) -> CapabilityResultReference:
    success_like = status in {CapabilityResultStatus.SUCCESS, CapabilityResultStatus.PARTIAL}
    manifest = None
    if success_like:
        manifest = ObservationManifest(
            manifest_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"manifest:{namespace}:{action.action_id}")),
            owner_id=SCAN_ID,
            action_id=action.action_id,
            capability_name=action.capability_name,
            output_schema=action.output_schema,
            observation_count=0,
            content_sha256=hashlib.sha256(b"").hexdigest(),
            size_bytes=0,
            object_key=f"scans/{SCAN_ID}/{action.action_id}.jsonl",
        ).reference()
    return CapabilityResultReference(
        action_id=action.action_id,
        action_digest=action.action_digest,
        capability_name=action.capability_name,
        adapter_name=str(action.placement["adapter_name"]),
        adapter_version=str(action.placement["adapter_version"]),
        output_schema=action.output_schema,
        status=status,
        partial=status in {CapabilityResultStatus.PARTIAL, CapabilityResultStatus.TIMED_OUT},
        timed_out=status is CapabilityResultStatus.TIMED_OUT,
        reason_code=reason,
        receipt_ref=CapabilityReceiptReference(
            receipt_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"receipt:{namespace}:{action.action_id}:{status.value}")),
            receipt_hash=hashlib.sha256(
                f"{namespace}:{action.action_id}:{status.value}".encode()
            ).hexdigest(),
        ),
        observation_manifest_ref=manifest,
        budget_reserved=action.requested_budget,
        budget_consumed=(action.requested_budget if charge_full else {}),
    )


class FakeBackend:
    def __init__(self, plan: ScanActionPlan, backend_name: str, *, cancelled=False):
        self.plan = plan
        self.backend_name = backend_name
        self.results: dict[str, CapabilityResultReference] = {}
        self.cancelled = cancelled
        self.acquired: list[str] = []
        self.heartbeats: list[str] = []
        self.terminal_races: set[str] = set()

    async def acquire_action(self, action):
        if action.action_id in self.terminal_races:
            raise ActionAlreadyTerminal(action.action_id)
        self.acquired.append(action.action_id)
        return ActionLease(
            lease_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"lease:{self.backend_name}:{action.action_id}")),
            lease_token="0123456789abcdef0123456789abcdef",
            scan_id=self.plan.scan_id,
            plan_digest=self.plan.plan_digest,
            execution_plan_digest=self.plan.execution_plan_digest,
            target_binding_digest=self.plan.target_binding_digest,
            action=action,
            backend=self.backend_name,
            worker_id=f"{self.backend_name}-worker-1",
            lease_seconds=30,
            attempt=1,
        )

    async def heartbeat(self, lease):
        self.heartbeats.append(lease.action.action_id)

    async def settle(self, lease, result):
        existing = self.results.get(lease.action.action_id)
        if existing is not None:
            return existing
        self.results[lease.action.action_id] = result
        return result

    async def load_result(self, action_id):
        return self.results.get(action_id)

    async def cancellation_requested(self):
        return self.cancelled


class FakeExecutor:
    def __init__(self, *, fail_action: str | None = None, lose_action: str | None = None):
        self.fail_action = fail_action
        self.lose_action = lose_action
        self.executed: list[str] = []
        self.synthetic: list[tuple[str, str, bool]] = []

    async def execute(self, action, lease, heartbeat):
        self.executed.append(action.action_id)
        await heartbeat()
        if action.action_id == self.lose_action:
            raise ActionLeaseLost("node lost")
        if action.action_id == self.fail_action:
            return _result(
                action,
                status=CapabilityResultStatus.FAILED,
                reason=CapabilityResultReason.ADAPTER_FAILED,
                charge_full=True,
            )
        return _result(action, status=CapabilityResultStatus.SUCCESS)

    async def terminal_without_execution(
        self, action, lease, *, status, reason_code, charge_full_reservation,
    ):
        self.synthetic.append((action.action_id, status, charge_full_reservation))
        return _result(
            action,
            status=CapabilityResultStatus(status),
            reason=CapabilityResultReason(reason_code),
            charge_full=charge_full_reservation,
        )


def _run(orchestrator, plan):
    return asyncio.run(orchestrator.run(plan))


def test_local_and_broker_backends_produce_identical_action_and_status_matrices():
    plan = _plan()
    reports = []
    for backend_name in ("local", "broker"):
        backend = FakeBackend(plan, backend_name)
        report = _run(
            ScanOrchestrator(backend=backend, executor=FakeExecutor()), plan,
        )
        reports.append(report)
        assert backend.acquired == [action.action_id for action in plan.actions]
        assert backend.heartbeats

    assert reports[0].action_ids == reports[1].action_ids
    assert reports[0].status_matrix == reports[1].status_matrix
    assert set(reports[0].status_matrix.values()) == {"success"}


def test_resume_reuses_terminal_results_and_only_runs_remaining_actions():
    plan = _plan()
    backend = FakeBackend(plan, "local")
    backend.results[plan.actions[0].action_id] = _result(
        plan.actions[0], status=CapabilityResultStatus.SUCCESS,
    )
    executor = FakeExecutor()

    report = _run(ScanOrchestrator(backend=backend, executor=executor), plan)

    assert report.action_ids == tuple(action.action_id for action in plan.actions)
    assert executor.executed == ["baseline.security_txt", "finalize.report"]
    assert backend.acquired == ["baseline.security_txt", "finalize.report"]


def test_failed_dependency_is_blocked_but_receipt_driven_finalizer_still_runs():
    plan = _plan()
    backend = FakeBackend(plan, "local")
    executor = FakeExecutor(fail_action="baseline.http")

    report = _run(ScanOrchestrator(backend=backend, executor=executor), plan)

    assert report.status_matrix == {
        "baseline.http": "failed",
        "baseline.security_txt": "blocked",
        "finalize.report": "success",
    }
    assert executor.executed == ["baseline.http", "finalize.report"]
    assert ("baseline.security_txt", "blocked", False) in executor.synthetic


def test_node_loss_charges_full_hold_and_resume_continues_from_terminal_receipt():
    plan = _plan()
    backend = FakeBackend(plan, "broker")
    executor = FakeExecutor(lose_action="baseline.http")

    report = _run(ScanOrchestrator(backend=backend, executor=executor), plan)

    failed = report.action_results["baseline.http"]
    assert failed.status is CapabilityResultStatus.FAILED
    assert dict(failed.budget_consumed) == dict(plan.actions[0].requested_budget)
    assert report.status_matrix["baseline.security_txt"] == "blocked"
    assert report.status_matrix["finalize.report"] == "success"


def test_cancellation_terminalizes_current_and_residual_actions_without_execution():
    plan = _plan()
    backend = FakeBackend(plan, "local", cancelled=True)
    executor = FakeExecutor()

    report = _run(ScanOrchestrator(backend=backend, executor=executor), plan)

    assert set(report.status_matrix.values()) == {"cancelled"}
    assert executor.executed == []
    assert len(executor.synthetic) == len(plan.actions)


def test_duplicate_lease_reuses_the_already_terminal_result():
    plan = _plan()
    backend = FakeBackend(plan, "local")
    first = plan.actions[0]
    backend.results[first.action_id] = _result(
        first, status=CapabilityResultStatus.SUCCESS,
    )
    # Simulate a terminal race for the second action after the initial load.
    second = plan.actions[1]
    original_load = backend.load_result
    loads = {second.action_id: 0}

    async def raced_load(action_id):
        if action_id == second.action_id:
            loads[action_id] += 1
            if loads[action_id] == 1:
                backend.results[action_id] = _result(
                    second, status=CapabilityResultStatus.SUCCESS,
                )
                backend.terminal_races.add(action_id)
                return None
        return await original_load(action_id)

    backend.load_result = raced_load
    executor = FakeExecutor()
    report = _run(ScanOrchestrator(backend=backend, executor=executor), plan)

    assert report.status_matrix[second.action_id] == "success"
    assert second.action_id not in executor.executed
    assert executor.executed == ["finalize.report"]


class _PoolLease:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return _PoolLease(self.conn)


class FakePostgresConn:
    def __init__(self, plan):
        self.scan_status = "running"
        self.rows = {
            action.action_id: {
                "status": "planned",
                "action_digest": action.action_digest,
                "attempt": 0,
                "result_json": None,
            }
            for action in plan.actions
        }

    async def fetchrow(self, query, *args):
        action_id = str(args[1])
        row = self.rows[action_id]
        if "SET status='leased'" in query:
            if row["status"] != "planned" or row["action_digest"] != args[2]:
                return None
            row.update({
                "status": "leased",
                "backend_name": args[5],
                "worker_id": args[6],
                "lease_id": args[7],
                "lease_token_hash": args[8],
                "lease_expires_at": args[9],
                "attempt": row["attempt"] + 1,
            })
            return {"attempt": row["attempt"]}
        if "SET status='running'" in query:
            if (
                row["status"] not in {"leased", "running"}
                or row["lease_id"] != args[3]
                or row["lease_token_hash"] != args[4]
                or row["worker_id"] != args[5]
            ):
                return None
            row["status"] = "running"
            row["lease_expires_at"] = args[6]
            return {"lease_expires_at": row["lease_expires_at"]}
        if "SET status=$7" in query:
            if (
                row["status"] not in {"leased", "running"}
                or row["lease_id"] != args[3]
                or row["lease_token_hash"] != args[4]
                or row["worker_id"] != args[5]
            ):
                return None
            row.update({
                "status": args[6],
                "reason_code": args[7],
                "receipt_id": args[8],
                "receipt_hash": args[9],
                "observation_manifest_id": args[10],
                "result_digest": args[11],
                "result_json": args[12],
                "lease_token_hash": None,
                "lease_expires_at": None,
            })
            return {"result_json": row["result_json"]}
        if "SELECT status, result_json, action_digest" in query:
            return dict(row)
        if "SELECT status, action_digest, result_json" in query:
            return dict(row)
        raise AssertionError(query)

    async def fetchval(self, query, *args):
        assert "SELECT status FROM scans" in query
        return self.scan_status


def test_postgres_backend_hashes_lease_token_and_settles_generic_result_atomically():
    plan = _plan()
    conn = FakePostgresConn(plan)
    backend = PostgresScanExecutionBackend(
        pool=FakePool(conn),
        plan=plan,
        worker_id="local-worker-1",
        token_factory=lambda: "abcdefghijklmnopqrstuvwxyz012345",
    )
    action = plan.actions[0]

    lease = asyncio.run(backend.acquire_action(action))
    stored_row = conn.rows[action.action_id]
    assert stored_row["lease_token_hash"] != lease.lease_token
    assert stored_row["lease_token_hash"] == hashlib.sha256(
        lease.lease_token.encode()
    ).hexdigest()
    asyncio.run(backend.heartbeat(lease))
    result = _result(action, status=CapabilityResultStatus.SUCCESS)
    settled = asyncio.run(backend.settle(lease, result))

    assert settled == result
    assert asyncio.run(backend.load_result(action.action_id)) == result
    assert stored_row["status"] == "success"
    assert stored_row["lease_token_hash"] is None
    assert stored_row["result_digest"] == result.result_digest


def test_postgres_backend_fails_closed_after_lease_authority_is_lost():
    plan = _plan()
    conn = FakePostgresConn(plan)
    backend = PostgresScanExecutionBackend(
        pool=FakePool(conn),
        plan=plan,
        worker_id="local-worker-1",
        token_factory=lambda: "abcdefghijklmnopqrstuvwxyz012345",
    )
    action = plan.actions[0]
    lease = asyncio.run(backend.acquire_action(action))
    conn.rows[action.action_id]["lease_token_hash"] = "f" * 64

    with pytest.raises(ActionLeaseLost, match="heartbeat"):
        asyncio.run(backend.heartbeat(lease))
    with pytest.raises(ActionLeaseLost, match="settlement"):
        asyncio.run(backend.settle(
            lease, _result(action, status=CapabilityResultStatus.SUCCESS),
        ))


def test_postgres_backend_cancellation_and_remote_payload_are_database_free():
    plan = _plan()
    conn = FakePostgresConn(plan)
    backend = PostgresScanExecutionBackend(
        pool=FakePool(conn),
        plan=plan,
        worker_id="broker-worker-1",
        backend_name="broker",
        token_factory=lambda: "abcdefghijklmnopqrstuvwxyz012345",
    )
    conn.scan_status = "cancelling"
    assert asyncio.run(backend.cancellation_requested()) is True

    lease = asyncio.run(backend.acquire_action(plan.actions[0]))
    payload = lease.remote_payload()
    flattened = str(payload).lower()
    assert payload["action"]["action_id"] == plan.actions[0].action_id
    assert payload["action"]["requested_budget"] == dict(plan.actions[0].requested_budget)
    assert payload["action"]["dependencies"] == list(plan.actions[0].dependencies)
    assert not any(name in flattened for name in ("database_url", "postgres", "redis_url"))
