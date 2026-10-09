"""A revoked or expired target authorization stops a running local Scan (PostgreSQL).

The local path is composed exactly as ``_execute_reserved_deterministic_scan`` composes it:
the real ``PostgresScanExecutionBackend`` (durable leases and budget reservations), the real
``ReceiptScanActionExecutor`` and ``ScanOrchestrator``, and the real ``ScanAuthorityGuard``
over the installed schema. Only the dispatcher is a fixture (``FixtureToolDispatcher``): it
records which actions ran and, for a long action, runs a fixture tool process (``sleep``)
that it stops when the action is interrupted, as the worker's process runner does. No target
is contacted.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from tests.disposable_postgres import require_disposable_database  # noqa: E402
import retest_contract  # noqa: E402
import target_authorization  # noqa: E402
from targets.asset_migration import BoundConnectionPool  # noqa: E402
from runtime.models import ScanPolicy, TargetBinding  # noqa: E402
from runtime.receipts import CapabilityReceipt  # noqa: E402
from scan.action_authority_guard import AUTHORIZATION_WITHDRAWN, ScanAuthorityGuard  # noqa: E402
from scan.action_interruption import action_interrupted  # noqa: E402
from scan.action_plan import ScanAction, ScanActionPlan  # noqa: E402
from scan.action_store import PostgresScanActionStore  # noqa: E402
from scan.execution_backend import PostgresScanExecutionBackend  # noqa: E402
from scan.orchestrator import ScanOrchestrator  # noqa: E402
from scan.worker_action_executor import ReceiptScanActionExecutor  # noqa: E402

DSN_ENV = "TARGET_ASSET_TEST_DATABASE_URL"
TEMPLATE = "scan_revocation_template_" + uuid.uuid4().hex[:12]


def _dsn() -> str:
    dsn = os.environ.get(DSN_ENV)
    if not dsn:
        pytest.skip(f"{DSN_ENV} is not configured")
    database = dsn.rsplit("/", 1)[-1]
    return require_disposable_database(dsn, database)


@pytest.fixture(scope="module")
def template_database():
    """One installed schema (db/init.sql plus every startup migration), cloned per test."""
    asyncpg = pytest.importorskip("asyncpg")
    dsn = _dsn()

    async def create():
        admin = await asyncpg.connect(dsn)
        try:
            await admin.execute(f'CREATE DATABASE "{TEMPLATE}"')
        finally:
            await admin.close()
        conn = await asyncpg.connect(dsn, database=TEMPLATE)
        try:
            await conn.execute((ROOT / "db/init.sql").read_text())
            await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
        finally:
            await conn.close()

    async def drop():
        admin = await asyncpg.connect(dsn)
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{TEMPLATE}" WITH (FORCE)')
        finally:
            await admin.close()

    asyncio.run(create())
    yield TEMPLATE
    asyncio.run(drop())


@asynccontextmanager
async def scan_database(template: str):
    import asyncpg
    dsn = _dsn()
    name = "scan_revocation_" + uuid.uuid4().hex
    admin = await asyncpg.connect(dsn)
    pool = None
    try:
        await admin.execute(f'CREATE DATABASE "{name}" TEMPLATE "{template}"')
        pool = await asyncpg.create_pool(dsn, database=name, min_size=1, max_size=4)
        yield pool
    finally:
        if pool is not None:
            await pool.close()
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await admin.close()


def _action(action_id: str, ordinal: int, capability: str, dependencies=()) -> ScanAction:
    final = action_id == "finalize.report"
    return ScanAction(
        action_id=action_id,
        stage="finalize_evidence" if final else "deterministic_baseline",
        ordinal=ordinal,
        capability_name=capability,
        capability_args={"report_only": True} if final else {"method": "GET"},
        target_binding_digest="a" * 64,
        input_binding_digest=hashlib.sha256(action_id.encode()).hexdigest(),
        requested_budget={"http_requests": 1, "tool_wall_seconds": 30},
        placement={"eligible_backends": ["local"], "adapter_name": "fixture", "adapter_version": "1"},
        dependencies=tuple(dependencies),
        required=True,
        supporting=False,
        output_schema="scan-report/v2" if final else "http-observation/v1",
    )


def _active_plan(scan_id: uuid.UUID) -> ScanActionPlan:
    """A passive probe, then two active template actions, then the report."""
    first = _action("baseline.http", 0, "http.request")
    active = _action("templates.active", 1, "templates.scan", (first.action_id,))
    later = _action("templates.followup", 2, "templates.scan", (active.action_id,))
    final = _action("finalize.report", 3, "scan.finalize", (first.action_id, active.action_id, later.action_id))
    return ScanActionPlan(scan_id=str(scan_id), execution_plan_digest="b" * 64,
                          target_binding_digest="a" * 64, actions=(first, active, later, final))


@dataclass
class FixtureToolDispatcher:
    """Fixture dispatcher: records actions; ``long_actions`` run a fixture ``sleep`` process."""

    target_id: str
    scan_id: str
    long_actions: frozenset[str] = frozenset()
    during: dict[str, object] = field(default_factory=dict)
    after: dict[str, object] = field(default_factory=dict)
    dispatched: list[str] = field(default_factory=list)
    process_exits: dict[str, tuple[int | None, float]] = field(default_factory=dict)

    async def __call__(self, action, lease, heartbeat):
        self.dispatched.append(action.action_id)
        status, errors = "success", ()
        if action.action_id in self.long_actions:
            process = await asyncio.create_subprocess_exec("sleep", "30")
            hook = self.during.get(action.action_id)
            task = asyncio.create_task(hook()) if hook else None
            try:
                while process.returncode is None:
                    if action_interrupted():  # the process runner's stop, every 50 ms
                        process.terminate()
                        await process.wait()
                        status, errors = "cancelled", ("cancelled",)
                        break
                    try:
                        await asyncio.wait_for(process.wait(), timeout=0.05)
                    except asyncio.TimeoutError:
                        pass
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
                if task is not None:
                    await task
            self.process_exits[action.action_id] = (process.returncode, time.monotonic())
        hook = self.after.get(action.action_id)
        if hook:
            await hook()
        now = datetime.now(timezone.utc).isoformat()
        return CapabilityReceipt(
            capability_name=action.capability_name, adapter_name="fixture", adapter_version="1",
            target_id=self.target_id, scan_id=self.scan_id, worker_id="local:fixture", status=status,
            input_digest=action.action_digest, parser_version="fixture/v1", started_at=now, finished_at=now,
            budget_reserved=action.requested_budget,
            budget_consumed={"http_requests": 1, "tool_wall_seconds": 1}, errors=errors,
            observations=({"kind": "http_response", "status_code": 200},),
        )


@dataclass
class Scan:
    pool: object
    target_id: uuid.UUID
    scan_id: uuid.UUID
    plan: ScanActionPlan
    binding: TargetBinding
    policy: ScanPolicy
    events: list[str] = field(default_factory=list)

    def guard(self, **kwargs) -> ScanAuthorityGuard:
        return ScanAuthorityGuard.for_scan(self.pool, target_binding=self.binding, policy=self.policy,
                                           record_event=self.events.append, **kwargs)

    async def run(self, dispatcher, guard):
        backend = PostgresScanExecutionBackend(pool=self.pool, plan=self.plan, worker_id="local:fixture",
                                               backend_name="local")
        executor = ReceiptScanActionExecutor(
            scan_id=str(self.scan_id), target_id=str(self.target_id), worker_id="local:fixture",
            dispatcher=dispatcher, scope_receipt_id=self.binding.scope_receipt_id,
            approval_receipt_id=self.policy.approval_receipt_id, authority=guard)
        return await ScanOrchestrator(backend=backend, executor=executor).run(self.plan)

    async def actions(self) -> dict[str, tuple[str, str | None]]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("SELECT action_id, status, reason_code FROM scan_capability_actions "
                                    "WHERE scan_id=$1", self.scan_id)
        return {row["action_id"]: (row["status"], row["reason_code"]) for row in rows}

    async def held_reservations(self) -> int:
        async with self.pool.acquire() as conn:
            return await conn.fetchval(
                """SELECT count(*) FROM budget_reservations WHERE owner_kind='scan' AND owner_id=$1
                     AND status IN ('reserved','running')""", str(self.scan_id))

    async def revoke(self) -> int:
        async with self.pool.acquire() as conn:
            return await target_authorization.revoke_target_authorization(
                conn, self.target_id, revoked_by="fixture-owner", reason="fixture revoke mid-scan")


async def _scan(pool, *, url="http://revocation.test", active=True, plan=None, approval=None,
                authorize=True) -> Scan:
    async with pool.acquire() as conn:
        target_id = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", url)
        scope_id = None
        approval_id = approval
        if authorize:
            standing = await target_authorization.authorize_target(conn, target_id, approved_by="fixture-owner")
            scope_id = str(standing["scope_receipt_id"])
            approval_id = approval or (str(standing["approval_receipt_id"]) if active else None)
        else:
            receipt = (await target_authorization.evaluate_target_scope(conn, target_id))["receipt"]
            await target_authorization.persist_scope_receipt(conn, receipt, target_id)
            scope_id = receipt["receipt_id"]
        scan_id = uuid.uuid4()
        await conn.execute(
            """INSERT INTO scans (id,target_id,target_url,status,scan_generation,budget_json,budget_used_json)
               VALUES ($1,$2,$3,'running','canonical',$4::jsonb,'{}'::jsonb)""",
            scan_id, target_id, url, json.dumps({
                "max_duration_seconds": 600, "max_http_requests": 50, "max_endpoints": 50,
                "max_browser_actions": 0, "max_tcp_ports": 0, "max_tool_wall_seconds": 600,
                "max_workers": 1, "max_state_changing_requests": 0, "max_hosts": 1}))
        plan = (plan or _active_plan)(scan_id)
        await PostgresScanActionStore().persist_plan(conn, plan=plan)
    host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    binding = TargetBinding(target_id=str(target_id), target_kind="web", canonical_host=host,
                            allowed_origins=(url,), environment="lab", scope_receipt_id=scope_id)
    policy = ScanPolicy(active_testing=active, approval_receipt_id=approval_id, scope_receipt_id=scope_id)
    return Scan(pool=pool, target_id=target_id, scan_id=scan_id, plan=plan, binding=binding, policy=policy)


def test_a_revoke_between_actions_stops_the_next_action_with_its_reason(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               after={"baseline.http": scan.revoke})
            guard = scan.guard()
            result = await scan.run(dispatcher, guard)
            # The active action after the revoke never ran; only the zero-traffic report did.
            assert dispatcher.dispatched == ["baseline.http", "finalize.report"]
            actions = await scan.actions()
            assert actions["baseline.http"][0] == "success"  # what ran before the revoke stays
            assert actions["templates.active"] == ("blocked", "authorization_revoked")
            assert actions["templates.followup"] == ("blocked", "dependency_failed")
            assert result.status_matrix["templates.active"] == "blocked"
            assert await scan.held_reservations() == 0
            assert guard.reason == "authorization_revoked" and "approval_revocation" in scan.events
            report = await guard.annotate({"coverage": {"status": "complete", "reasons": []}},
                                          scan_id=str(scan.scan_id))
            stop = report["scan_metadata"]["authority_stop"]
            assert report["scan_metadata"]["stop_reason"] == AUTHORIZATION_WITHDRAWN
            assert stop["not_run_actions"] == ["templates.active", "templates.followup"]
            assert report["coverage"] == {"status": "partial", "reasons": [AUTHORIZATION_WITHDRAWN]}
            metadata = report["scan_metadata"]
            assert metadata["status"] == "partial" and metadata["partial"] is True
            assert metadata["grade_reliable"] is False
            assert AUTHORIZATION_WITHDRAWN in metadata["grade_reliability_reasons"]
    asyncio.run(run())


def test_a_revoke_during_a_long_action_stops_its_tool_process_within_seconds(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            revoked_at = {}

            async def revoke_soon():
                await asyncio.sleep(0.5)
                revoked_at["t"] = time.monotonic()
                assert await scan.revoke() == 1

            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               long_actions=frozenset({"baseline.http"}),
                                               during={"baseline.http": revoke_soon})
            guard = scan.guard()  # the production 2 s poll
            await scan.run(dispatcher, guard)
            returncode, exited_at = dispatcher.process_exits["baseline.http"]
            assert returncode is not None and returncode < 0  # stopped by a signal, not finished
            assert exited_at - revoked_at["t"] < 3.0
            actions = await scan.actions()
            assert actions["baseline.http"] == ("partial", "authorization_revoked")
            assert actions["templates.active"] == ("blocked", "authorization_revoked")
            assert dispatcher.dispatched == ["baseline.http", "finalize.report"]
            assert guard.interrupted_actions == ["baseline.http"]
            assert await scan.held_reservations() == 0
    asyncio.run(run())


def test_expiry_during_a_long_action_stops_it_as_expired(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            async with pool.acquire() as conn:  # a bounded approval for this target, 1.5 s left
                bounded = await conn.fetchval(
                    """INSERT INTO approval_receipts(scope_receipt_id,risk_tier,confirmations,action_name,
                           action_context,approved_by,expires_at)
                       VALUES($1,'active','["confirm_authorized"]','scan.submit','{}','fixture-owner',
                              NOW()+INTERVAL '1500 milliseconds') RETURNING id""",
                    scan.binding.scope_receipt_id)
            scan.policy = ScanPolicy(active_testing=True, approval_receipt_id=str(bounded),
                                     scope_receipt_id=scan.binding.scope_receipt_id)
            # The long action is active, so it needs the approval for as long as it runs.
            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               long_actions=frozenset({"templates.active"}))
            guard = scan.guard(poll_seconds=0.5)
            started = time.monotonic()
            await scan.run(dispatcher, guard)
            assert time.monotonic() - started < 6.0
            actions = await scan.actions()
            assert actions["baseline.http"][0] == "success"
            assert actions["templates.active"] == ("partial", "authorization_expired")
            assert actions["templates.followup"] == ("blocked", "authorization_expired")
            assert await scan.held_reservations() == 0
    asyncio.run(run())


def test_a_scan_without_revocation_is_unaffected_and_polling_is_bounded(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            counted = CountingPool(pool)
            # The active action runs 2.2 s; nothing changes while it does.
            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               after={"templates.active": lambda: asyncio.sleep(2.2)})
            guard = scan.guard(poll_seconds=0.2)
            guard.pool = counted
            await scan.run(dispatcher, guard)
            actions = await scan.actions()
            assert {status for status, _reason in actions.values()} == {"success"}
            assert dispatcher.dispatched == [action.action_id for action in scan.plan.actions]
            assert guard.reason is None and not scan.events
            # One full check before each of the three non-report actions, none while nothing changed.
            assert guard.full_checks == 3
            # About one poll per 0.2 s of the 2.2 s action, each a single statement.
            assert 8 <= guard.polls <= 12
            assert counted.statements_by_kind["fingerprint"] == guard.polls + guard.full_checks
            report = {"coverage": {"status": "complete", "reasons": []}}
            assert await guard.annotate(dict(report), scan_id=str(scan.scan_id)) == report
    asyncio.run(run())


class CountingPool:
    """Counts statements the guard sends; ``fingerprint`` is the in-flight poll query."""

    def __init__(self, pool):
        self._pool = pool
        self.statements_by_kind: dict[str, int] = {"fingerprint": 0, "other": 0}

    def acquire(self):
        pool = self

        @asynccontextmanager
        async def acquired():
            async with pool._pool.acquire() as conn:
                yield CountingConnection(conn, pool.statements_by_kind)
        return acquired()


class CountingConnection:
    def __init__(self, conn, counts):
        self._conn, self._counts = conn, counts

    def _count(self, query):
        kind = "fingerprint" if "AS authority_owner" in query else "other"
        self._counts[kind] += 1

    async def fetchrow(self, query, *args):
        self._count(query)
        return await self._conn.fetchrow(query, *args)

    async def fetchval(self, query, *args):
        self._count(query)
        return await self._conn.fetchval(query, *args)

    async def fetch(self, query, *args):
        self._count(query)
        return await self._conn.fetch(query, *args)


def test_a_deactivated_target_stops_the_scan_as_out_of_scope(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)

            async def deactivate():
                async with pool.acquire() as conn:
                    await conn.execute("UPDATE targets SET is_active=false WHERE id=$1", scan.target_id)

            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               after={"baseline.http": deactivate})
            guard = scan.guard()
            await scan.run(dispatcher, guard)
            actions = await scan.actions()
            assert actions["templates.active"] == ("blocked", "scope_invalid")
            assert "target_transport_block" in scan.events
            assert await scan.held_reservations() == 0
    asyncio.run(run())


def test_a_passive_scan_without_an_approval_keeps_running_after_a_revoke(template_database):
    """Passive actions need scope, not an approval (``revalidate_action_authority``)."""
    def passive_plan(scan_id):
        first = _action("baseline.http", 0, "http.request")
        second = _action("baseline.tls", 1, "tls.inspect", (first.action_id,))
        final = _action("finalize.report", 2, "scan.finalize", (first.action_id, second.action_id))
        return ScanActionPlan(scan_id=str(scan_id), execution_plan_digest="b" * 64,
                              target_binding_digest="a" * 64, actions=(first, second, final))

    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool, active=False, plan=passive_plan)
            assert scan.policy.approval_receipt_id is None
            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               after={"baseline.http": scan.revoke})
            guard = scan.guard()
            await scan.run(dispatcher, guard)
            assert dispatcher.dispatched == ["baseline.http", "baseline.tls", "finalize.report"]
            assert guard.reason is None
    asyncio.run(run())


def test_a_receipt_the_target_no_longer_stands_behind_stops_the_scan_without_a_row_update(template_database):
    """Second gap: the receipt row is still active, but the target's authorization is not."""
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)

            async def move_host():  # the target now names another host; nothing touched the receipt
                async with pool.acquire() as conn:
                    await conn.execute("UPDATE targets SET url='http://elsewhere.test' WHERE id=$1",
                                       scan.target_id)

            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               after={"baseline.http": move_host})
            guard = scan.guard()
            await scan.run(dispatcher, guard)
            async with pool.acquire() as conn:
                status = await conn.fetchval("SELECT status FROM approval_receipts WHERE id=$1",
                                             uuid.UUID(scan.policy.approval_receipt_id))
            assert status == "active"
            assert (await scan.actions())["templates.active"] == ("blocked", "authorization_revoked")
    asyncio.run(run())


def test_an_alias_receipt_stops_when_its_source_is_revoked_even_without_the_cascade(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool, url="http://example.test")
            source = scan.policy.approval_receipt_id
            async with pool.acquire() as conn:  # the www twin derived as target_dns_alias does it
                receipt = (await target_authorization.evaluate_target_scope(conn, scan.target_id))["receipt"]
                receipt = {**receipt, "receipt_id": "scope-alias-" + uuid.uuid4().hex,
                           "allowed_hosts": ["example.test", "www.example.test"]}
                await target_authorization.persist_scope_receipt(conn, receipt, scan.target_id)
                derived = await conn.fetchval(
                    """INSERT INTO approval_receipts(scope_receipt_id,risk_tier,confirmations,action_name,
                           action_context,approved_by)
                       VALUES($1,'active','["confirm_authorized"]','target.authorization',$2::jsonb,'fixture-owner')
                       RETURNING id""",
                    receipt["receipt_id"], json.dumps({"target_id": str(scan.target_id), "host": "www.example.test",
                                                       "derived_from_approval_receipt_id": source}))
            scan.binding = TargetBinding(target_id=str(scan.target_id), target_kind="web",
                                         canonical_host="www.example.test",
                                         allowed_origins=("http://www.example.test",), environment="lab",
                                         scope_receipt_id=receipt["receipt_id"])
            scan.policy = ScanPolicy(active_testing=True, approval_receipt_id=str(derived),
                                     scope_receipt_id=receipt["receipt_id"])

            async def revoke_source_only():  # the lineage cascade did not reach the derived row
                async with pool.acquire() as conn:
                    await conn.execute("UPDATE approval_receipts SET status='revoked', revoked_at=NOW(), "
                                       "revoked_by='fixture' WHERE id=$1", uuid.UUID(source))

            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               after={"baseline.http": revoke_source_only})
            guard = scan.guard()
            await scan.run(dispatcher, guard)
            assert dispatcher.dispatched == ["baseline.http", "finalize.report"]
            assert (await scan.actions())["templates.active"] == ("blocked", "authorization_revoked")
    asyncio.run(run())


def test_an_origin_inheriting_its_host_authorization_runs_until_the_origin_is_revoked(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            async with pool.acquire() as conn:
                host = await conn.fetchval(
                    "INSERT INTO device_targets(name,primary_locator) VALUES('Host','inherit.test') RETURNING id")
            scan = await _scan(pool, url="https://inherit.test:8443", authorize=False)
            async with pool.acquire() as conn:
                await conn.execute("UPDATE targets SET asset_owner_id=$2 WHERE id=$1", scan.target_id, host)
                standing = await target_authorization.authorize_target(conn, host, approved_by="fixture-owner")
                inherited = await target_authorization.current_target_authorization(conn, scan.target_id)
            assert inherited and inherited["inherited"]
            assert inherited["approval_receipt_id"] == standing["approval_receipt_id"]
            scope_id = str(standing["scope_receipt_id"])
            scan.binding = TargetBinding(target_id=str(scan.target_id), target_kind="web",
                                         canonical_host="inherit.test",
                                         allowed_origins=("https://inherit.test:8443",), environment="lab",
                                         scope_receipt_id=scope_id)
            scan.policy = ScanPolicy(active_testing=True, approval_receipt_id=str(standing["approval_receipt_id"]),
                                     scope_receipt_id=scope_id)
            # The origin's own revoke ends the inheritance; the host's receipt row stays active.
            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               after={"templates.active": scan.revoke})
            guard = scan.guard()
            await scan.run(dispatcher, guard)
            assert dispatcher.dispatched == ["baseline.http", "templates.active", "finalize.report"]
            # Without the inheritance the host's receipt no longer covers this origin: the shared
            # decision calls that scope_invalid, as it does for Hunt and broker actions.
            assert (await scan.actions())["templates.followup"] == ("blocked", "scope_invalid")
    asyncio.run(run())


class FlakyPool:
    """Fixture pool whose ``acquire`` fails while ``down`` (a database blip for the guard only)."""

    def __init__(self, pool):
        self._pool, self.down, self.failed = pool, False, 0

    def acquire(self):
        if self.down:
            self.failed += 1
            raise OSError("fixture: database unreachable")
        return self._pool.acquire()


def test_a_database_blip_under_the_tolerance_does_not_stop_a_healthy_scan(template_database):
    """S3: two failed polls (about 4 s) with the approval still active: nothing is stopped."""
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            flaky = FlakyPool(pool)
            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               after={"templates.active": _outage(flaky, 4.0, settle=2.5)})
            guard = scan.guard()  # production 2 s poll and 10 s tolerance
            guard.pool = flaky
            await scan.run(dispatcher, guard)
            assert flaky.failed >= 2
            actions = await scan.actions()
            assert {status for status, _reason in actions.values()} == {"success"}
            assert dispatcher.dispatched == [action.action_id for action in scan.plan.actions]
            assert not guard.withdrawn and not scan.events
    asyncio.run(run())


def test_a_longer_outage_interrupts_the_action_as_unverified_never_as_revoked(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            flaky = FlakyPool(pool)
            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               long_actions=frozenset({"templates.active"}),
                                               during={"templates.active": _outage(flaky, 3.0)})
            guard = scan.guard(poll_seconds=0.3, unverified_after_seconds=1.5)
            guard.pool = flaky
            await scan.run(dispatcher, guard)
            actions = await scan.actions()
            assert actions["templates.active"] == ("partial", "authorization_unverified")
            # The approval was never revoked: the guard is not withdrawn, nothing claims a revoke,
            # and once the database is back the next action is checked and runs.
            assert not guard.withdrawn and "approval_revocation" not in scan.events
            assert actions["templates.followup"][0] == "success"
            assert not any(reason == "authorization_revoked" for _status, reason in actions.values())
            report = {"coverage": {"status": "complete", "reasons": []}}
            assert await guard.annotate(dict(report), scan_id=str(scan.scan_id)) == report
            assert await scan.held_reservations() == 0
    asyncio.run(run())


def _outage(flaky, seconds, *, settle=0.0):
    async def outage():
        await asyncio.sleep(0.3)
        flaky.down = True
        await asyncio.sleep(seconds)
        flaky.down = False
        await asyncio.sleep(settle)
    return outage
