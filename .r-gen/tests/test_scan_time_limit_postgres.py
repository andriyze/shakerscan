"""The Scan's time limit stops a running local Scan and keeps its findings (PostgreSQL).

Composed as ``_execute_reserved_deterministic_scan`` composes it: the real
``PostgresScanExecutionBackend``, ``ReceiptScanActionExecutor`` and ``ScanOrchestrator`` over the
installed schema, with the fixture dispatcher of ``test_scan_local_revocation_postgres`` (a long
action runs a fixture ``sleep`` process and stops it when the action is interrupted). No target
is contacted.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
import json
import time

from tests.test_scan_local_revocation_postgres import (  # noqa: F401  (template_database is a fixture)
    FixtureToolDispatcher,
    _scan,
    scan_database,
    template_database,
)
from scan.execution_backend import PostgresScanExecutionBackend  # noqa: E402
from scan.orchestrator import ScanOrchestrator  # noqa: E402
from scan.scan_deadline import SCAN_TIME_LIMIT, ScanDeadline, finalization_reserve_seconds  # noqa: E402
from scan.worker_action_executor import ReceiptScanActionExecutor  # noqa: E402


def _deadline_in(seconds: float, *, limit: int = 120) -> ScanDeadline:
    started = time.time() - (limit - finalization_reserve_seconds(limit)) + seconds
    deadline = ScanDeadline.for_scan(started_at=started, max_duration_seconds=limit)
    deadline.stop_grace_seconds = 2.0
    return deadline


async def _run(scan, dispatcher, deadline):
    backend = PostgresScanExecutionBackend(pool=scan.pool, plan=scan.plan, worker_id="local:fixture",
                                           backend_name="local")
    executor = ReceiptScanActionExecutor(
        scan_id=str(scan.scan_id), target_id=str(scan.target_id), worker_id="local:fixture",
        dispatcher=dispatcher, scope_receipt_id=scan.binding.scope_receipt_id,
        approval_receipt_id=scan.policy.approval_receipt_id, authority=scan.guard(),
        deadline=deadline)
    return await ScanOrchestrator(backend=backend, executor=executor).run(scan.plan)


def test_the_time_limit_stops_the_running_action_skips_the_rest_and_still_reports(template_database):  # noqa: F811
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id),
                                               long_actions=frozenset({"templates.active"}))
            deadline = _deadline_in(1.0)
            started = time.monotonic()
            result = await _run(scan, dispatcher, deadline)
            assert time.monotonic() - started < 6.0  # not the fixture tool's 30 s
            returncode, _exited = dispatcher.process_exits["templates.active"]
            assert returncode is not None and returncode < 0  # stopped by a signal
            actions = await scan.actions()
            assert actions["baseline.http"][0] == "success"  # what ran before the limit stays
            assert actions["templates.active"] == ("partial", SCAN_TIME_LIMIT)
            assert actions["templates.followup"] == ("timed_out", SCAN_TIME_LIMIT)
            assert actions["finalize.report"][0] == "success"  # the report still ran
            # The action past the limit never started; only the zero-traffic report did.
            assert dispatcher.dispatched == ["baseline.http", "templates.active", "finalize.report"]
            assert result.status_matrix["templates.followup"] == "timed_out"
            assert deadline.interrupted_actions == ["templates.active"]
            assert deadline.not_run_actions == ["templates.followup"]
            assert await scan.held_reservations() == 0
            async with pool.acquire() as conn:
                consumed = await conn.fetchval(
                    """SELECT result_json->'budget_consumed' FROM scan_capability_actions
                        WHERE scan_id=$1 AND action_id='templates.followup'""", scan.scan_id)
            consumed = json.loads(consumed) if isinstance(consumed, str) else consumed
            assert consumed and set(consumed.values()) == {0}  # nothing charged
            report = deadline.annotate({"coverage": {"status": "complete", "reasons": []},
                                        "findings": [{"title": "confirmed before the stop"}]})
            assert report["findings"] == [{"title": "confirmed before the stop"}]
            assert report["coverage"] == {"status": "partial", "reasons": [SCAN_TIME_LIMIT]}
            assert report["scan_metadata"]["stopped_at_time_limit"] is True
    asyncio.run(run())


def test_a_scan_inside_its_limit_is_unaffected(template_database):  # noqa: F811
    async def run():
        async with scan_database(template_database) as pool:
            scan = await _scan(pool)
            dispatcher = FixtureToolDispatcher(str(scan.target_id), str(scan.scan_id))
            deadline = _deadline_in(60.0)
            await _run(scan, dispatcher, deadline)
            actions = await scan.actions()
            assert {status for status, _reason in actions.values()} == {"success"}
            assert not deadline.stopped
    asyncio.run(run())
