#!/usr/bin/env python3
"""Real-PostgreSQL proof that cancellation wins the Scan action-admission race."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

import asyncpg


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:  # release images expose /app/scan as the runtime package
    from scan.action_plan import ScanAction, ScanActionPlan
    from scan.action_reservations import (
        ScanActionReservationError,
        admit_and_start_scan_action_reservation,
    )
    from scan.action_store import PostgresScanActionStore
    from scan.capability_result import CapabilityResultStatus
    from scan.execution_backend import PostgresScanExecutionBackend
except ModuleNotFoundError:  # source checkout
    from api.scan.action_plan import ScanAction, ScanActionPlan
    from api.scan.action_reservations import (
        ScanActionReservationError,
        admit_and_start_scan_action_reservation,
    )
    from api.scan.action_store import PostgresScanActionStore
    from api.scan.capability_result import CapabilityResultStatus
    from api.scan.execution_backend import PostgresScanExecutionBackend


def _plan(scan_id: str) -> ScanActionPlan:
    action_id = "baseline.http"
    action = ScanAction(
        action_id=action_id,
        stage="deterministic_baseline",
        ordinal=0,
        capability_name="http.request",
        capability_args={"method": "GET"},
        target_binding_digest="a" * 64,
        input_binding_digest=hashlib.sha256(action_id.encode()).hexdigest(),
        requested_budget={"http_requests": 1, "tool_wall_seconds": 2},
        placement={
            "eligible_backends": ["local", "broker"],
            "adapter_name": "httpx",
            "adapter_version": "1",
        },
        dependencies=(),
        required=True,
        supporting=False,
        output_schema="http-observation/v1",
    )
    return ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64,
        actions=(action,),
    )


async def _run(database_url: str) -> dict[str, object]:
    pool = await asyncpg.create_pool(database_url, min_size=2, max_size=4)
    target_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    plan = _plan(str(scan_id))
    checked = asyncio.Event()
    cancelled = asyncio.Event()
    admission_error: str | None = None
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO targets (id,url,name) VALUES ($1,$2,$3)",
                target_id,
                f"http://cancellation-race-{target_id}.invalid",
                "V2 cancellation race fixture",
            )
            await conn.execute(
                """INSERT INTO scans (
                       id,target_id,target_url,status,scan_generation,
                       budget_json,budget_used_json
                   ) VALUES ($1,$2,$3,'running','canonical',$4::jsonb,$5::jsonb)""",
                scan_id,
                target_id,
                f"http://cancellation-race-{target_id}.invalid",
                json.dumps({
                    "max_duration_seconds": 120,
                    "max_http_requests": 20,
                    "max_endpoints": 20,
                    "max_browser_actions": 20,
                    "max_tcp_ports": 20,
                    "max_tool_wall_seconds": 60,
                    "max_workers": 1,
                    "max_state_changing_requests": 0,
                    "max_hosts": 1,
                }),
                json.dumps({
                    "http_requests": 0,
                    "state_changing_requests": 0,
                    "browser_actions": 0,
                    "tcp_ports_attempted": 0,
                    "hosts_attempted": 0,
                    "tool_wall_seconds": 0,
                }),
            )
            await PostgresScanActionStore().persist_plan(conn, plan=plan)

        async def scheduler() -> None:
            nonlocal admission_error
            async with pool.acquire() as conn:
                status = await conn.fetchval(
                    "SELECT status FROM scans WHERE id=$1", scan_id,
                )
                if status != "running":
                    raise AssertionError("fixture Scan was not executable")
                checked.set()
                await cancelled.wait()
                try:
                    async with conn.transaction():
                        await admit_and_start_scan_action_reservation(
                            conn,
                            plan=plan,
                            action=plan.actions[0],
                            worker_id="cancellation-race-worker",
                            lease_seconds=30,
                        )
                except ScanActionReservationError as exc:
                    admission_error = str(exc)

        async def operator() -> None:
            await checked.wait()
            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE scans SET status='cancelling' WHERE id=$1",
                    scan_id,
                )
            cancelled.set()

        await asyncio.gather(scheduler(), operator())
        if not admission_error or "stopped" not in admission_error:
            raise AssertionError(
                "action admission did not fail after concurrent cancellation"
            )

        async with pool.acquire() as conn:
            active_reservations = await conn.fetchval(
                """SELECT count(*) FROM budget_reservations
                    WHERE owner_kind='scan' AND owner_id=$1
                      AND status IN ('reserved','running')""",
                str(scan_id),
            )
            action_status = await conn.fetchval(
                """SELECT status FROM scan_capability_actions
                    WHERE scan_id=$1 AND action_id=$2""",
                scan_id,
                plan.actions[0].action_id,
            )
        if active_reservations != 0 or action_status != "planned":
            raise AssertionError("cancelled admission created execution authority")

        backend = PostgresScanExecutionBackend(
            pool=pool,
            plan=plan,
            worker_id="cancellation-settler",
        )
        result = await backend.cancel_action(plan.actions[0])
        if (
            result.status is not CapabilityResultStatus.CANCELLED
            or any(result.budget_consumed.values())
        ):
            raise AssertionError("cancellation settlement was not zero-traffic")

        async with pool.acquire() as conn:
            terminal = await conn.fetchrow(
                """SELECT a.status AS action_status, a.attempt,
                          r.status AS reservation_status, r.hold_applied,
                          r.actual_json
                     FROM scan_capability_actions a
                     JOIN budget_reservations r ON r.id=a.reservation_id
                    WHERE a.scan_id=$1 AND a.action_id=$2""",
                scan_id,
                plan.actions[0].action_id,
            )
        actual_json = terminal["actual_json"] if terminal is not None else {}
        actual = (
            json.loads(actual_json)
            if isinstance(actual_json, str)
            else dict(actual_json or {})
        )
        if (
            terminal is None
            or terminal["action_status"] != "cancelled"
            or terminal["attempt"] != 0
            or terminal["reservation_status"] != "failed"
            or terminal["hold_applied"]
            or any(actual.values())
        ):
            raise AssertionError("cancellation terminal state is inconsistent")
        return {
            "schema_version": "scan-cancellation-race-receipt/v1",
            "passed": True,
            "scan_id": str(scan_id),
            "admission_rejected": True,
            "active_reservations": 0,
            "action_attempts": 0,
            "target_traffic": 0,
        }
    finally:
        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM scans WHERE id=$1", scan_id)
            await conn.execute("DELETE FROM targets WHERE id=$1", target_id)
        await pool.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database-url", default=os.environ.get("DATABASE_URL"),
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if not args.database_url:
        parser.error("--database-url or DATABASE_URL is required")
    receipt = asyncio.run(_run(args.database_url))
    if args.json:
        print(json.dumps(receipt, sort_keys=True))
    else:
        print("PASS: cancelled Scan admitted no action execution authority")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
