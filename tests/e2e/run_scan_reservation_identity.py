#!/usr/bin/env python3
"""Real-PostgreSQL proof of Scan action/reservation composite identity."""

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

try:  # release image
    from runtime.reservation_store import PostgresBudgetReservationStore
    from scan.action_plan import ScanAction, ScanActionPlan
    from scan.action_store import PostgresScanActionStore
    from scan.execution_backend import PostgresScanExecutionBackend
except ModuleNotFoundError:  # source checkout
    from api.runtime.reservation_store import PostgresBudgetReservationStore
    from api.scan.action_plan import ScanAction, ScanActionPlan
    from api.scan.action_store import PostgresScanActionStore
    from api.scan.execution_backend import PostgresScanExecutionBackend


def _action(
    action_id: str, ordinal: int, *, method: str = "GET",
) -> ScanAction:
    return ScanAction(
        action_id=action_id,
        stage="deterministic_baseline",
        ordinal=ordinal,
        capability_name="http.request",
        capability_args={"method": method},
        target_binding_digest="a" * 64,
        input_binding_digest=hashlib.sha256(
            f"{action_id}:{method}".encode(),
        ).hexdigest(),
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


def _plan(scan_id: uuid.UUID, actions: tuple[ScanAction, ...]) -> ScanActionPlan:
    return ScanActionPlan(
        scan_id=str(scan_id),
        execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64,
        actions=actions,
    )


def _budget() -> tuple[str, str]:
    return (
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


async def _must_reject(conn, query: str, *args) -> None:
    try:
        async with conn.transaction():
            await conn.execute(query, *args)
    except asyncpg.ForeignKeyViolationError:
        return
    raise AssertionError("database accepted a detached action reservation identity")


async def _run(database_url: str) -> dict[str, object]:
    pool = await asyncpg.create_pool(database_url, min_size=1, max_size=4)
    first_scan = uuid.uuid4()
    second_scan = uuid.uuid4()
    first_plan = _plan(first_scan, (
        _action("baseline.http", 0),
        _action("baseline.security_txt", 1),
    ))
    second_plan = _plan(second_scan, (
        _action("baseline.http", 0, method="HEAD"),
    ))
    try:
        budget, used = _budget()
        async with pool.acquire() as conn:
            await PostgresBudgetReservationStore().ensure_schema(conn)
            await PostgresScanActionStore().ensure_schema(conn)
            for scan_id in (first_scan, second_scan):
                await conn.execute(
                    """INSERT INTO scans (
                           id,target_url,status,scan_generation,
                           budget_json,budget_used_json
                       ) VALUES ($1,$2,'running','canonical',$3::jsonb,$4::jsonb)""",
                    scan_id,
                    f"http://reservation-identity-{scan_id}.invalid",
                    budget,
                    used,
                )
            store = PostgresScanActionStore()
            await store.persist_plan(conn, plan=first_plan)
            await store.persist_plan(conn, plan=second_plan)

        first_backend = PostgresScanExecutionBackend(
            pool=pool, plan=first_plan, worker_id="identity-worker-1",
        )
        second_backend = PostgresScanExecutionBackend(
            pool=pool, plan=second_plan, worker_id="identity-worker-2",
        )
        first_lease = await first_backend.acquire_action(first_plan.actions[0])
        second_action_lease = await first_backend.acquire_action(
            first_plan.actions[1],
        )
        cross_scan_lease = await second_backend.acquire_action(
            second_plan.actions[0],
        )

        async with pool.acquire() as conn:
            cross_scan_reservation_id = await conn.fetchval(
                """SELECT reservation_id FROM scan_capability_actions
                    WHERE scan_id=$1 AND action_id=$2""",
                second_scan,
                second_plan.actions[0].action_id,
            )
            await _must_reject(
                conn,
                """UPDATE scan_capability_actions SET reservation_id=$3
                    WHERE scan_id=$1 AND action_id=$2""",
                first_scan,
                first_plan.actions[0].action_id,
                cross_scan_reservation_id,
            )
            second_reservation_id = await conn.fetchval(
                """SELECT reservation_id FROM scan_capability_actions
                    WHERE scan_id=$1 AND action_id=$2""",
                first_scan,
                first_plan.actions[1].action_id,
            )
            await _must_reject(
                conn,
                """UPDATE scan_capability_actions SET reservation_id=$3
                    WHERE scan_id=$1 AND action_id=$2""",
                first_scan,
                first_plan.actions[0].action_id,
                second_reservation_id,
            )
            first_reservation_id = await conn.fetchval(
                """SELECT reservation_id FROM scan_capability_actions
                    WHERE scan_id=$1 AND action_id=$2""",
                first_scan,
                first_plan.actions[0].action_id,
            )
            await _must_reject(
                conn,
                "UPDATE budget_reservations SET action_digest=$2 WHERE id=$1",
                first_reservation_id,
                "f" * 64,
            )
            valid_links = await conn.fetchval(
                """SELECT count(*)
                     FROM scan_capability_actions a
                     JOIN budget_reservations r
                       ON (a.reservation_id, a.reservation_owner_kind,
                           a.reservation_owner_id, a.action_id, a.action_digest)
                        = (r.id, r.owner_kind, r.owner_id,
                           r.action_id, r.action_digest)
                    WHERE a.scan_id=ANY($1::uuid[])""",
                [first_scan, second_scan],
            )
        if valid_links != 3:
            raise AssertionError("valid action reservations lost composite identity")
        return {
            "schema_version": "scan-reservation-identity-receipt/v1",
            "passed": True,
            "cross_scan_rejected": True,
            "cross_action_rejected": True,
            "digest_change_rejected": True,
            "valid_links": valid_links,
            "lease_ids": sorted({
                first_lease.lease_id,
                second_action_lease.lease_id,
                cross_scan_lease.lease_id,
            }),
        }
    finally:
        async with pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM scans WHERE id=ANY($1::uuid[])",
                [first_scan, second_scan],
            )
            await conn.execute(
                """DELETE FROM budget_reservations
                    WHERE owner_kind='scan' AND owner_id=ANY($1::text[])""",
                [str(first_scan), str(second_scan)],
            )
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
        print("PASS: PostgreSQL enforced Scan action reservation identity")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
