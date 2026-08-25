#!/usr/bin/env python3
"""Candidate-stack proof that action resume never repeats completed target traffic."""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
from typing import Any
import urllib.request
import uuid

import asyncpg
import redis


SCRIPT_PATH = Path(__file__).resolve()
ROOT = Path("/app") if Path("/app/scan").is_dir() else SCRIPT_PATH.parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:  # release image
    from runtime.receipts import CapabilityReceipt
    from scan.action_plan import ScanAction, ScanActionPlan
    from scan.action_store import PostgresScanActionStore
    from scan.capability_result import CapabilityResultStatus
    from scan.execution_backend import PostgresScanExecutionBackend, ScanExecutionBackendError
    from scan.orchestrator import ScanOrchestrator
except ModuleNotFoundError:  # source checkout
    from api.runtime.receipts import CapabilityReceipt
    from api.scan.action_plan import ScanAction, ScanActionPlan
    from api.scan.action_store import PostgresScanActionStore
    from api.scan.capability_result import CapabilityResultStatus
    from api.scan.execution_backend import PostgresScanExecutionBackend, ScanExecutionBackendError
    from api.scan.orchestrator import ScanOrchestrator


class _CountingHandler(BaseHTTPRequestHandler):
    counts: Counter[str] = Counter()

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        type(self).counts[self.path] += 1
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: Any) -> None:
        return


def _action(action_id: str, ordinal: int, path: str) -> ScanAction:
    return ScanAction(
        action_id=action_id,
        stage="deterministic_baseline",
        ordinal=ordinal,
        capability_name="http.request",
        capability_args={"method": "GET", "path": path},
        target_binding_digest="a" * 64,
        input_binding_digest=hashlib.sha256(
            f"{action_id}:{path}".encode(),
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


def _plan(scan_id: uuid.UUID) -> ScanActionPlan:
    return ScanActionPlan(
        scan_id=str(scan_id),
        execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64,
        actions=(
            _action("baseline.http", 0, "/first"),
            _action("baseline.security_txt", 1, "/second"),
        ),
    )


class _CountingExecutor:
    def __init__(self, base_url: str, target_id: uuid.UUID, worker_id: str) -> None:
        self.base_url = base_url
        self.target_id = target_id
        self.worker_id = worker_id
        self.executed: list[str] = []

    async def execute(self, action, lease, heartbeat):
        await heartbeat()
        path = str(action.capability_args["path"])
        def request() -> None:
            with urllib.request.urlopen(self.base_url + path) as response:
                response.read()
        await asyncio.to_thread(request)
        self.executed.append(action.action_id)
        now = datetime.now(timezone.utc).isoformat()
        return CapabilityReceipt(
            capability_name=action.capability_name,
            adapter_name=str(action.placement["adapter_name"]),
            adapter_version=str(action.placement["adapter_version"]),
            target_id=str(self.target_id),
            scan_id=lease.scan_id,
            worker_id=self.worker_id,
            status="success",
            input_digest=action.action_digest,
            parser_version="scan-action-resume-e2e/v1",
            started_at=now,
            finished_at=now,
            redacted_execution={
                "action_id": action.action_id,
                "method": "GET",
                "path_sha256": hashlib.sha256(path.encode()).hexdigest(),
            },
            budget_reserved=action.requested_budget,
            budget_consumed={"http_requests": 1, "tool_wall_seconds": 1},
        )

    async def terminal_without_execution(
        self, action, lease, *, status, reason_code, charge_full_reservation,
    ):
        now = datetime.now(timezone.utc).isoformat()
        return CapabilityReceipt(
            capability_name=action.capability_name,
            adapter_name=str(action.placement["adapter_name"]),
            adapter_version=str(action.placement["adapter_version"]),
            target_id=str(self.target_id),
            scan_id=lease.scan_id,
            worker_id=self.worker_id,
            status=status,
            input_digest=action.action_digest,
            parser_version="scan-action-resume-e2e/v1",
            started_at=now,
            finished_at=now,
            redacted_execution={"action_id": action.action_id, "executed": False},
            budget_reserved=action.requested_budget,
            budget_consumed=(
                action.requested_budget if charge_full_reservation else {}
            ),
            errors=(reason_code,),
        )


class _LostAcknowledgementBackend(PostgresScanExecutionBackend):
    def __init__(self, *args, lost_action_id: str, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._lost_action_id = lost_action_id
        self._injected = False

    async def settle(self, lease, result):
        settled = await super().settle(lease, result)
        if lease.action.action_id == self._lost_action_id and not self._injected:
            self._injected = True
            raise ScanExecutionBackendError("injected post-settlement response loss")
        return settled


async def _run(database_url: str, redis_url: str) -> dict[str, Any]:
    pool = await asyncpg.create_pool(database_url, min_size=2, max_size=6)
    redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
    scan_id = uuid.uuid4()
    plan = _plan(scan_id)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CountingHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    queue_key = f"v2:resume-e2e:{scan_id}"
    _CountingHandler.counts.clear()
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO scans (
                       id,target_url,status,scan_generation,
                       budget_json,budget_used_json
                   ) VALUES ($1,$2,'running','canonical',$3::jsonb,$4::jsonb)""",
                scan_id,
                base_url,
                json.dumps({
                    "max_duration_seconds": 120,
                    "max_http_requests": 10,
                    "max_endpoints": 10,
                    "max_browser_actions": 0,
                    "max_tcp_ports": 0,
                    "max_tool_wall_seconds": 30,
                    "max_workers": 2,
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

        first_executor = _CountingExecutor(base_url, scan_id, "resume-worker-1")
        first_backend = _LostAcknowledgementBackend(
            pool=pool,
            plan=plan,
            worker_id="resume-worker-1",
            lost_action_id=plan.actions[0].action_id,
        )
        try:
            await ScanOrchestrator(
                backend=first_backend, executor=first_executor,
            ).run(plan)
        except ScanExecutionBackendError as exc:
            if "post-settlement" not in str(exc):
                raise
        else:
            raise AssertionError("lost acknowledgement fault was not injected")
        if dict(_CountingHandler.counts) != {"/first": 1}:
            raise AssertionError("first action traffic did not settle exactly once")

        # Model a duplicated queue delivery to two real DB-backed schedulers.
        redis_client.rpush(queue_key, "delivery-1", "delivery-2")
        deliveries = [redis_client.lpop(queue_key), redis_client.lpop(queue_key)]
        resumed_executors = [
            _CountingExecutor(base_url, scan_id, f"resume-worker-{index}")
            for index in (2, 3)
        ]
        async def deliver(index: int, executor: _CountingExecutor):
            backend = PostgresScanExecutionBackend(
                pool=pool,
                plan=plan,
                worker_id=f"resume-worker-{index}",
            )
            for attempt in range(20):
                try:
                    return await ScanOrchestrator(
                        backend=backend, executor=executor,
                    ).run(plan)
                except ScanExecutionBackendError as exc:
                    if "active execution lease" not in str(exc) or attempt == 19:
                        raise
                    await asyncio.sleep(0.05)
            raise AssertionError("duplicate delivery did not converge")

        reports = await asyncio.gather(*(
            deliver(index, executor)
            for index, executor in zip((2, 3), resumed_executors, strict=True)
        ))
        if deliveries != ["delivery-1", "delivery-2"]:
            raise AssertionError("Redis duplicate-delivery fixture was not consumed")
        if dict(_CountingHandler.counts) != {"/first": 1, "/second": 1}:
            raise AssertionError("resumed action traffic was repeated")
        if any(plan.actions[0].action_id in item.executed for item in resumed_executors):
            raise AssertionError("terminal first action re-executed after resume")
        if sum(
            plan.actions[1].action_id in item.executed
            for item in resumed_executors
        ) != 1:
            raise AssertionError("competing workers did not execute remaining work once")
        if any(
            report.status_matrix != {
                action.action_id: CapabilityResultStatus.SUCCESS.value
                for action in plan.actions
            }
            for report in reports
        ):
            raise AssertionError("resumed result matrix is incomplete")
        return {
            "schema_version": "scan-action-resume-receipt/v1",
            "passed": True,
            "scan_id": str(scan_id),
            "lost_acknowledgement_recovered": True,
            "partial_continuation_recovered": True,
            "duplicate_queue_deliveries": 2,
            "competing_workers": 2,
            "target_request_counts": dict(sorted(_CountingHandler.counts.items())),
            "repeated_target_requests": 0,
        }
    finally:
        redis_client.delete(queue_key)
        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM scans WHERE id=$1", scan_id)
            await conn.execute(
                "DELETE FROM budget_reservations WHERE owner_kind='scan' AND owner_id=$1",
                str(scan_id),
            )
        await pool.close()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"))
    parser.add_argument("--redis-url", default=os.environ.get("REDIS_URL"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if not args.database_url or not args.redis_url:
        parser.error("DATABASE_URL and REDIS_URL are required")
    receipt = asyncio.run(_run(args.database_url, args.redis_url))
    if args.json:
        print(json.dumps(receipt, sort_keys=True))
    else:
        print("PASS: resumed Scan action traffic was not repeated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
