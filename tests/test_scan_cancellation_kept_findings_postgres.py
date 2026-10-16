"""Cancelled Scans keep what their settled actions confirmed, on every entry point (PostgreSQL).

Covered here, through the worker's own job handlers over the installed schema:

* a parallel Scan's shard cancelled while it runs stores its kept report (``process_scan_shard_job``);
* the cancelled parent is never merged, but keeps the union of what its shards kept — completed
  shards and cancelled shards' kept reports — under the parent, and rebuilding it again (a later
  shard settles) changes nothing (``process_scan_merge_job`` / ``_fold_cancelled_parallel_parent``);
* an ASM exploit batch cancelled while it runs keeps its findings and stays cancelled
  (``process_exploit_batch_job``), instead of recording the cancel as an error;
* a cancelled Scan's ledger is kept when its kept report has none (``persist_kept_cancelled_scan``).

The Scan execution itself is a fixture (it cancels the row, as ``POST /scans/{id}/cancel`` does,
and returns the kept report the canonical executor builds); Redis is a fixture. No target is
contacted.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

from tests.test_scan_local_revocation_postgres import scan_database  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]
import asm_inventory  # noqa: E402
import parallel_scan  # noqa: E402
import worker  # noqa: E402
from scan.cancelled_report import (  # noqa: E402
    is_kept_cancelled_report, mark_cancelled_scan_report, persist_kept_cancelled_scan,
)

URL = "http://cancel.fixture.test"


class FixtureRedis:
    """Enough of Redis for the job handlers; records what was enqueued."""

    def __init__(self):
        self.values: dict[str, object] = {}
        self.pushed: list[tuple[str, str]] = []

    def hset(self, *_args, **_kwargs):
        return 1

    def hget(self, *_args):
        return None

    def expire(self, *_args):
        return True

    def delete(self, *_args):
        return 1

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value, *_args, **_kwargs):
        self.values.setdefault(key, value)
        return True

    def decr(self, *_args):
        return 0

    def lpush(self, key, value):
        self.pushed.append((key, value))
        return 1

    def rpush(self, *_args):
        return 1

    def ltrim(self, *_args):
        return True

    def lrange(self, *_args):
        return []


def _finding(title: str, path: str) -> dict:
    return {"title": title, "severity": "medium", "url": f"{URL}{path}", "type": "fixture",
            "tool": "fixture", "evidence": {"request": f"GET {path}"}}


def _kept(findings: list[dict]) -> dict:
    return mark_cancelled_scan_report({
        "target": URL, "findings": findings, "result": {"score": None, "grade": None},
        "coverage": {"status": "partial", "reasons": []}, "scan_metadata": {},
    })


@pytest.fixture
def fixtures(monkeypatch):
    redis = FixtureRedis()

    async def nothing(*_args, **_kwargs):
        return None

    async def identity(options, *_args):
        return options

    async def artifact(*_args, **_kwargs):
        return "/tmp/fixture-result.json"

    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "update_scan_progress", nothing)
    monkeypatch.setattr(worker, "send_heartbeats", lambda *_a, **_k: None)
    monkeypatch.setattr(worker, "_hydrate_generic_scan_credentials", identity)
    monkeypatch.setattr(worker, "_hydrate_managed_scan_credentials", identity)
    monkeypatch.setattr(worker, "persist_result_artifact", artifact)
    monkeypatch.setattr(worker, "_try_acquire_parallel_shard_slot", lambda *_a, **_k: (True, 4))
    monkeypatch.setattr(worker, "_release_parallel_shard_slot", lambda *_a, **_k: None)
    monkeypatch.setattr(worker.http_archive, "start_scan_capture", lambda *_a: False)
    monkeypatch.setattr(worker.domain_rate, "track_dispatch_hold", nothing)
    monkeypatch.setattr(worker.domain_rate, "mark_executing", lambda *_a, **_k: None)
    monkeypatch.setattr(worker.domain_rate, "measure", lambda *_a, **_k: None)
    return redis


async def _target(pool) -> uuid.UUID:
    async with pool.acquire() as conn:
        return await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", URL)


async def _scan_row(pool, target_id, *, status, role="standalone", parent=None, index=None,
                    result=None, budget_used=None) -> uuid.UUID:
    scan_id = uuid.uuid4()
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO scans (id, target_id, target_url, status, scan_role, parent_scan_id,
                                  shard_index, result, findings_count, budget_used_json)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10::jsonb)""",
            scan_id, target_id, URL, status, role, parent, index,
            json.dumps(result) if result is not None else None,
            len((result or {}).get("findings") or []), json.dumps(budget_used or {}),
        )
    return scan_id


async def _cancel(pool, scan_id):
    """What ``POST /scans/{id}/cancel`` writes for a running Scan."""
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE scans SET status='cancelled', error_message='Cancelled by user',
                      completed_at=NOW(), progress=100, current_phase='cancelled' WHERE id=$1""",
            scan_id)


def test_a_cancelled_parallel_scan_keeps_what_its_shards_kept(template_database, fixtures, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            target_id = await _target(pool)
            parent = await _scan_row(pool, target_id, status="running", role="parent")
            done = await _scan_row(pool, target_id, status="completed", role="shard", parent=parent, index=0,
                                   result={"target": URL, "findings": [_finding("completed shard", "/a")],
                                           "result": {"score": 90, "grade": "A"}})
            running = await _scan_row(pool, target_id, status="running", role="shard", parent=parent, index=1,
                                      budget_used={"http_requests": 7})
            never_ran = await _scan_row(pool, target_id, status="queued", role="shard", parent=parent, index=2)

            async def execute(*_args, **_kwargs):
                # The parent is cancelled while this shard runs (the endpoint fans the cancel out
                # to every unfinished shard); the shard's executor keeps its settled findings.
                for scan_id in (parent, running, never_ran):
                    await _cancel(pool, scan_id)
                return _kept([_finding("cancelled shard", "/b"), _finding("completed shard", "/a")])

            monkeypatch.setattr(worker, "_execute_reserved_deterministic_scan", execute)
            await worker.process_scan_shard_job({
                "job_id": "job-" + uuid.uuid4().hex, "scan_id": str(running), "parent_scan_id": str(parent),
                "target_id": str(target_id), "target": URL, "options": {}, "shard_index": 1, "shard_count": 3,
            })
            async with pool.acquire() as conn:
                shard = await conn.fetchrow(
                    "SELECT status, result, findings_count, coverage_status, budget_used_json FROM scans WHERE id=$1",
                    running)
                parent_row = await conn.fetchrow(
                    "SELECT status, result, findings_count, coverage_status FROM scans WHERE id=$1", parent)
                stored = await conn.fetch(
                    "SELECT title, scan_id FROM findings WHERE target_id=$1 ORDER BY title", target_id)
            # The cancelled shard stores its kept report; its ledger is untouched; it stays cancelled.
            assert shard["status"] == "cancelled" and shard["findings_count"] == 2
            assert shard["coverage_status"] == "cancelled"
            assert is_kept_cancelled_report(json.loads(shard["result"]))
            assert json.loads(shard["budget_used_json"]) == {"http_requests": 7}
            # The parent stays cancelled and keeps the union of what its shards kept.
            assert parent_row["status"] == "cancelled" and parent_row["coverage_status"] == "cancelled"
            report = json.loads(parent_row["result"])
            assert sorted(item["title"] for item in report["findings"]) == ["cancelled shard", "completed shard"]
            assert parent_row["findings_count"] == 2 and is_kept_cancelled_report(report)
            assert report["parallel"]["shards_kept"] == 2 and report["parallel"]["shards_total"] == 3
            assert [(row["title"], row["scan_id"]) for row in stored] == [
                ("cancelled shard", parent), ("completed shard", parent)]

            # The merge job of a cancelled parent rebuilds the same union (idempotent).
            await worker.process_scan_merge_job({"parent_scan_id": str(parent)})
            async with pool.acquire() as conn:
                again = await conn.fetchrow("SELECT status, findings_count FROM scans WHERE id=$1", parent)
                count = await conn.fetchval("SELECT count(*) FROM findings WHERE target_id=$1", target_id)
            assert dict(again) == {"status": "cancelled", "findings_count": 2} and count == 2
            # The completed shard was not rewritten.
            async with pool.acquire() as conn:
                assert await conn.fetchval("SELECT status FROM scans WHERE id=$1", done) == "completed"
    asyncio.run(run())


def test_a_parent_that_is_not_cancelled_is_not_folded(template_database, fixtures, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            target_id = await _target(pool)
            parent = await _scan_row(pool, target_id, status="running", role="parent")
            await _scan_row(pool, target_id, status="completed", role="shard", parent=parent, index=0,
                            result={"findings": [_finding("completed shard", "/a")]})
            assert await worker._fold_cancelled_parallel_parent(str(parent), "fixture") is None
            async with pool.acquire() as conn:
                row = await conn.fetchrow("SELECT status, result FROM scans WHERE id=$1", parent)
            assert row["status"] == "running" and row["result"] is None
    asyncio.run(run())


def test_cancelling_a_parent_queues_its_fold(monkeypatch):
    redis = FixtureRedis()
    parallel_scan.enqueue_cancelled_parent_fold(redis, "parent-1", "scan_jobs")
    assert redis.pushed and json.loads(redis.pushed[0][1])["parent_scan_id"] == "parent-1"
    assert json.loads(redis.pushed[0][1])["type"] == parallel_scan.MERGE_JOB_TYPE


def test_a_cancelled_asm_batch_keeps_its_findings_and_stays_cancelled(template_database, fixtures, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            target_id = await _target(pool)
            async with pool.acquire() as conn:
                await asm_inventory.upsert_endpoints(
                    conn, str(target_id), ["GET /search?q=1", "GET /item?id=2"], source="scan")
            scan_id = await _scan_row(pool, target_id, status="queued")

            async def queued(_scan_id):
                return "queued"

            async def reserve(*_args, amount, **_kwargs):
                return {"granted": amount, "requested": amount}

            async def execute(*_args, **_kwargs):
                await _cancel(pool, scan_id)
                return _kept([_finding("found before the cancel", "/search")])

            monkeypatch.setattr(worker, "_confirmed_scan_handoff_status", queued)
            monkeypatch.setattr(worker, "_reserve_target_domain_endpoint_budget", reserve)
            monkeypatch.setattr(worker, "_execute_reserved_deterministic_scan", execute)
            await worker.process_exploit_batch_job({
                "job_id": "job-" + uuid.uuid4().hex, "scan_id": str(scan_id), "target_id": str(target_id),
                "target": URL, "options": {}, "batch_size": 10,
            })
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT status, findings_count, coverage_status, result FROM scans WHERE id=$1", scan_id)
                titles = [r["title"] for r in await conn.fetch(
                    "SELECT title FROM findings WHERE target_id=$1", target_id)]
                attempts = [r["status"] for r in await conn.fetch(
                    "SELECT status FROM asm_endpoint_attempts WHERE scan_id=$1", scan_id)]
                leased = await conn.fetchval(
                    "SELECT count(*) FROM target_endpoints WHERE target_id=$1 AND test_status='in_progress'",
                    target_id)
            assert row["status"] == "cancelled" and row["findings_count"] == 1
            assert row["coverage_status"] == "cancelled" and is_kept_cancelled_report(json.loads(row["result"]))
            assert titles == ["found before the cancel"]
            # The batch is recorded as a partial attempt, never as an error; nothing stays leased.
            assert attempts and "error" not in attempts and set(attempts) == {"partial"}
            assert leased == 0
    asyncio.run(run())


def test_a_kept_report_without_a_ledger_keeps_the_rows_ledger(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            target_id = await _target(pool)
            scan_id = await _scan_row(pool, target_id, status="cancelled", budget_used={"http_requests": 3})
            from datetime import datetime, timezone
            kept = await persist_kept_cancelled_scan(
                pool, scan_id=str(scan_id), result=_kept([]), completed_at=datetime.now(timezone.utc),
                duration=1, coverage={"status": "cancelled"}, budget_used=None)
            async with pool.acquire() as conn:
                ledger = await conn.fetchval("SELECT budget_used_json FROM scans WHERE id=$1", scan_id)
            assert kept is True and json.loads(ledger) == {"http_requests": 3}
    asyncio.run(run())
