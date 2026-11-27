"""A host's finding badge follows device findings without an API restart (PostgreSQL).

Device posture and device probe Scans store their findings through ``save_device_findings``.
Those rows carry the host target's id in ``findings.target_id`` (the device alias trigger copies
it), so ``targets.active_findings_count`` must move with them. Writing the ``device_targets``
compatibility view only reaches ``target_device_profiles``; the host target's own badge stayed
stale until the startup reconciliation ran again.

The findings are fixtures written through the worker's own persistence function on the installed
schema (db/init.sql plus every startup migration). No target is contacted.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

from tests.test_scan_local_revocation_postgres import scan_database  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]
import worker  # noqa: E402


def _posture_finding(title: str) -> dict:
    """Fixture: a device posture finding as the posture runner reports it."""
    return {"title": title, "severity": "medium", "tool": "device_posture",
            "url": "device://badge-host.test", "description": "fixture",
            "fingerprint": "device-badge-" + title}


async def _host_and_scan(pool, run_kind: str) -> tuple[uuid.UUID, uuid.UUID]:
    async with pool.acquire() as conn:
        host = await conn.fetchval(
            "INSERT INTO device_targets(name,primary_locator) VALUES('Badge host','badge-host.test') RETURNING id")
        scan_id = await conn.fetchval(
            """INSERT INTO scans(target_url,status,run_kind,device_target_id)
               VALUES('host://badge-host.test','completed',$1,$2) RETURNING id""", run_kind, host)
    return host, scan_id


async def _badges(pool, host) -> tuple[int, int, int]:
    async with pool.acquire() as conn:
        target = await conn.fetchval("SELECT active_findings_count FROM targets WHERE id=$1", host)
        profile = await conn.fetchval("SELECT active_findings_count FROM device_targets WHERE id=$1", host)
        rows = await conn.fetchval(
            "SELECT count(*) FROM findings WHERE target_id=$1 AND status='active'", host)
    return target, profile, rows


def test_device_posture_findings_move_the_host_targets_badge(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            host, scan_id = await _host_and_scan(pool, "device_posture")
            saved = await worker.save_device_findings(
                str(scan_id), str(host), [_posture_finding("one"), _posture_finding("two")])
            assert saved == 2
            assert await _badges(pool, host) == (2, 2, 2)
            # A later posture Scan that no longer sees "two" resolves it; the badge drops at once.
            await worker.save_device_findings(
                str(scan_id), str(host), [_posture_finding("one")], resolve_posture_missing=True)
            assert await _badges(pool, host) == (1, 1, 1)
    asyncio.run(run())


def test_device_probe_findings_move_the_host_targets_badge(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            host, scan_id = await _host_and_scan(pool, "device_probe")
            finding = {**_posture_finding("probe"), "tool": "device_candidate_verifier"}
            assert await worker.save_device_findings(str(scan_id), str(host), [finding]) == 1
            assert await _badges(pool, host) == (1, 1, 1)
    asyncio.run(run())


def test_device_posture_completion_recounts_the_host_target(template_database, monkeypatch):
    """The completion step recounts the host target, not only the device profile."""
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            host, scan_id = await _host_and_scan(pool, "device_posture")
            await worker.save_device_findings(str(scan_id), str(host), [_posture_finding("one")])
            async with pool.acquire() as conn:
                # Drift from an earlier release: the badge was left at zero.
                await conn.execute("UPDATE targets SET active_findings_count=0 WHERE id=$1", host)
            await worker.refresh_device_finding_badges(str(host))
            assert await _badges(pool, host) == (1, 1, 1)
    asyncio.run(run())
