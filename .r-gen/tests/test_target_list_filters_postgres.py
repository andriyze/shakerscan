"""Several targets in one list request, and the two new change categories (PostgreSQL).

A caller that keeps its own grouping of targets (an application, a team's assets) reads one list
for all of them: ``target_id`` repeats on GET /findings, /scans, /hunts, /timeline,
/exposure/services and /exposure/changes. GET /exposure/changes also reports new services (a
connected device's open port first seen, or a web service recorded under a host) and findings
proven in the window, whatever their severity.

Only FINDINGS_PROOF_SQL_TEST_DATABASE_URL on localhost/shakerscan_proof_sql_test is permitted. Its
schema is replaced from db/init.sql. Hosts are under the reserved ``.invalid`` domain; nothing is
contacted.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import uuid

import pytest

from tests.disposable_postgres import require_disposable_database
from tests.test_finding_detail_related_postgres import DSN, REQUIRED, TARGET, _fresh_schema_and_adder

if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable findings PostgreSQL database"
)

OTHER = uuid.UUID("33333333-3333-4333-8333-333333333333")
THIRD = uuid.UUID("44444444-4444-4444-8444-444444444444")


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    @asynccontextmanager
    async def _acquire(self):
        yield self.conn

    def acquire(self):
        return self._acquire()


def _run(scenario):
    dsn = require_disposable_database(DSN or "", "shakerscan_proof_sql_test")

    async def go():
        conn = await asyncpg.connect(dsn)
        try:
            setup, add = _fresh_schema_and_adder(conn)
            await setup()
            await conn.execute("ALTER TABLE targets ADD COLUMN IF NOT EXISTS asset_owner_id UUID")
            for target_id, url in ((OTHER, "https://other.invalid"), (THIRD, "https://third.invalid")):
                await conn.execute("INSERT INTO targets (id, url, name) VALUES ($1, $2, $2)", target_id, url)
            return await scenario(conn, add)
        finally:
            await conn.close()

    return asyncio.run(go())


async def _finding(conn, target_id, title, *, evidence=None, severity="medium", hours_ago=1):
    finding_id = uuid.uuid4()
    await conn.execute(
        """INSERT INTO findings (id, target_id, fingerprint, title, severity, tool, url, evidence, status,
                                 source, first_seen_at)
           VALUES ($1, $2, $3, $4, $5, 'nuclei', 'https://x.invalid/', $6::jsonb, 'active', 'dast',
                   NOW() - make_interval(hours => $7))""",
        finding_id, target_id, finding_id.hex, title, severity, json.dumps(evidence or {}), hours_ago)
    return finding_id


def test_changes_report_new_services_and_newly_proven_findings_per_target(monkeypatch):
    from api.exposure import router as exposure_router

    async def scenario(conn, _add):
        device = await conn.fetchval(
            "INSERT INTO device_targets (name, primary_locator) VALUES ('camera', 'camera.lab.invalid') RETURNING id")
        await conn.execute(
            """INSERT INTO device_services (device_target_id, transport, port, service_name, first_seen_at)
               VALUES ($1, 'tcp', 554, 'rtsp', NOW() - INTERVAL '2 hours'),
                      ($1, 'tcp', 22, 'ssh', NOW() - INTERVAL '30 days')""", device)
        await conn.execute(
            """INSERT INTO targets (url, name, asset_owner_id, created_at)
               VALUES ('https://other.invalid:8443', 'admin port', $1, NOW() - INTERVAL '1 hour')""", OTHER)
        await _finding(conn, TARGET, "proven medium", evidence={"proof_of_exploitation": True})
        await _finding(conn, OTHER, "proven on other", evidence={"proof_of_exploitation": True})
        await _finding(conn, TARGET, "old proof", evidence={"proof_of_exploitation": True}, hours_ago=24 * 30)
        await _finding(conn, TARGET, "unproven", evidence={})
        monkeypatch.setattr(exposure_router, "_pool", lambda: _Pool(conn))
        everything = await exposure_router.exposure_changes(days=7, examples=5)
        one_target = await exposure_router.exposure_changes(days=7, examples=5, target_id=[TARGET])
        device_only = await exposure_router.exposure_changes(days=7, examples=5, target_id=[device])
        return everything, one_target, device_only

    everything, one_target, device_only = _run(scenario)

    def category(result, key):
        return next(item for item in result["categories"] if item["key"] == key)

    services = category(everything, "new_services")
    assert services["count"] == 2, "the RTSP port first seen today and the web service under a host"
    assert {e["detail"] for e in services["examples"]} == {"tcp/554 · rtsp", "web service"}
    proven = category(everything, "newly_proven")
    assert proven["count"] == 2 and {e["label"] for e in proven["examples"]} == {"proven medium", "proven on other"}
    assert "proof_state=verified" in proven["href"]

    assert category(one_target, "newly_proven")["count"] == 1
    assert category(one_target, "new_services")["count"] == 0
    assert category(device_only, "new_services")["count"] == 1
    assert category(device_only, "newly_proven")["count"] == 0
    assert everything["total_changes"] >= one_target["total_changes"]
