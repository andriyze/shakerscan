"""A Scan keeps listing every finding it observed, also after a later run sees it again.

A finding is one row per target and fingerprint, and ``findings.scan_id`` moves to the latest
Scan that saw it. Read by that column, an earlier Scan's list lost the finding while the Scan's
stored count and report still included it, so the Scan's headline, its severity links and its
list disagreed. ``finding_scan_observations`` records each Scan's observations, and a Scan's
findings are read through it: ``GET /findings?scan_id=`` (also with a severity), the Scan
detail's rows and total, and the release gate's links from report rows to their records.

The re-observation below is the statement shape the worker's save path uses (an ``UPDATE`` that
sets ``scan_id``); the rows are fixtures on the installed schema (db/init.sql plus every startup
migration). The startup test rebuilds a database from before the relation existed.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
import importlib
from pathlib import Path
import sys
import uuid

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

from tests.test_scan_local_revocation_postgres import scan_database  # noqa: E402
from tests.test_target_asset_startup_postgres import startup_database  # noqa: E402
from targets.asset_migration import BoundConnectionPool  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]
import finding_routes.router as findings_router  # noqa: E402
from scan.detail_bounds import scan_detail_findings  # noqa: E402
from scan.deployment_gate_rows import SCAN_FINDING_IDS_SQL  # noqa: E402
from scan.finding_observations import OBSERVATIONS_MIGRATION, OBSERVATION_TRIGGER  # noqa: E402
from scan_finding_proof import SCAN_DETAIL_FINDINGS_SQL  # noqa: E402


async def _scan(conn, target) -> uuid.UUID:
    return await conn.fetchval(
        "INSERT INTO scans(target_id,target_url,status) VALUES($1,'https://observed.test','completed') RETURNING id",
        target)


async def _first_seen(conn, target, scan, title, severity) -> uuid.UUID:
    return await conn.fetchval(
        """INSERT INTO findings(target_id,scan_id,fingerprint,title,severity,status,tool,url,source)
           VALUES($1,$2,$3,$4,$5,'active','http_baseline','https://observed.test/',  'dast') RETURNING id""",
        target, scan, uuid.uuid4().hex, title, severity)


async def _seen_again(conn, finding, scan) -> None:
    await conn.execute("UPDATE findings SET scan_id=$2, last_seen_at=NOW() WHERE id=$1", finding, scan)


async def _three_scans(conn) -> dict[str, uuid.UUID]:
    """Three Scans of one target: a header finding all three see, one only the first sees, one
    only the last sees, and one the first two see."""
    target = await conn.fetchval("INSERT INTO targets(url,name) VALUES('https://observed.test','Observed') RETURNING id")
    first, second, third = [await _scan(conn, target) for _ in range(3)]
    every = await _first_seen(conn, target, first, "Missing HSTS header", "low")
    only_first = await _first_seen(conn, target, first, "SQL injection in id", "critical")
    first_two = await _first_seen(conn, target, first, "Missing referrer policy", "info")
    await _seen_again(conn, every, second)
    await _seen_again(conn, first_two, second)
    await _seen_again(conn, every, third)
    only_third = await _first_seen(conn, target, third, "Open redirect", "high")
    return {"target": target, "first": first, "second": second, "third": third, "every": every,
            "only_first": only_first, "first_two": first_two, "only_third": only_third}


def _ids(rows) -> set[str]:
    return {str(row["id"]) for row in rows}


def test_a_scan_lists_and_counts_what_it_observed_after_later_runs_see_it_again(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            async with pool.acquire() as conn:
                ids = await _three_scans(conn)
            expected = {
                "first": {ids["every"], ids["only_first"], ids["first_two"]},
                "second": {ids["every"], ids["first_two"]},  # neither first nor last to see them
                "third": {ids["every"], ids["only_third"]},
            }
            monkeypatch.setattr(findings_router, "_pool_provider", lambda: pool)
            monkeypatch.setattr(findings_router, "_load_effective_ai_settings", lambda: {})
            app = FastAPI()
            app.include_router(findings_router.router)
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://api.test") as client:
                for name, observed in expected.items():
                    listed = await client.get("/findings", params={"scan_id": str(ids[name]), "limit": 500})
                    assert listed.status_code == 200, listed.text
                    body = listed.json()
                    assert _ids(body["findings"]) == {str(value) for value in observed}, name
                    assert body["total"] == len(observed), name
                # A severity link from the Scan's headline lists what the headline counted.
                low = await client.get("/findings", params={"scan_id": str(ids["first"]), "severity": "low"})
                assert _ids(low.json()["findings"]) == {str(ids["every"])}
                info = await client.get("/findings", params={"scan_id": str(ids["second"]), "severity": "info"})
                assert _ids(info.json()["findings"]) == {str(ids["first_two"])}
                # The row still names the Scan that saw it last; the filter does not depend on it.
                row = next(item for item in low.json()["findings"] if item["id"] == str(ids["every"]))
                assert row["scan_id"] == str(ids["third"])
                assert row["first_seen_scan_id"] == str(ids["first"])
            async with pool.acquire() as conn:
                for name, observed in expected.items():
                    rows, total = await scan_detail_findings(conn, SCAN_DETAIL_FINDINGS_SQL, ids[name], 500)
                    assert _ids(rows) == {str(value) for value in observed}, name
                    assert total == len(observed), name
                    linked = await conn.fetch(SCAN_FINDING_IDS_SQL, ids[name])
                    assert _ids(linked) == {str(value) for value in observed}, name
                # The total stays exact when the page is shorter than the Scan's findings.
                rows, total = await scan_detail_findings(conn, SCAN_DETAIL_FINDINGS_SQL, ids["first"], 1)
                assert (len(rows), total) == (1, 3)
                assert rows[0]["severity"] == "critical"
                # Deleting an earlier Scan removes its observations and the finding only it saw;
                # what later Scans observed stays theirs.
                await conn.execute("DELETE FROM scans WHERE id=$1", ids["first"])
                assert await conn.fetchval(
                    "SELECT count(*) FROM finding_scan_observations WHERE scan_id=$1", ids["first"]) == 0
                rows, total = await scan_detail_findings(conn, SCAN_DETAIL_FINDINGS_SQL, ids["second"], 500)
                assert _ids(rows) == {str(ids["every"]), str(ids["first_two"])}
    asyncio.run(run())


def test_startup_installs_the_relation_on_an_existing_database_and_restores_first_and_last():
    async def run():
        async with startup_database() as conn:
            module = importlib.import_module("retest_contract")
            await module.run_schema_migrations(BoundConnectionPool(conn))
            # Reproduce an installation from before the relation shipped. This is an isolated
            # disposable database; no retained operator data exists.
            await conn.execute(f"DROP TRIGGER {OBSERVATION_TRIGGER} ON findings")
            await conn.execute("DROP TABLE finding_scan_observations")
            await conn.execute("DELETE FROM app_schema_migrations WHERE name=$1", OBSERVATIONS_MIGRATION)
            ids = await _three_scans(conn)
            await module.run_schema_migrations(BoundConnectionPool(conn))

            async def observed(name):
                return _ids(await conn.fetch(
                    "SELECT finding_id AS id FROM finding_scan_observations WHERE scan_id=$1", ids[name]))

            # The scan columns of an existing finding name its first and its last Scan, so both
            # get the finding back. A Scan in between left no record (first_two is listed for
            # the second Scan only because that Scan was the last to see it).
            assert await observed("first") == {str(ids["every"]), str(ids["only_first"]), str(ids["first_two"])}
            assert await observed("second") == {str(ids["first_two"])}
            assert await observed("third") == {str(ids["every"]), str(ids["only_third"])}
            assert await conn.fetchval(
                "SELECT count(*) FROM app_schema_migrations WHERE name=$1", OBSERVATIONS_MIGRATION) == 1
            # From now on the trigger records each observation, also for a Scan in between.
            target = ids["target"]
            fourth, fifth = await _scan(conn, target), await _scan(conn, target)
            await _seen_again(conn, ids["only_third"], fourth)
            await _seen_again(conn, ids["only_third"], fifth)
            before = await conn.fetchval("SELECT count(*) FROM finding_scan_observations")
            # A restart is idempotent: no second backfill, no lost rows, one trigger.
            await module.run_schema_migrations(BoundConnectionPool(conn))
            assert await conn.fetchval("SELECT count(*) FROM finding_scan_observations") == before
            assert await observed("third") == {str(ids["every"]), str(ids["only_third"])}
            assert _ids(await conn.fetch(
                "SELECT finding_id AS id FROM finding_scan_observations WHERE scan_id=$1", fourth)) == {
                    str(ids["only_third"])}
            assert await conn.fetchval(
                "SELECT count(*) FROM pg_trigger WHERE tgrelid='findings'::regclass AND tgname=$1",
                OBSERVATION_TRIGGER) == 1
    asyncio.run(run())


def test_a_fresh_install_and_the_startup_migration_share_one_definition():
    from scan.finding_observations import FINDING_SCAN_OBSERVATIONS_SCHEMA_SQL, OBSERVATION_TRIGGER_SQL

    init_sql = (ROOT / "db" / "init.sql").read_text(encoding="utf-8")
    assert FINDING_SCAN_OBSERVATIONS_SCHEMA_SQL.strip() in init_sql
    assert OBSERVATION_TRIGGER_SQL.strip() in init_sql
