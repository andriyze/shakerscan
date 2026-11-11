"""A discovery run does not decide what a target shows as its latest result.

A discovery run (``scan_role`` ``asm_recon`` or ``parallel_discovery``) is a scan row with a
score and a grade of its own, and the Scans list hides it by default. The target's grade, score,
last-scanned time and Scan count, the dashboard's latest results and the exposure inventory's
latest scan come from application Scans; the Scans list says how many discovery and internal
runs it leaves out.

The rows are fixtures on the installed schema (db/init.sql plus every startup migration). The
startup test rebuilds a database whose targets were written by the earlier trigger function.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import importlib
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

from tests.test_scan_local_revocation_postgres import scan_database  # noqa: E402
from tests.test_target_asset_startup_postgres import startup_database  # noqa: E402
from targets.asset_migration import BoundConnectionPool  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]
from scan.discovery_runs import (  # noqa: E402
    DISCOVERY_SCAN_ROLES,
    TARGET_HEADLINE_MIGRATION,
    TARGET_STATS_FUNCTION_SQL,
)

NOW = datetime.now(timezone.utc)

# The trigger function as it was before discovery runs were told apart: every completed
# non-shard scan became the target's latest result.
EARLIER_TARGET_STATS_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION update_target_stats()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'completed'
       AND NEW.target_id IS NOT NULL
       AND COALESCE(NEW.scan_role, 'standalone') <> 'shard' THEN
        UPDATE targets SET
            last_scan_id = NEW.id,
            last_scanned_at = NEW.completed_at,
            last_score = NEW.score,
            last_grade = NEW.grade,
            last_assurance_score = NEW.assurance_score,
            total_scans = total_scans + 1,
            active_findings_count = (
                SELECT COUNT(*) FROM findings
                WHERE target_id = NEW.target_id AND status = 'active'
            ),
            updated_at = NOW()
        WHERE id = NEW.target_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""


async def _target(conn, host: str) -> uuid.UUID:
    return await conn.fetchval(
        "INSERT INTO targets(url,name) VALUES($1,$2) RETURNING id", f"https://{host}", host)


async def _completed(conn, target, host, *, role, score, grade, assurance, minutes_ago, findings=0) -> uuid.UUID:
    """A run of ``target`` that completes ``minutes_ago`` (the trigger fires on the transition)."""
    created = NOW - timedelta(minutes=minutes_ago + 5)
    scan = await conn.fetchval(
        """INSERT INTO scans(target_id,target_url,status,scan_type,run_kind,scan_role,created_at)
           VALUES($1,$2,'running','scan','web_dast',$3,$4) RETURNING id""",
        target, f"https://{host}", role, created)
    for index in range(findings):
        await conn.execute(
            """INSERT INTO findings(target_id,scan_id,fingerprint,title,severity,status,tool,url,source)
               VALUES($1,$2,$3,$4,'low','active','http_baseline',$5,'dast')""",
            target, scan, uuid.uuid4().hex, f"Missing header {index}", f"https://{host}/")
    await conn.execute(
        """UPDATE scans SET status='completed', score=$2, grade=$3, assurance_score=$4,
                  findings_count=$5, completed_at=$6 WHERE id=$1""",
        scan, score, grade, assurance, findings, NOW - timedelta(minutes=minutes_ago))
    return scan


async def _headline(conn, target) -> dict:
    return dict(await conn.fetchrow(
        """SELECT last_scan_id, last_score, last_grade, last_assurance_score, last_scanned_at,
                  total_scans, active_findings_count FROM targets WHERE id=$1""", target))


def test_the_discovery_roles_are_the_ones_the_engine_writes():
    import asm_inventory
    import parallel_scan

    assert set(DISCOVERY_SCAN_ROLES) == {asm_inventory.ASM_RECON_ROLE, parallel_scan.PARALLEL_DISCOVERY_ROLE}
    init_sql = (ROOT / "db" / "init.sql").read_text(encoding="utf-8")
    assert TARGET_STATS_FUNCTION_SQL.strip() in init_sql


def test_a_discovery_run_does_not_decide_the_latest_result(template_database, monkeypatch):
    from operations import dashboard_data
    import exposure.router as exposure_router

    async def run():
        async with scan_database(template_database) as pool:
            async with pool.acquire() as conn:
                target = await _target(conn, "app.observed.test")
                application = await _completed(
                    conn, target, "app.observed.test", role="standalone", score=0, grade="F*",
                    assurance=83, minutes_ago=30, findings=3)
                # A later discovery run of the same target, graded on the little it looked at.
                discovery = await _completed(
                    conn, target, "app.observed.test", role="asm_recon", score=68, grade="D",
                    assurance=32, minutes_ago=10, findings=2)
                parallel_step = await _completed(
                    conn, target, "app.observed.test", role="parallel_discovery", score=90, grade="A",
                    assurance=10, minutes_ago=5)
                # A target only discovery has looked at has no application result yet.
                mapped = await _target(conn, "mapped.observed.test")
                await _completed(conn, mapped, "mapped.observed.test", role="asm_recon", score=75,
                                 grade="C", assurance=20, minutes_ago=3, findings=1)

                headline = await _headline(conn, target)
                assert headline["last_scan_id"] == application
                assert (headline["last_score"], headline["last_grade"]) == (0, "F*")
                assert headline["last_assurance_score"] == 83
                assert headline["last_scanned_at"] == NOW - timedelta(minutes=30)
                assert headline["total_scans"] == 1
                # What the discovery run recorded still counts on the target.
                assert headline["active_findings_count"] == 5
                only_mapped = await _headline(conn, mapped)
                assert only_mapped["last_scan_id"] is None and only_mapped["last_grade"] is None
                assert (only_mapped["total_scans"], only_mapped["active_findings_count"]) == (0, 1)

                # The dashboard's latest result of the target is the application Scan.
                recent = await dashboard_data.recent_latest_scans(conn, limit=10)
                assert [row["id"] for row in recent] == [application]
                assert (recent[0]["grade"], recent[0]["findings_count"]) == ("F*", 3)

            # The exposure inventory links the same Scan as the asset's latest.
            monkeypatch.setattr(exposure_router, "_pool", lambda: pool)
            body = await exposure_router.exposure_assets(
                None, root_domain=None, kind=None, cohort="all", limit=100, offset=0, cursor=None,
                sort=None, fields=None, count=None, since=None)
            assets = {asset["url"]: asset for asset in body["assets"]}
            graded = assets["https://app.observed.test"]
            assert str(graded["latest_scan_id"]) == str(application)
            assert graded["latest_scan_href"] == f"/scans/{application}"
            assert (graded["grade"], graded["total_scans"]) == ("F*", 1)
            assert assets["https://mapped.observed.test"]["latest_scan_id"] is None

            # The Scans list shows the application Scan and says how many runs it leaves out;
            # with the control on, it lists all of them and hides none.
            api = importlib.import_module("api")
            api = importlib.import_module("api.api") if hasattr(api, "__path__") else api
            monkeypatch.setattr(api, "db_pool", pool)
            args = dict(status=None, target=None, root_domain=None, created_within_days=None,
                        include_shards=False, include_model_intake=False, include_devices=False,
                        limit=50, offset=0, include_details=False, cursor=None, count=None,
                        fields=None, since=None)
            listed = await api.list_scans(None, target_id=str(target), include_internal=False, **args)
            assert [row["id"] for row in listed["scans"]] == [str(application)]
            assert (listed["total"], listed["hidden_internal"]) == (1, 2)
            shown = await api.list_scans(None, target_id=str(target), include_internal=True, **args)
            assert {row["id"] for row in shown["scans"]} == {
                str(application), str(discovery), str(parallel_step)}
            assert (shown["total"], shown["hidden_internal"]) == (3, 0)
            everything = await api.list_scans(None, target_id=None, include_internal=False, **args)
            assert (everything["total"], everything["hidden_internal"]) == (1, 3)
    asyncio.run(run())


def test_startup_repairs_targets_whose_latest_result_came_from_a_discovery_run():
    async def run():
        async with startup_database() as conn:
            module = importlib.import_module("retest_contract")
            await module.run_schema_migrations(BoundConnectionPool(conn))
            # Reproduce an installation from before discovery runs were told apart. This is an
            # isolated disposable database; no retained operator data exists.
            await conn.execute(EARLIER_TARGET_STATS_FUNCTION_SQL)
            await conn.execute("DELETE FROM app_schema_migrations WHERE name=$1", TARGET_HEADLINE_MIGRATION)
            target = await _target(conn, "app.repair.test")
            application = await _completed(
                conn, target, "app.repair.test", role="standalone", score=0, grade="F*", assurance=83,
                minutes_ago=30, findings=3)
            await _completed(conn, target, "app.repair.test", role="asm_recon", score=68, grade="D",
                             assurance=32, minutes_ago=10, findings=1)
            mapped = await _target(conn, "mapped.repair.test")
            await _completed(conn, mapped, "mapped.repair.test", role="asm_recon", score=75, grade="C",
                             assurance=20, minutes_ago=3)
            # A target whose latest result is an application Scan newer than its discovery run.
            settled = await _target(conn, "settled.repair.test")
            await _completed(conn, settled, "settled.repair.test", role="asm_recon", score=70, grade="C",
                             assurance=20, minutes_ago=50)
            settled_scan = await _completed(
                conn, settled, "settled.repair.test", role="standalone", score=95, grade="A",
                assurance=70, minutes_ago=40)
            before = await _headline(conn, target)
            assert (before["last_grade"], before["last_score"], before["total_scans"]) == ("D", 68, 2)

            await module.run_schema_migrations(BoundConnectionPool(conn))

            repaired = await _headline(conn, target)
            assert repaired["last_scan_id"] == application
            assert (repaired["last_grade"], repaired["last_score"]) == ("F*", 0)
            assert repaired["last_assurance_score"] == 83
            assert repaired["last_scanned_at"] == NOW - timedelta(minutes=30)
            assert (repaired["total_scans"], repaired["active_findings_count"]) == (1, 4)
            only_mapped = await _headline(conn, mapped)
            assert only_mapped["last_scan_id"] is None
            assert (only_mapped["last_grade"], only_mapped["last_score"]) == (None, None)
            assert only_mapped["last_scanned_at"] is None and only_mapped["total_scans"] == 0
            kept = await _headline(conn, settled)
            assert kept["last_scan_id"] == settled_scan
            assert (kept["last_grade"], kept["total_scans"]) == ("A", 1)

            # From now on a discovery run leaves the latest result alone, and a restart
            # neither repairs twice nor puts the earlier function back.
            await _completed(conn, target, "app.repair.test", role="asm_recon", score=50, grade="E",
                             assurance=30, minutes_ago=1)
            await module.run_schema_migrations(BoundConnectionPool(conn))
            again = await _headline(conn, target)
            assert again["last_scan_id"] == application
            assert (again["last_grade"], again["total_scans"]) == ("F*", 1)
            assert await conn.fetchval(
                "SELECT count(*) FROM app_schema_migrations WHERE name=$1", TARGET_HEADLINE_MIGRATION) == 1
    asyncio.run(run())
