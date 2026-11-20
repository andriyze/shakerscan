"""Several targets in one list request, on the full schema (PostgreSQL).

GET /findings, /scans, /hunts, /timeline and /exposure/services take a repeated ``target_id``; one
id filters exactly as before. The schema is db/init.sql plus every startup migration. Hosts are
under the reserved ``.invalid`` domain; nothing is contacted. Requires
``TARGET_ASSET_TEST_DATABASE_URL``.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

from tests.test_scan_local_revocation_postgres import scan_database  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]


async def _seed(conn):
    ids = {}
    for name in ("app", "other", "third"):
        target_id = await conn.fetchval(
            "INSERT INTO targets (url, name) VALUES ($1, $2) RETURNING id", f"https://{name}.filters.invalid", name)
        ids[name] = target_id
        finding_id = uuid.uuid4()
        await conn.execute(
            """INSERT INTO findings (id, target_id, fingerprint, title, severity, tool, url, evidence, status, source)
               VALUES ($1, $2, $3, $4, 'medium', 'nuclei', $5, $6::jsonb, 'active', 'dast')""",
            finding_id, target_id, finding_id.hex, f"finding on {name}", f"https://{name}.filters.invalid/",
            json.dumps({}))
        await conn.execute(
            "INSERT INTO scans (target_id, target_url, status, scan_type) VALUES ($1, $2, 'completed', 'scan')",
            target_id, f"https://{name}.filters.invalid")
        await conn.execute(
            "INSERT INTO hunt_runs (target_kind, target_id, objective) VALUES ('web', $1, $2)", target_id, name)
    return ids


def test_findings_scans_hunts_timeline_and_services_take_several_targets(template_database, monkeypatch):
    from finding_routes.list_query import FindingFilters
    from list_contract import SqlParams
    from operations import router as operations_router
    from scan_list_filters import scan_list_filters
    from hunt.run_service import HuntRunService
    from exposure.service_intel import load_service_intelligence
    from exposure.service_actions import canonical_registry
    from exposure.service_store import service_page

    async def run():
        async with scan_database(template_database) as pool:
            async with pool.acquire() as conn:
                ids = await _seed(conn)
                app, other, third = ids["app"], ids["other"], ids["third"]

                params = SqlParams()
                where = FindingFilters(target_id=[str(app), str(other)]).clauses(params)
                findings = {r["title"] for r in await conn.fetch(
                    f"SELECT f.title FROM findings f WHERE {' AND '.join(where)}", *params.values)}
                one = SqlParams()
                single = {r["title"] for r in await conn.fetch(
                    "SELECT f.title FROM findings f WHERE "
                    + " AND ".join(FindingFilters(target_id=str(third)).clauses(one)), *one.values)}

                sql, values = scan_list_filters(target_id=[str(app), f"{other},{other}"])
                scans = {r["target_url"] for r in await conn.fetch(
                    f"SELECT s.target_url FROM scans s LEFT JOIN targets t ON t.id = s.target_id WHERE 1=1{sql}",
                    *values)}

                snapshot, matcher = load_service_intelligence()
                services = await service_page(
                    conn, target_kind="all", target_id=[app, third], root_domain=None, search="",
                    limit=25, offset=0, snapshot=snapshot, matcher=matcher, registry=canonical_registry())

            hunts = await HuntRunService(lambda: pool).list(target_id=[str(other), str(third)])
            monkeypatch.setattr(operations_router, "_pool", lambda: pool)
            timeline = await operations_router.mission_timeline(
                limit=50, target_id=[str(app), str(third)], include_campaign_actions=True, include_scans=True,
                include_schedules=True, include_evidence=True, include_refuters=True, include_exports=True,
                cohort=None)
            return ids, findings, single, scans, services, hunts, timeline

    ids, findings, single, scans, services, hunts, timeline = asyncio.run(run())
    assert findings == {"finding on app", "finding on other"}
    assert single == {"finding on third"}, "one id still filters exactly as before"
    assert scans == {"https://app.filters.invalid", "https://other.filters.invalid"}
    assert {item["id"] for item in services["targets"]} == {str(ids["app"]), str(ids["third"])}
    listed = hunts.get("items") or hunts.get("hunts") or hunts.get("runs") or []
    assert {item["objective"] for item in listed} == {"other", "third"}, hunts.keys()
    events = timeline.get("events") or timeline.get("items") or []
    labels = {str(e.get("target_url") or e.get("label") or e.get("title") or "") for e in events}
    assert any("app.filters.invalid" in label for label in labels), events[:3]
    assert not any("other.filters.invalid" in label for label in labels)
