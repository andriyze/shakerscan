"""GET /findings?include_retest=true says per row whether it can be retested, as the detail does.

A client listing findings to offer retests (a "retest selected" list) needs to know which rows a
retest can conclude, without one detail request per row. The list answers the same
``retest_supported``/``retest_type``/``retest_modes``/``retest_unsupported_reason`` the detail
answers, decided by the same function, in one read for the page. Without the flag the list is
unchanged. Rows are fixtures on the installed schema (db/init.sql plus every startup migration).

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import uuid

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

from tests.test_scan_local_revocation_postgres import scan_database  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]
import finding_routes.router as findings_router  # noqa: E402

KEYS = ("retest_supported", "retest_type", "retest_modes", "retest_unsupported_reason", "retest_active")


async def _fixture_rows(pool) -> dict[str, uuid.UUID]:
    """Fixture findings: a SQL injection a prover retests, an exposure only a Scan checks again,
    a finding of a signed-in Scan whose identity a retest cannot apply, and a device finding."""
    async with pool.acquire() as conn:
        target = await conn.fetchval("INSERT INTO targets(url,name) VALUES('https://retest-list.test','Retest list') RETURNING id")
        signed_in = await conn.fetchval(
            """INSERT INTO scans(target_id,target_url,status,options) VALUES($1,'https://retest-list.test','completed',$2::jsonb)
               RETURNING id""", target, json.dumps({"credential_profile_refs": ["cp-fixture"]}))
        device = await conn.fetchval(
            "INSERT INTO device_targets(name,primary_locator) VALUES('Retest host','retest-host.test') RETURNING id")

        async def finding(title, tool, **extra):
            return await conn.fetchval(
                """INSERT INTO findings(target_id,device_target_id,scan_id,fingerprint,title,severity,status,tool,url,source,evidence)
                   VALUES($1,$2,$3,$4,$5,'high','active',$6,'https://retest-list.test/q?id=1',$7,$8::jsonb) RETURNING id""",
                extra.get("target", target), extra.get("device"), extra.get("scan"), uuid.uuid4().hex, title, tool,
                extra.get("source", "dast"), json.dumps(extra.get("evidence", {})))

        return {
            "sqli": await finding("SQL Injection in id", "sqlmap", evidence={"type": "sqli", "param": "id"}),
            "exposure": await finding("Sensitive exposure: configuration secret file", "shakerscan_exposure_probe"),
            "signed_in": await finding("SQL Injection in q", "sqlmap", scan=signed_in, evidence={"type": "sqli", "param": "q"}),
            "device": await finding("Telnet open", "device_posture", target=None, device=device, source="device"),
        }


def test_the_list_reports_retest_capability_as_the_detail_does(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            ids = await _fixture_rows(pool)
            monkeypatch.setattr(findings_router, "_pool_provider", lambda: pool)
            monkeypatch.setattr(findings_router, "_load_effective_ai_settings", lambda: {})
            app = FastAPI()
            app.include_router(findings_router.router)
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://api.test") as client:
                listed = await client.get("/findings", params={"status": "active", "limit": 500, "include_retest": "true"})
                assert listed.status_code == 200, listed.text
                rows = {row["id"]: row for row in listed.json()["findings"]}
                assert set(rows) == {str(value) for value in ids.values()}
                for name, finding_id in ids.items():
                    detail = await client.get(f"/findings/{finding_id}")
                    assert detail.status_code == 200, detail.text
                    expected = {key: detail.json().get(key) for key in KEYS}
                    assert {key: rows[str(finding_id)].get(key) for key in KEYS} == expected, name
                assert rows[str(ids["sqli"])]["retest_supported"] is True
                assert rows[str(ids["exposure"])]["retest_supported"] is False
                assert rows[str(ids["device"])]["retest_supported"] is False
                assert rows[str(ids["signed_in"])]["retest_unsupported_reason"] == "retest_needs_signed_in_identity"
                plain = await client.get("/findings", params={"status": "active", "limit": 500})
                assert all("retest_supported" not in row for row in plain.json()["findings"])
                refused = await client.get("/findings", params={"include_retest": "true", "count": "exact"})
                assert refused.status_code == 400
    asyncio.run(run())
