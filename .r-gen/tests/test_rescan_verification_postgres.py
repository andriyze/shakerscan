"""A Scan's rescan verifications, written to and read back from PostgreSQL.

``record_rescan_verifications`` records one completed ``scan_rescan`` verification (likely_fixed,
the Scan and its read as proof) for each open passive finding of the target the Scan re-checked
on its own URL and no longer saw, never changes a finding's status, skips a finding the Scan
reported again, and is idempotent per Scan. ``GET /retests`` lists them for a follower that closes
findings on a likely_fixed verification. Rows are fixtures on the installed schema.

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
import retest_routes.router as retest_router  # noqa: E402
from scan.rescan_verification import record_rescan_verifications  # noqa: E402

SITE = "https://rescan.test"


async def _fixture(conn):
    target = await conn.fetchval("INSERT INTO targets(url,name) VALUES($1,'Rescan') RETURNING id", SITE)
    first = await conn.fetchval("INSERT INTO scans(target_id,target_url,status) VALUES($1,$2,'completed') RETURNING id", target, SITE)
    later = await conn.fetchval("INSERT INTO scans(target_id,target_url,status) VALUES($1,$2,'completed') RETURNING id", target, SITE)

    async def finding(tool, url, evidence, scan=first):
        return await conn.fetchval(
            """INSERT INTO findings(target_id,scan_id,fingerprint,title,severity,status,tool,url,source,evidence)
               VALUES($1,$2,$3,'fixture','high','active',$4,$5,'dast',$6::jsonb) RETURNING id""",
            target, scan, uuid.uuid4().hex, tool, url, json.dumps(evidence))

    def exposure(path):
        return {"exposure_class": "environment_secret_file", "request_url": SITE + path,
                "response_status": 200, "matched_signature": "fixture", "discovered_via": "seed_path"}

    ids = {
        "env": await finding("shakerscan_exposure_probe", SITE + "/.env", exposure("/.env")),
        "git": await finding("shakerscan_exposure_probe", SITE + "/.git/config",
                             {**exposure("/.git/config"), "exposure_class": "version_control_exposure"}),
        "seen_again": await finding("shakerscan_exposure_probe", SITE + "/id_rsa",
                                    {**exposure("/id_rsa"), "exposure_class": "private_key_material"}, scan=later),
        "csp": await finding("http_baseline", SITE, {
            "check": "missing_header_content-security-policy", "header": "content-security-policy",
            "observed_response": {"request_line": f"GET {SITE}/", "response_status": 200, "principal": "anonymous"}}),
    }
    return target, later, ids


REPORT = {"check_coverage": {
    "schema_version": "scan-check-coverage/v1",
    "exposure": [
        {"url": SITE + "/.env", "response_status": 404, "exposure_class": None},
        {"url": SITE + "/.git/config", "response_status": 200, "exposure_class": "version_control_exposure"},
        {"url": SITE + "/id_rsa", "response_status": 404, "exposure_class": None},
    ],
    "baseline_headers": [{"request_line": f"GET {SITE}/", "response_status": 200, "principal": "anonymous",
                          "present_headers": ["content-security-policy"]}],
}}


def test_a_rescan_records_fixed_verifications_and_changes_no_status(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            async with pool.acquire() as conn:
                target, later, ids = await _fixture(conn)
                first = await record_rescan_verifications(conn, scan_id=str(later), target_id=str(target), report=REPORT)
                again = await record_rescan_verifications(conn, scan_id=str(later), target_id=str(target), report=REPORT)
                rows = await conn.fetch("SELECT finding_id, verification_mode, status, result_status, verdict, "
                                        "scan_id, proof FROM finding_verifications")
                statuses = {row["id"]: row["status"] for row in await conn.fetch("SELECT id, status FROM findings")}
                verdicts = {row["id"]: row["last_verification_verdict"] for row in
                            await conn.fetch("SELECT id, last_verification_verdict FROM findings")}
            assert (first, again) == (2, 0)
            assert {row["finding_id"] for row in rows} == {ids["env"], ids["csp"]}
            assert all((row["verification_mode"], row["status"], row["result_status"], row["verdict"], row["scan_id"])
                       == ("scan_rescan", "completed", "likely_fixed", "likely_fixed", later) for row in rows)
            proofs = {row["finding_id"]: json.loads(row["proof"]) for row in rows}
            assert proofs[ids["env"]]["response_status"] == 404 and proofs[ids["env"]]["scan_id"] == str(later)
            assert proofs[ids["csp"]]["header_present"] is True
            assert set(statuses.values()) == {"active"}  # the engine never closes a finding itself
            assert verdicts[ids["env"]] == "likely_fixed" and verdicts[ids["git"]] is None

            monkeypatch.setattr(retest_router, "_pool_provider", lambda: pool)
            app = FastAPI()
            app.include_router(retest_router.router)
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://api.test") as client:
                listed = await client.get("/retests", params={"verification_mode": "scan_rescan"})
                assert listed.status_code == 200, listed.text
                body = listed.json()
                assert body["count"] == 2
                assert {row["finding_id"] for row in body["retests"]} == {str(ids["env"]), str(ids["csp"])}
                assert all(row["severity"] == "high" and row["verdict"] == "likely_fixed" for row in body["retests"])
                future = await client.get("/retests", params={"since": "2999-01-01T00:00:00Z"})
                assert future.json()["count"] == 0
                assert (await client.get("/retests", params={"verification_mode": "deterministic"})).status_code == 422
                assert (await client.get("/retests", params={"since": "yesterday"})).status_code == 400

    asyncio.run(run())
