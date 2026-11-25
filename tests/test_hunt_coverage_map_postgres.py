"""Open coverage read from PostgreSQL: the real queries, the finish guard and the debrief."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from fastapi import HTTPException

from api.hunt.coverage_ledger import COVERAGE_LEDGER_SCHEMA_STATEMENTS
from api.hunt.coverage_map import load_coverage
from api.hunt.run_service import HuntRunService

DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")


@pytest.mark.asyncio
async def test_coverage_is_read_from_the_hunts_records_and_holds_an_early_finish():
    import asyncpg

    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
    schema = "hunt_open_coverage_" + uuid4().hex
    conn = await asyncpg.connect(DSN)
    pool = None
    try:
        await conn.execute(f'CREATE SCHEMA "{schema}"; SET search_path TO "{schema}"')
        ddl = (Path(__file__).resolve().parents[1] / "db/init.sql").read_text()
        await conn.execute("CREATE TABLE targets(id UUID PRIMARY KEY); CREATE TABLE device_targets(id UUID PRIMARY KEY);"
                           "CREATE TABLE scan_campaigns(id UUID PRIMARY KEY);"
                           "CREATE TABLE budget_reservations(owner_kind TEXT, owner_id TEXT, status TEXT);"
                           "CREATE TABLE http_transactions(hunt_run_id UUID, hunt_action_id UUID,"
                           " sequence INTEGER, status_code INTEGER)")
        for table in ("hunt_runs", "hunt_actions", "target_endpoints", "hunt_coverage_angle_events"):
            await conn.execute(re.search(rf"CREATE TABLE {table} \(.*?\n\);", ddl, re.S)[0])
        for statement in COVERAGE_LEDGER_SCHEMA_STATEMENTS:
            await conn.execute(statement)
        await conn.execute("""CREATE TABLE investigation_candidates (
            id UUID PRIMARY KEY, family TEXT, title TEXT, status TEXT, claimed_severity TEXT,
            fingerprint TEXT, canonical_locus JSONB, verifier_contract_id TEXT,
            last_seen_at TIMESTAMPTZ DEFAULT NOW());
            CREATE TABLE investigation_candidate_observations(candidate_id UUID, hunt_run_id UUID);""")
        target, hunt, other = uuid4(), uuid4(), uuid4()
        await conn.execute("INSERT INTO targets VALUES($1)", target)
        await conn.executemany(
            "INSERT INTO hunt_runs(id,target_kind,target_id,objective,status,policy_json,budget_json,budget_used_json) "
            "VALUES($1,'web',$2,'Coverage',$3,$4,'{\"max_http_requests\":1000,\"max_duration_seconds\":5400}',"
            "'{\"http_requests\":20}')",
            [(hunt, target, "active", json.dumps({"allowed_capabilities": ["web.crawl", "web.content_discover"]})),
             (other, target, "active", "{}")],
        )
        for path, params, source in (("/search", "q", "crawl"), ("/hub/api/users/{id}", "", "crawl"),
                                     ("/.env", "", "hunt_probe"), ("/gone", "", "crawl")):
            await conn.execute(
                "INSERT INTO target_endpoints(target_id,method,path,param_shape,fingerprint,source,test_status) "
                "VALUES($1,'GET',$2,$3,$4,$5,$6)", target, path, params, uuid4().hex, source,
                "gone" if path == "/gone" else "untested")

        answers = []

        def action(capability, status, values, http_status=None):
            action_id = uuid4()
            if http_status:
                answers.append((hunt, action_id, len(answers), http_status))
            return (action_id, hunt, capability, status, json.dumps({"input": values}), "{}")

        await conn.executemany(
            "INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,input_summary,result_summary) "
            "VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb)",
            [action("web.crawl", "completed", {}),
             action("http.request", "completed", {"method": "GET", "path": "/hub/api/users/2"}, 200),
             action("sqli.verify", "completed", {"path": "/search", "parameter": "q"}),
             action("http.request", "completed", {"method": "GET", "path": "/hub/orders"}, 200)],
        )
        await conn.executemany("INSERT INTO http_transactions VALUES($1,$2,$3,$4)", answers)
        candidate = uuid4()
        await conn.execute(
            "INSERT INTO investigation_candidates(id,family,title,status,fingerprint,canonical_locus) "
            "VALUES($1,'bola','Other users','new','fp-1','{\"route\":\"/hub/api/users/{id}\"}')", candidate)
        await conn.execute("INSERT INTO investigation_candidate_observations VALUES($1,$2)", candidate, hunt)

        run = dict(await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1", hunt))
        report = await load_coverage(conn, run)
        open_routes = {item["endpoint"]: item["untested"] for item in report["open"]}
        assert "GET /gone" not in open_routes  # retired inventory rows are not coverage
        assert "GET /hub/api/users/{id}" not in open_routes  # requested, and its bola candidate
        assert open_routes["GET /search"] == ["xss"]  # sqli.verify ran (and requested it); xss did not
        assert open_routes["GET /.env"] == ["exposure", "review"]
        assert "GET /hub/orders" in open_routes  # a route this Hunt saw answer
        assert report["discovery"]["steps"] == {"crawl": "done", "content_discovery": "not_run"}

        pool = await asyncpg.create_pool(DSN, min_size=1, max_size=2, server_settings={"search_path": schema})
        service = HuntRunService(lambda: pool)
        page = await service.coverage(str(hunt), limit=2)
        assert page["returned"] == 2 and page["has_more"] is True
        with pytest.raises(HTTPException) as refused:
            await service.finish(str(hunt), summary="Done", next_actions=[])
        assert refused.value.status_code == 409 and "GET /.env" in refused.value.detail
        assert await conn.fetchval("SELECT status FROM hunt_runs WHERE id=$1", hunt) == "active"
        # Refused before anything changed; the forced finish and its debrief are covered without a
        # database (test_hunt_finish_coverage_guard), as finishing settles tables this fixture lacks.
        checkpoint_free = await load_coverage(conn, {**run, "target_kind": "device"})
        assert checkpoint_free is None
    finally:
        if pool is not None:
            await pool.close()
        await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await conn.close()
