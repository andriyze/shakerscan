"""Coverage migration, ownership, latest-event SQL and restart acceptance."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from fastapi import HTTPException

from api.hunt.coverage_ledger import COVERAGE_LEDGER_SCHEMA_STATEMENTS, CoverageLedgerError
from api.hunt.run_service import HuntRunService

DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")


@pytest.mark.asyncio
@pytest.mark.parametrize("bootstrap", [False, True], ids=["upgrade", "fresh-install"])
async def test_coverage_persists_and_checkpoint_uses_latest_owned_evidence(bootstrap):
    import asyncpg

    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
    schema = "hunt_coverage_" + uuid4().hex
    conn = await asyncpg.connect(DSN)
    pool = None
    try:
        await conn.execute(f'CREATE SCHEMA "{schema}"; SET search_path TO "{schema}"')
        ddl = (Path(__file__).resolve().parents[1] / "db/init.sql").read_text()
        await conn.execute("CREATE TABLE targets(id UUID PRIMARY KEY); CREATE TABLE device_targets(id UUID PRIMARY KEY)")
        for table in ("hunt_runs", "hunt_actions"):
            await conn.execute(re.search(rf"CREATE TABLE {table} \(.*?\n\);", ddl, re.S)[0])
        if bootstrap:
            await conn.execute(re.search(r"CREATE TABLE hunt_coverage_angle_events \(.*?\n\);", ddl, re.S)[0])
        # Exercise both an existing installation and repeated startup after a fresh install.
        for _ in range(2):
            for statement in COVERAGE_LEDGER_SCHEMA_STATEMENTS:
                await conn.execute(statement)
        await conn.execute("""CREATE TABLE investigation_candidates (
            id UUID PRIMARY KEY, family TEXT, title TEXT, status TEXT, claimed_severity TEXT,
            fingerprint TEXT, canonical_locus JSONB, verifier_contract_id TEXT,
            last_seen_at TIMESTAMPTZ DEFAULT NOW());
            CREATE TABLE investigation_candidate_observations(candidate_id UUID, hunt_run_id UUID);
        """)
        target, hunt, other_hunt, completed, partial, foreign, candidate = [uuid4() for _ in range(7)]
        await conn.execute("INSERT INTO targets VALUES($1)", target)
        await conn.executemany(
            "INSERT INTO hunt_runs(id,target_kind,target_id,objective,budget_json,budget_used_json) "
            "VALUES($1,'web',$2,'Coverage acceptance','{\"max_http_requests\":20}','{\"http_requests\":2}')",
            [(hunt, target), (other_hunt, target)],
        )
        await conn.executemany(
            "INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status) VALUES($1,$2,'http.request',$3)",
            [(completed, hunt, "completed"), (partial, hunt, "partial"), (foreign, other_hunt, "completed")],
        )
        pool = await asyncpg.create_pool(DSN, min_size=1, max_size=2, server_settings={"search_path": schema})
        service = HuntRunService(lambda: pool)
        angle = {"family": "authorization", "locus": {"method": "GET", "route": "/records/{id}"},
                 "mechanism": "cross-principal read", "status": "planned"}
        await service.record_coverage_angle(str(hunt), values=angle)
        for action, code in [(foreign, "coverage_evidence_not_owned"), (partial, "coverage_negative_requires_completed_actions")]:
            with pytest.raises(CoverageLedgerError) as exc:
                await service.record_coverage_angle(str(hunt), values={
                    **angle, "status": "negative", "evidence_action_ids": [str(action)],
                })
            assert exc.value.code == code
        await service.record_coverage_angle(str(hunt), values={
            **angle, "status": "negative", "evidence_action_ids": [str(completed)],
        })
        current = await service.coverage_angles(str(hunt), limit=1)
        assert current["total"] == 1 and current["angles"][0]["status"] == "negative"
        assert await conn.fetchval("SELECT count(*) FROM hunt_coverage_angle_events") == 2
        assert (await service.coverage_angles(str(other_hunt)))["total"] == 0

        await conn.execute(
            "INSERT INTO investigation_candidates(id,family,title,status,claimed_severity,fingerprint,canonical_locus) "
            "VALUES($1,'authorization','Read boundary','new','info','canonical-fingerprint','{\"route\":\"/other/{id}\"}')",
            candidate,
        )
        candidate_angle = {**angle, "locus": {"route": "/other/{id}"}, "status": "candidate",
                           "evidence_action_ids": [str(completed)], "candidate_id": str(candidate)}
        with pytest.raises(CoverageLedgerError) as exc:
            await service.record_coverage_angle(str(hunt), values=candidate_angle)
        assert exc.value.code == "coverage_candidate_not_owned"
        await conn.execute("INSERT INTO investigation_candidate_observations VALUES($1,$2)", candidate, hunt)
        await service.record_coverage_angle(str(hunt), values=candidate_angle)
        checkpoint = await service.checkpoint(str(hunt))
        assert checkpoint["review_queue"][0]["fingerprint"] == "canonical-fingerprint"
        assert len(checkpoint["continuation_queue"]) == 1
        await conn.execute("UPDATE investigation_candidates SET status='verified' WHERE id=$1", candidate)

        # Exceed the compact window: aggregate counts must cover all exact angles.
        for n in range(205):
            await service.record_coverage_angle(str(hunt), values={
                **angle, "locus": {"route": f"/unexamined/{n}"},
            })
        await pool.close()
        pool = await asyncpg.create_pool(DSN, min_size=1, max_size=2, server_settings={"search_path": schema})
        restarted = HuntRunService(lambda: pool)
        checkpoint = await restarted.checkpoint(str(hunt))
        assert checkpoint["coverage"]["angle_count"] == 207
        assert checkpoint["coverage"]["status_counts"] == {"candidate": 1, "negative": 1, "planned": 205}
        assert checkpoint["coverage"]["angles_truncated"] is True
        assert len(checkpoint["coverage"]["latest_angles"]) == 200
        assert checkpoint["review_queue"] == []
        assert checkpoint["budget_used"] == {"http_requests": 2}
        assert json.loads(await conn.fetchval("SELECT budget_used_json FROM hunt_runs WHERE id=$1", hunt)) == {"http_requests": 2}
        await conn.execute("UPDATE hunt_runs SET status='completed' WHERE id=$1", hunt)
        with pytest.raises(HTTPException) as exc:
            await restarted.record_coverage_angle(str(hunt), values=angle)
        assert exc.value.status_code == 409
    finally:
        if pool is not None:
            await pool.close()
        await conn.execute(f'DROP SCHEMA "{schema}" CASCADE')
        await conn.close()
