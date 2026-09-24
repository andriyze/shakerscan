"""Real PostgreSQL materialization, deduplication, attribution and rollback.

Uses an isolated schema with the columns/constraints touched by the production
bridge. Queue/session resolution and blind Juice Shop recall are not tested here.
"""
import json
import os
from urllib.parse import urlsplit
import uuid

import pytest

from api.finding_routes.hunt_scope import finding_hunt_predicate
from api.hunt.deterministic_findings import materialize_verified_hunt_findings
from tests.test_hunt_authz_findings import ORIGIN, proof

DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")


@pytest.mark.parametrize("kind", ["api", "device"])
@pytest.mark.asyncio
async def test_proof_is_durable_deduplicated_and_attributed_to_each_verifying_run(kind):
    import asyncpg
    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
    schema = "hunt_authz_proof_" + uuid.uuid4().hex
    conn = await asyncpg.connect(DSN)
    try:
        await conn.execute(f'CREATE SCHEMA "{schema}"')
        await conn.execute(f'SET search_path TO "{schema}"')
        await conn.execute("""
          CREATE TABLE targets(id uuid PRIMARY KEY, active_findings_count int DEFAULT 0,updated_at timestamptz);
          CREATE TABLE device_targets(LIKE targets INCLUDING ALL);
          CREATE TABLE hunt_runs(id uuid PRIMARY KEY,target_id uuid,device_target_id uuid);
          CREATE TABLE findings(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            target_id uuid REFERENCES targets(id),device_target_id uuid REFERENCES device_targets(id),
            hunt_run_id uuid REFERENCES hunt_runs(id),fingerprint text,title text,description text,severity text,
            cvss_score numeric,tool text,cwe text,url text,evidence jsonb,source text,status text,
            last_verification_status text,last_verification_verdict text,last_verification_confidence numeric,
            last_verified_at timestamptz,verification_count int,last_seen_at timestamptz,
            resolved_at timestamptz,updated_at timestamptz);
          CREATE UNIQUE INDEX web_identity ON findings(target_id,fingerprint) WHERE target_id IS NOT NULL;
          CREATE UNIQUE INDEX device_identity ON findings(device_target_id,fingerprint) WHERE device_target_id IS NOT NULL;
          CREATE TABLE finding_verifications(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            finding_id uuid REFERENCES findings(id),target_id uuid,device_target_id uuid,
            requested_by text,status text,result_status text,verdict text,verdict_reason text,finding_type text,
            target_url text,original_url text,proof jsonb,confidence numeric,verification_mode text,
            contract_id text,contract_version text,proof_basis text,started_at timestamptz,
            completed_at timestamptz,updated_at timestamptz);
        """)
        target, first, second = (uuid.uuid4() for _ in range(3))
        table, column = ("device_targets", "device_target_id") if kind == "device" else ("targets", "target_id")
        await conn.execute(f"INSERT INTO {table}(id) VALUES ($1)", target)
        for hunt in (first, second):
            await conn.execute(f"INSERT INTO hunt_runs(id,{column}) VALUES ($1,$2)", hunt, target)
            async with conn.transaction():
                ids = await materialize_verified_hunt_findings(
                    conn, hunt, uuid.uuid4(), target, ORIGIN, "authz.verify", uuid.uuid4(),
                    {}, [proof()], target_kind=kind,
                )
            assert len(ids) == 1
        assert await conn.fetchval("SELECT count(*) FROM findings") == 1
        assert await conn.fetchval("SELECT count(*) FROM finding_verifications") == 2
        row = await conn.fetchrow("SELECT * FROM findings")
        assert row["cwe"] == "CWE-639" and row["verification_count"] == 2
        assert row["last_verification_verdict"] == "exploited" and row["cvss_score"] is None
        assert json.loads(row["evidence"])["canonical_capability"] == "authz.verify"
        for hunt in (first, second):
            assert await conn.fetchval("SELECT count(*) FROM findings f WHERE " + finding_hunt_predicate(1), hunt) == 1
        # Candidate-family proofs historically lack direct attribution: retained
        # verification still answers the run-scoped query without backfill writes.
        await conn.execute("UPDATE findings SET hunt_run_id=NULL")
        assert await conn.fetchval("SELECT count(*) FROM findings f WHERE " + finding_hunt_predicate(1), first) == 1
        assert await conn.fetchval(f"SELECT active_findings_count FROM {table} WHERE id=$1", target) == 1
        # Outer settlement failure must roll back findings and history together.
        with pytest.raises(RuntimeError, match="rollback fixture"):
            async with conn.transaction():
                await materialize_verified_hunt_findings(
                    conn, second, uuid.uuid4(), target, ORIGIN, "authz.verify", uuid.uuid4(),
                    {}, [proof()], target_kind=kind,
                )
                raise RuntimeError("rollback fixture")
        assert await conn.fetchval("SELECT count(*) FROM finding_verifications") == 2
        assert await conn.fetchval("SELECT verification_count FROM findings") == 2
    finally:
        await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await conn.close()
