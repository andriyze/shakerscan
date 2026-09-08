"""Real PostgreSQL locking/rollback acceptance; no target traffic or capability calls.

Set HUNT_TEST_POSTGRES_DSN to a disposable local PostgreSQL service. Each test
creates and removes its own randomly named schema, never an existing schema.
Missing configuration is a skip; configured but unavailable PostgreSQL is a failure.
"""
import asyncio
from contextlib import asynccontextmanager
import os
from types import SimpleNamespace
from urllib.parse import urlsplit
import uuid

import pytest

from api.hunt.authorization_candidate import LINK_TYPE, ensure_authorization_candidate
from api.hunt.authorization_evidence import digest
from api.hunt.authorization_repository import PROPOSAL_TYPE, PostgresAuthorizationRepository


DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")

# Only the tables this repository operation touches. The real repository SQL,
# JSONB casts, UUIDs, xmax and row locks are executed without SQLite adaptation.
DDL = """
CREATE TABLE hunt_runs(id uuid PRIMARY KEY,target_id uuid,device_target_id uuid,target_kind text,status text,context_pack jsonb);
CREATE TABLE application_graph_nodes(id uuid PRIMARY KEY,target_id uuid,node_type text,node_key text,label text,attributes jsonb,UNIQUE(target_id,node_type,node_key));
CREATE TABLE investigation_candidates(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),plane text,target_id uuid,device_target_id uuid,
 research_episode_id uuid,agent_hunt_run_id uuid,device_agent_run_id uuid,hunt_run_id uuid,
 family text,canonical_locus jsonb,title text,claim text,claimed_severity text,evidence_refs jsonb,
 verifier_contract_id text,source_kind text,fingerprint text UNIQUE,status text,created_by text,
 last_seen_at timestamptz DEFAULT NOW(),created_at timestamptz DEFAULT NOW(),updated_at timestamptz DEFAULT NOW());
CREATE TABLE investigation_candidate_observations(
 id bigserial PRIMARY KEY,candidate_id uuid,research_episode_id uuid,agent_hunt_run_id uuid,
 device_agent_run_id uuid,hunt_run_id uuid,source_kind text,title text,claim text,claimed_severity text,
 evidence_refs jsonb,verifier_contract_id text,observation_context jsonb,created_by text,
 created_at timestamptz DEFAULT NOW());
"""


@asynccontextmanager
async def postgres_store():
    import asyncpg
    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}, "Use a disposable local database"
    schema = "hunt_integrity_" + uuid.uuid4().hex
    admin = await asyncpg.connect(DSN)
    pool = None
    try:
        await admin.execute(f'CREATE SCHEMA "{schema}"')
        await admin.execute(f'SET search_path TO "{schema}"')
        await admin.execute(DDL)
        pool = await asyncpg.create_pool(DSN, min_size=1, max_size=10,
            server_settings={"search_path": schema, "application_name": schema})
        hunt, target = uuid.uuid4(), uuid.uuid4()
        await admin.execute("INSERT INTO hunt_runs VALUES($1,$2,NULL,'web','active','{}'::jsonb)", hunt, target)
        core = {"schema_version": "hunt-authorization/v1", "hunt_id": str(hunt), "target_id": str(target)}
        proposal_digest = digest(core)
        proposal = uuid.uuid5(hunt, "authorization:" + proposal_digest)
        repo = PostgresAuthorizationRepository()
        await repo.insert_node(admin, {"id": hunt, "target_id": target}, proposal, PROPOSAL_TYPE,
            f"authz:{proposal}", {**core, "proposal_id": str(proposal), "proposal_digest": proposal_digest})
        state = {"proposal_id": str(proposal), "proposal_digest": proposal_digest,
            "baseline_kind": "own_object", "expected_access": "denied",
            "authorization_assessment": "potential_violation", "cross_access_observed": True,
            "selected_request_examined": True, "route": "/records/<owner-object>",
            "attempts": [{"attempt": 1, "action_id": str(uuid.uuid4()), "receipt_id": str(uuid.uuid4()),
                "cross_access_observed": True, "authorization_assessment": "potential_violation",
                "certainty": "observed", "proof_state": "inconclusive"}]}
        yield admin, SimpleNamespace(pool=pool, repo=repo), str(hunt), state, schema
    finally:
        if pool is not None:
            await asyncio.wait_for(pool.close(), 15)
        await admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await admin.close()


def test_concurrent_real_postgres_materialization_waits_for_proposal_lock():
    async def exercise():
        async with postgres_store() as (admin, service, hunt, state, application):
            transaction = admin.transaction()
            await transaction.start()
            await admin.fetchrow("SELECT id FROM application_graph_nodes WHERE id=$1 FOR UPDATE", uuid.UUID(state["proposal_id"]))
            tasks = [asyncio.create_task(ensure_authorization_candidate(service, hunt, state)) for _ in range(8)]
            try:
                waiting = 0
                for _ in range(100):
                    await admin.execute("SELECT pg_stat_clear_snapshot()")
                    waiting = await admin.fetchval(
                        "SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 "
                        "AND wait_event_type='Lock' AND query LIKE '%application_graph_nodes%' "
                        "AND query LIKE '%FOR UPDATE%'", application)
                    if waiting or all(task.done() for task in tasks):
                        break
                    await asyncio.sleep(0.02)
                assert waiting > 0, "materialization did not lock the existing proposal"
                assert await admin.fetchval("SELECT count(*) FROM investigation_candidate_observations") == 0
            finally:
                await transaction.rollback()
                results = await asyncio.wait_for(asyncio.gather(*tasks), 15)
            assert len({result["candidate"]["id"] for result in results}) == 1
            assert await admin.fetchval("SELECT count(*) FROM investigation_candidates") == 1
            assert await admin.fetchval("SELECT count(*) FROM investigation_candidate_observations") == 1
            assert await admin.fetchval("SELECT count(*) FROM application_graph_nodes WHERE node_type=$1", LINK_TYPE) == 1
    asyncio.run(exercise())


def test_link_failure_rolls_back_candidate_and_observation_then_retry_recovers():
    class FailingRepository(PostgresAuthorizationRepository):
        async def insert_node(self, conn, run, node_id, kind, key, attributes):
            if kind == LINK_TYPE:
                raise RuntimeError("fixture link failure")
            return await super().insert_node(conn, run, node_id, kind, key, attributes)

    async def exercise():
        async with postgres_store() as (admin, service, hunt, state, _):
            service.repo = FailingRepository()
            with pytest.raises(RuntimeError, match="fixture link failure"):
                await ensure_authorization_candidate(service, hunt, state)
            assert await admin.fetchval("SELECT count(*) FROM investigation_candidates") == 0
            assert await admin.fetchval("SELECT count(*) FROM investigation_candidate_observations") == 0
            service.repo = PostgresAuthorizationRepository()
            result = await ensure_authorization_candidate(service, hunt, state)
            assert result["candidate"]["authoritative"] is False
            assert await admin.fetchval("SELECT count(*) FROM investigation_candidate_observations") == 1
    asyncio.run(exercise())
