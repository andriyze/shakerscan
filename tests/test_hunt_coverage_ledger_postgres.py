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
        queued, quiet = uuid4(), uuid4()
        await conn.execute("INSERT INTO targets VALUES($1)", target)
        await conn.executemany(
            "INSERT INTO hunt_runs(id,target_kind,target_id,objective,budget_json,budget_used_json) "
            "VALUES($1,'web',$2,'Coverage acceptance','{\"max_http_requests\":20}','{\"http_requests\":2}')",
            [(hunt, target), (other_hunt, target)],
        )
        ran = json.dumps({"budget_accounting": {"actual": {"http_requests": 1}}})
        handoff = json.dumps({"ok": True, "status": "queued", "scan_id": str(uuid4()),
                              "budget_consumed": {"tcp_ports_attempted": 100}})
        await conn.executemany(
            "INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,result_summary) "
            "VALUES($1,$2,'http.request',$3,$4::jsonb)",
            [(completed, hunt, "completed", ran), (partial, hunt, "partial", ran),
             (foreign, other_hunt, "completed", ran), (queued, hunt, "completed", handoff),
             (quiet, hunt, "completed", "{}")],
        )
        pool = await asyncpg.create_pool(DSN, min_size=1, max_size=2, server_settings={"search_path": schema})
        service = HuntRunService(lambda: pool)
        angle = {"family": "authorization", "locus": {"method": "GET", "route": "/records/{id}"},
                 "mechanism": "cross-principal read", "status": "planned"}
        await service.record_coverage_angle(str(hunt), values=angle)
        for action, code in [(foreign, "coverage_evidence_not_owned"),
                             (partial, "coverage_negative_requires_completed_actions"),
                             (queued, "coverage_evidence_queued_handoff"),
                             (quiet, "coverage_negative_requires_executed_actions")]:
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
        unbound = {**candidate_angle, "status": "planned", "evidence_action_ids": [], "candidate_id": None}
        with pytest.raises(CoverageLedgerError) as exc:
            await service.record_coverage_angle(str(hunt), values=unbound)
        assert exc.value.code == "coverage_candidate_binding_superseded"
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
        # Resumable budget exhaustion: evidence-bound settlement is accepted, planning is not.
        await conn.execute("UPDATE hunt_runs SET status='budget_exhausted' WHERE id=$1", hunt)
        settled = {**angle, "locus": {"route": "/unexamined/0"}, "status": "negative",
                   "evidence_action_ids": [str(completed)]}
        await restarted.record_coverage_angle(str(hunt), values=settled)
        with pytest.raises(CoverageLedgerError) as exc:
            await restarted.record_coverage_angle(str(hunt), values=angle)
        assert exc.value.code == "coverage_budget_exhausted_requires_evidence"
        for update in ("UPDATE hunt_runs SET completed_at=NOW() WHERE id=$1",
                       "UPDATE hunt_runs SET status='cancelled' WHERE id=$1",
                       "UPDATE hunt_runs SET status='completed' WHERE id=$1"):
            await conn.execute(update, hunt)
            with pytest.raises(HTTPException) as exc:
                await restarted.record_coverage_angle(str(hunt), values=settled)
            assert exc.value.status_code == 409
    finally:
        if pool is not None:
            await pool.close()
        await conn.execute(f'DROP SCHEMA "{schema}" CASCADE')
        await conn.close()


# The table exactly as the first ledger release (ba329985) created it, before event_seq,
# with an auto-named status check and timestamp-ordered indexes.
FIRST_RELEASE_LEDGER_DDL = """
CREATE TABLE hunt_coverage_angle_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_run_id UUID NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    family TEXT NOT NULL,
    locus_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    mechanism TEXT NOT NULL DEFAULT '',
    principal_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    hypothesis TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (
        status IN ('planned','testing','negative','partial','blocked','candidate')
    ),
    evidence_action_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    contradictory_evidence_action_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    candidate_id UUID,
    blocker TEXT,
    proof_gap TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_hunt_coverage_angle_events_run
ON hunt_coverage_angle_events(hunt_run_id, created_at DESC, id DESC);
CREATE INDEX idx_hunt_coverage_angle_events_fingerprint
ON hunt_coverage_angle_events(hunt_run_id, fingerprint, created_at DESC, id DESC);
"""


async def _ledger_catalog(conn, schema):
    columns = [tuple(row) for row in await conn.fetch(
        """SELECT column_name, data_type, is_nullable,
                  replace(COALESCE(column_default, ''), $1 || '.', '')
           FROM information_schema.columns
           WHERE table_schema=$1 AND table_name='hunt_coverage_angle_events'
           ORDER BY ordinal_position""", schema)]
    constraints = sorted(tuple(row) for row in await conn.fetch(
        """SELECT conname, replace(pg_get_constraintdef(oid), $1 || '.', '')
           FROM pg_constraint
           WHERE conrelid=($1 || '.hunt_coverage_angle_events')::regclass""", schema))
    indexes = sorted(tuple(row) for row in await conn.fetch(
        """SELECT indexname, replace(indexdef, $1 || '.', '')
           FROM pg_indexes WHERE schemaname=$1 AND tablename='hunt_coverage_angle_events'""",
        schema))
    return columns, constraints, indexes


@pytest.mark.asyncio
async def test_converted_ledger_matches_fresh_schema_and_orders_by_sequence():
    import asyncpg
    from api.hunt.coverage_ledger import list_coverage_angles

    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
    ddl = (Path(__file__).resolve().parents[1] / "db/init.sql").read_text()
    conn = await asyncpg.connect(DSN)
    schemas = {name: f"hunt_coverage_{name}_" + uuid4().hex for name in ("fresh", "converted")}
    try:
        for name, schema in schemas.items():
            await conn.execute(f'CREATE SCHEMA "{schema}"; SET search_path TO "{schema}"')
            await conn.execute("CREATE TABLE targets(id UUID PRIMARY KEY); "
                               "CREATE TABLE device_targets(id UUID PRIMARY KEY); "
                               "CREATE TABLE investigation_candidates(id UUID PRIMARY KEY, status TEXT)")
            for table in ("hunt_runs", "hunt_actions"):
                await conn.execute(re.search(rf"CREATE TABLE {table} \(.*?\n\);", ddl, re.S)[0])
            if name == "fresh":
                block = ddl[ddl.index("CREATE TABLE hunt_coverage_angle_events"):]
                await conn.execute(block[:block.index("-- ====")])
            else:
                await conn.execute(FIRST_RELEASE_LEDGER_DDL)
        target, hunt = uuid4(), uuid4()
        await conn.execute(f'SET search_path TO "{schemas["converted"]}"')
        await conn.execute("INSERT INTO targets VALUES($1)", target)
        await conn.execute("INSERT INTO hunt_runs(id,target_kind,target_id) VALUES($1,'web',$2)", hunt, target)
        # Pre-upgrade rows inserted out of time order; the upgrade numbers them by created_at.
        for minute, fingerprint in ((2, "second"), (1, "first"), (3, "third")):
            await conn.execute(
                "INSERT INTO hunt_coverage_angle_events(hunt_run_id,fingerprint,family,status,created_at) "
                "VALUES($1,$2,'authorization','planned', TIMESTAMPTZ '2026-10-01' + make_interval(mins => $3))",
                hunt, fingerprint, minute)
        for _ in range(2):  # restart twice: idempotent on both populations
            for schema in schemas.values():
                await conn.execute(f'SET search_path TO "{schema}"')
                for statement in COVERAGE_LEDGER_SCHEMA_STATEMENTS:
                    await conn.execute(statement)

        fresh = await _ledger_catalog(conn, schemas["fresh"])
        converted = await _ledger_catalog(conn, schemas["converted"])
        assert fresh == converted
        assert ("hunt_coverage_angle_status_check",) == tuple(name for name, _ in fresh[1] if "check" in name)
        assert [name for name, _ in fresh[2]] == [
            "hunt_coverage_angle_events_pkey",
            "idx_hunt_coverage_angle_events_fingerprint_seq",
            "idx_hunt_coverage_angle_events_run_seq",
        ]
        await conn.execute(f'SET search_path TO "{schemas["converted"]}"')
        rows = await conn.fetch("SELECT fingerprint, event_seq FROM hunt_coverage_angle_events ORDER BY event_seq")
        assert [(row["fingerprint"], row["event_seq"]) for row in rows] == [("first", 1), ("second", 2), ("third", 3)]
        assert await conn.fetchval(
            "INSERT INTO hunt_coverage_angle_events(hunt_run_id,fingerprint,family,status) "
            "VALUES($1,'fourth','authorization','planned') RETURNING event_seq", hunt) == 4

        # Two events for one angle in one transaction share NOW(). The later insert must win
        # even when its random id sorts first, which the timestamp/id order got wrong.
        await conn.execute(f'SET search_path TO "{schemas["fresh"]}"')
        await conn.execute("INSERT INTO targets VALUES($1)", target)
        await conn.execute("INSERT INTO hunt_runs(id,target_kind,target_id) VALUES($1,'web',$2)", hunt, target)
        async with conn.transaction():
            for event_id, status in (("ffffffff-ffff-4fff-8fff-ffffffffffff", "planned"),
                                     ("00000000-0000-4000-8000-000000000000", "testing")):
                await conn.execute(
                    "INSERT INTO hunt_coverage_angle_events(id,hunt_run_id,fingerprint,family,status) "
                    "VALUES($1,$2,'same-angle','authorization',$3)", event_id, hunt, status)
        current = await list_coverage_angles(conn, hunt_run_id=str(hunt))
        assert [(angle["status"], angle["sequence"]) for angle in current["angles"]] == [("testing", 2)]
    finally:
        for schema in schemas.values():
            await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await conn.close()
