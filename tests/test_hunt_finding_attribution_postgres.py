"""D21 in real PostgreSQL: the first verifying Hunt keeps a finding; later Hunts are recorded.

Live (plan-hunt-main732, D21): luna's Hunt verified two findings, GLM's concurrent Hunt verified
them again six minutes later and took them over, so luna's Hunt ended with finding_ids [] while
its debrief said verified. These tests drive the production attribution path
(``_execute_hunt_candidate_verification``) and the production Hunt read (``HuntRunService.get``)
against a disposable database built from db/init.sql. Only the web verifier is a labelled double:
it reports the finding the proof materialized, exactly as the real verifier result does.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from urllib.parse import urlsplit
import uuid

import pytest

from api.hunt import interaction_router as router
from api.hunt.run_service import HuntRunService

DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")
ROOT = Path(__file__).resolve().parents[1]


async def _database():
    import asyncpg

    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
    admin = await asyncpg.connect(DSN)
    name = "hunt_attribution_" + uuid.uuid4().hex
    await admin.execute(f'CREATE DATABASE "{name}"')
    conn = await asyncpg.connect(DSN, database=name)
    await conn.execute((ROOT / "db/init.sql").read_text())
    await conn.close()
    pool = await asyncpg.create_pool(DSN, database=name, min_size=3, max_size=6)
    from retest_contract import run_schema_migrations  # the installed startup migration

    await run_schema_migrations(pool)

    async def drop():
        await pool.close()
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await admin.close()

    return pool, drop


async def _seed(pool, hunts: int):
    async with pool.acquire() as conn:
        target = await conn.fetchval(
            "INSERT INTO targets(url) VALUES($1) RETURNING id", f"https://{uuid.uuid4().hex}.test")
        finding = await conn.fetchval(
            """INSERT INTO findings(target_id,fingerprint,title,severity,status,source,
                   last_verification_verdict,last_verified_at,verification_count)
               VALUES($1,$2,'Anonymous /actuator/env discloses configuration','high','active',
                      'autonomous','exploited',NOW(),1) RETURNING id""",
            target, uuid.uuid4().hex)
        runs = []
        for _ in range(hunts):
            hunt = await conn.fetchval(
                """INSERT INTO hunt_runs(target_kind,target_id,status,objective)
                   VALUES('web',$1,'active','D21 acceptance') RETURNING id""", target)
            action = await conn.fetchval(
                """INSERT INTO hunt_actions(hunt_run_id,capability_name,status)
                   VALUES($1,'candidate.verify','running') RETURNING id""", hunt)
            runs.append(({"id": hunt, "target_id": target, "device_target_id": None}, action))
    return finding, runs


def _install(monkeypatch, pool, finding):
    async def verifier(candidate_uuid, approval, *, created_by, autonomous):
        # Labelled double for the web verifier: its proof materialized ``finding``.
        return {"candidate_id": str(candidate_uuid), "verified": True,
                "verified_finding_id": str(finding)}

    monkeypatch.setattr(router, "_verify_suspected_finding_workflow", verifier)
    monkeypatch.setattr(router, "_pool", lambda: pool)


async def _verify(run, action):
    return await router._execute_hunt_candidate_verification(
        run=run, context={}, policy={"approval_receipt_id": "approval"},
        candidate_uuid=uuid.uuid4(), action_id=action,
    )


async def _finding_ids(pool, run) -> list[str]:
    record = await HuntRunService(lambda: pool).get(str(run["id"]))
    return record["outcome_summary"]["finding_ids"]


def test_a_later_hunt_re_verifying_a_finding_does_not_take_it_over(monkeypatch):
    async def scenario():
        pool, drop = await _database()
        try:
            finding, [(first, first_action), (second, second_action)] = await _seed(pool, 2)
            _install(monkeypatch, pool, finding)
            assert (await _verify(first, first_action))["hunt_attribution"]["role"] == "owner"
            later = await _verify(second, second_action)
            assert later["hunt_attributed"] is True
            assert later["hunt_attribution"]["role"] == "additional"
            assert later["hunt_attribution"]["owner_hunt_id"] == str(first["id"])
            async with pool.acquire() as conn:
                assert await conn.fetchval(
                    "SELECT hunt_run_id FROM findings WHERE id=$1", finding) == first["id"]
                rows = await conn.fetch(
                    """SELECT hunt_run_id, action_id, role, verified_at
                       FROM finding_hunt_verifications WHERE finding_id=$1
                       ORDER BY verified_at, id""", finding)
            assert [(r["hunt_run_id"], r["action_id"], r["role"]) for r in rows] == [
                (first["id"], first_action, "owner"), (second["id"], second_action, "additional")]
            assert all(r["verified_at"] is not None for r in rows)
            # Both Hunts' outcomes keep the verified finding their debriefs report.
            assert await _finding_ids(pool, first) == [str(finding)]
            assert await _finding_ids(pool, second) == [str(finding)]
            # A replay of the same verification action records nothing new.
            await _verify(second, second_action)
            async with pool.acquire() as conn:
                assert await conn.fetchval(
                    "SELECT count(*) FROM finding_hunt_verifications WHERE finding_id=$1", finding) == 2
        finally:
            await drop()

    asyncio.run(scenario())


def test_concurrent_hunts_verifying_one_finding_get_exactly_one_owner(monkeypatch):
    async def scenario():
        pool, drop = await _database()
        try:
            finding, runs = await _seed(pool, 2)
            _install(monkeypatch, pool, finding)
            async with pool.acquire() as blocker:
                # Hold the finding row so both attributions are waiting on it at once.
                transaction = blocker.transaction()
                await transaction.start()
                await blocker.execute("SELECT 1 FROM findings WHERE id=$1 FOR UPDATE", finding)
                tasks = [asyncio.create_task(_verify(run, action)) for run, action in runs]
                for _ in range(200):
                    waiting = await blocker.fetchval(
                        "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' "
                        "AND datname=current_database()")
                    if waiting == 2:
                        break
                    await asyncio.sleep(0.02)
                assert waiting == 2
                await transaction.commit()
                results = await asyncio.gather(*tasks)
            roles = sorted(result["hunt_attribution"]["role"] for result in results)
            assert roles == ["additional", "owner"]
            owner = next(run for (run, _), result in zip(runs, results)
                         if result["hunt_attribution"]["role"] == "owner")
            async with pool.acquire() as conn:
                assert await conn.fetchval(
                    "SELECT hunt_run_id FROM findings WHERE id=$1", finding) == owner["id"]
                stored = await conn.fetch(
                    "SELECT hunt_run_id, role FROM finding_hunt_verifications WHERE finding_id=$1",
                    finding)
            assert {(r["hunt_run_id"], r["role"]) for r in stored} == {
                (run["id"], "owner" if run is owner else "additional") for run, _ in runs}
            for run, _ in runs:
                assert await _finding_ids(pool, run) == [str(finding)]
        finally:
            await drop()

    asyncio.run(scenario())
