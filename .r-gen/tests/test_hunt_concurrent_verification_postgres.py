"""D40 on real PostgreSQL: two Hunts verifying one candidate at the same moment both keep it.

Live (plan-hunt-opencode-acceptance-673, A8): Hunt X won ``/phpinfo.php``; Hunts Y and Z2,
verifying the same shared candidate at the same moment, got 409 "Finding verification is already
in progress", the refusal was stored as their ``candidate.verify`` action and replayed for good,
and neither Hunt ever listed the finding.

These tests run the production verifier entry (``_verify_suspected_finding_workflow``) and its
finding-scoped advisory lock (``_agent_finding_verification_lock``), taken from api.py unchanged,
on a database built from db/init.sql plus the startup migration, and drive two Hunts through
``_execute_hunt_candidate_verification`` concurrently. Only the proof itself is a labelled double:
it holds the lock as a real proof does and reports the finding the proof re-proved.
"""
from __future__ import annotations

import ast
import asyncio
from contextlib import asynccontextmanager
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
import uuid

import pytest
from fastapi import HTTPException

from api.hunt import concurrent_verification
from api.hunt import interaction_router as router
from api.hunt.run_service import HuntRunService
from api.hunt.verification_refusal import VerificationRefused

DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")
ROOT = Path(__file__).resolve().parents[1]


async def _database():
    import asyncpg

    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
    admin = await asyncpg.connect(DSN)
    name = "hunt_concurrent_verify_" + uuid.uuid4().hex
    await admin.execute(f'CREATE DATABASE "{name}"')
    conn = await asyncpg.connect(DSN, database=name)
    await conn.execute((ROOT / "db/init.sql").read_text())
    await conn.close()
    pool = await asyncpg.create_pool(DSN, database=name, min_size=3, max_size=8)
    from retest_contract import run_schema_migrations  # the installed startup migration

    await run_schema_migrations(pool)

    async def drop():
        await pool.close()
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await admin.close()

    return pool, drop


async def _seed(pool, hunts: int):
    """One target, one verified finding, one shared web candidate, and N Hunts on the target."""
    async with pool.acquire() as conn:
        target = await conn.fetchval(
            "INSERT INTO targets(url) VALUES($1) RETURNING id", f"https://{uuid.uuid4().hex}.test")
        finding = await conn.fetchval(
            """INSERT INTO findings(target_id,fingerprint,title,severity,status,source,
                   last_verification_verdict,last_verified_at,verification_count)
               VALUES($1,$2,'phpinfo() exposes the PHP configuration','medium','active',
                      'autonomous','exploited',NOW(),1) RETURNING id""",
            target, uuid.uuid4().hex)
        candidate = await conn.fetchval(
            """INSERT INTO investigation_candidates(plane,target_id,family,title,claim,fingerprint)
               VALUES('web',$1,'data_exposure','/phpinfo.php discloses configuration',
                      'GET /phpinfo.php answers phpinfo()',$2) RETURNING id""",
            target, uuid.uuid4().hex)
        runs = []
        for _ in range(hunts):
            hunt = await conn.fetchval(
                """INSERT INTO hunt_runs(target_kind,target_id,status,objective)
                   VALUES('web',$1,'active','D40 acceptance') RETURNING id""", target)
            action = await conn.fetchval(
                """INSERT INTO hunt_actions(hunt_run_id,capability_name,status)
                   VALUES($1,'candidate.verify','running') RETURNING id""", hunt)
            runs.append(({"id": hunt, "target_id": target, "device_target_id": None}, action))
    return finding, candidate, runs


class Proofs:
    """The production verifier entry and lock from api.py; a labelled double for the proof."""

    def __init__(self, pool, finding) -> None:
        source = ROOT / "api/api.py"
        tree = ast.parse(source.read_text(), filename=str(source))
        wanted = {"_agent_finding_verification_lock", "_verify_suspected_finding_workflow"}
        nodes = [node for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in wanted]
        assert {node.name for node in nodes} == wanted
        self.namespace: dict[str, Any] = {
            "asynccontextmanager": asynccontextmanager, "HTTPException": HTTPException,
            "uuid": uuid, "Any": Any, "db_pool": pool,
            "_verify_web_candidate_workflow_unlocked": self.proof,
            "_verify_suspected_finding_workflow_unlocked": self.not_a_candidate,
        }
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(source), "exec"),
             self.namespace)
        self.finding = finding
        self.active = 0
        self.most_at_once = 0
        self.ran: list[str] = []
        self.refused = 0
        self.first_in_proof = asyncio.Event()
        self.release_first = asyncio.Event()
        lock = self.namespace["_agent_finding_verification_lock"]

        @asynccontextmanager
        async def counted_lock(finding_uuid):
            try:
                async with lock(finding_uuid):
                    yield
            except HTTPException as exc:
                if exc.status_code == 409:
                    self.refused += 1
                raise

        self.namespace["_agent_finding_verification_lock"] = counted_lock

    async def proof(self, candidate_uuid, approval, *, created_by, autonomous):
        """Labelled double: the deterministic proof, run while the verifier holds the lock."""
        self.active += 1
        self.most_at_once = max(self.most_at_once, self.active)
        try:
            self.ran.append(created_by)
            if len(self.ran) == 1:
                self.first_in_proof.set()
                await self.release_first.wait()
            return {"candidate_id": str(candidate_uuid), "verified": True,
                    "verified_finding_id": str(self.finding)}
        finally:
            self.active -= 1

    async def not_a_candidate(self, *_args, **_kwargs):
        raise AssertionError("the seeded id is a web candidate")


async def _verify(run, action, candidate):
    return await router._execute_hunt_candidate_verification(
        run=run, context={}, policy={"approval_receipt_id": "approval"},
        candidate_uuid=candidate, action_id=action,
    )


async def _finding_ids(pool, run) -> list[str]:
    record = await HuntRunService(lambda: pool).get(str(run["id"]))
    return record["outcome_summary"]["finding_ids"]


async def _until(predicate, seconds=10.0):
    deadline = asyncio.get_running_loop().time() + seconds
    while not predicate():
        assert asyncio.get_running_loop().time() < deadline
        await asyncio.sleep(0.02)


async def _settle(proofs) -> None:
    """On any outcome, let a held proof finish so its connection returns before the drop."""
    if proofs is not None:
        proofs.release_first.set()
    tasks = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
    if tasks:
        await asyncio.wait(tasks, timeout=10)


def _install(monkeypatch, pool, proofs, *, wait_seconds):
    monkeypatch.setattr(router, "_verify_suspected_finding_workflow",
                        proofs.namespace["_verify_suspected_finding_workflow"])
    monkeypatch.setattr(router, "_pool", lambda: pool)
    monkeypatch.setattr(concurrent_verification, "CONCURRENT_VERIFICATION_WAIT_SECONDS", wait_seconds)
    monkeypatch.setattr(concurrent_verification, "POLL_SECONDS", 0.05)


def test_the_second_of_two_concurrent_verifiers_waits_and_both_hunts_list_the_finding(monkeypatch):
    async def scenario():
        pool, drop = await _database()
        proofs = None
        try:
            finding, candidate, [(x, x_action), (y, y_action)] = await _seed(pool, 2)
            proofs = Proofs(pool, finding)
            _install(monkeypatch, pool, proofs, wait_seconds=30)
            first = asyncio.create_task(_verify(x, x_action, candidate))
            await proofs.first_in_proof.wait()
            # Y really arrives while X's proof holds the finding's lock.
            second = asyncio.create_task(_verify(y, y_action, candidate))
            await _until(lambda: proofs.refused >= 2 or second.done())
            assert not second.done(), "the second verifier waits instead of being refused"
            proofs.release_first.set()
            results = await asyncio.gather(first, second)
            assert [result["hunt_attribution"]["role"] for result in results] == ["owner", "additional"]
            assert results[1]["hunt_attribution"]["owner_hunt_id"] == str(x["id"])
            assert proofs.most_at_once == 1, "the two proofs never ran at once"
            assert len(proofs.ran) == 2, "the second Hunt ran its own proof once the first finished"
            async with pool.acquire() as conn:
                stored = await conn.fetch(
                    "SELECT hunt_run_id, action_id, role FROM finding_hunt_verifications WHERE finding_id=$1",
                    finding)
            assert {(r["hunt_run_id"], r["action_id"], r["role"]) for r in stored} == {
                (x["id"], x_action, "owner"), (y["id"], y_action, "additional")}
            assert await _finding_ids(pool, x) == [str(finding)]
            assert await _finding_ids(pool, y) == [str(finding)]
        finally:
            await _settle(proofs)
            await drop()

    asyncio.run(scenario())


def test_a_verifier_still_busy_past_the_bound_leaves_a_retryable_refusal(monkeypatch):
    async def scenario():
        pool, drop = await _database()
        proofs = None
        try:
            finding, candidate, [(x, x_action), (y, y_action)] = await _seed(pool, 2)
            proofs = Proofs(pool, finding)
            _install(monkeypatch, pool, proofs, wait_seconds=0.4)
            first = asyncio.create_task(_verify(x, x_action, candidate))
            await proofs.first_in_proof.wait()
            with pytest.raises(VerificationRefused) as refused:
                await _verify(y, y_action, candidate)
            assert refused.value.status_code == 409
            assert refused.value.detail["reason_code"] == "verification_in_progress"
            assert "attempt=2" in refused.value.detail["message"]
            assert len(proofs.ran) == 1 and proofs.refused >= 2, "it waited, and sent nothing"
            proofs.release_first.set()
            await first
            # The next attempt is a fresh action: it verifies and the Hunt lists the finding.
            async with pool.acquire() as conn:
                retry_action = await conn.fetchval(
                    """INSERT INTO hunt_actions(hunt_run_id,capability_name,status)
                       VALUES($1,'candidate.verify','running') RETURNING id""", y["id"])
            again = await _verify(y, retry_action, candidate)
            assert again["hunt_attribution"]["role"] == "additional"
            assert await _finding_ids(pool, y) == [str(finding)]
        finally:
            await _settle(proofs)
            await drop()

    asyncio.run(scenario())


def test_a_hunt_cancelled_during_the_wait_starts_no_proof(monkeypatch):
    """The wait used to poll for up to 90 s without reading the Hunt: a Hunt cancelled meanwhile
    still started its proof once the other verifier let go of the finding."""
    async def scenario():
        pool, drop = await _database()
        proofs = None
        try:
            finding, candidate, [(x, x_action), (y, y_action)] = await _seed(pool, 2)
            proofs = Proofs(pool, finding)
            _install(monkeypatch, pool, proofs, wait_seconds=30)
            first = asyncio.create_task(_verify(x, x_action, candidate))
            await proofs.first_in_proof.wait()
            second = asyncio.create_task(_verify(y, y_action, candidate))
            await _until(lambda: proofs.refused >= 1 or second.done())
            assert not second.done(), "the second verifier is waiting"
            async with pool.acquire() as conn:
                await conn.execute("UPDATE hunt_runs SET status='cancelled' WHERE id=$1", y["id"])
            proofs.release_first.set()  # the finding is free: only the cancellation stops Y now
            await first
            with pytest.raises(VerificationRefused) as refused:
                await second
            assert refused.value.status_code == 409 and refused.value.detail == "Hunt is cancelled"
            assert proofs.ran == [f"hunt_v2:{x['id']}"], "the cancelled Hunt sent no proof traffic"
            async with pool.acquire() as conn:
                assert await conn.fetchval(
                    "SELECT count(*) FROM finding_hunt_verifications WHERE hunt_run_id=$1", y["id"]) == 0
        finally:
            await _settle(proofs)
            await drop()

    asyncio.run(scenario())
