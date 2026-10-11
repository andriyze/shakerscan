"""Finding retests re-check their authorization while they run (PostgreSQL).

A retest is admitted by the real findings routes (``POST /findings/{id}/retest`` and the bulk
route), by the worker's automatic retests after a Scan, or recovered by the worker's requeues;
each records what it was admitted with (``finding_verifications.admitted_authority``). It then
runs through the worker's own ``process_finding_retest_job`` over the installed schema, watched by
``running_retest_authority`` (the device and AI run machinery). Only the provers are fixtures:
they hold a ``sleep`` process open, as a slow replay holds its connection, and ignore every stop
check, as the real provers have none; no target is contacted. Redis is a fixture.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
import dataclasses
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import time
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

from tests.test_scan_local_revocation_postgres import StallingPool, scan_database  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]
import target_authorization  # noqa: E402
import worker  # noqa: E402
from finding_routes import router as findings  # noqa: E402
from scan import running_scan_authority as running  # noqa: E402
from scan.retest_authority import retest_authority_stop  # noqa: E402
from retest_routes.router import public_retest_row  # noqa: E402
from scanner_tools import proof_of_exploit  # noqa: E402

URL = "http://retest.fixture.test"


class FakeRedis:
    def __init__(self):
        self.hashes: dict[str, dict[str, str]] = {}
        self.queued: list[tuple[str, dict]] = []

    def ping(self):
        return True

    def hset(self, key, field=None, value=None, mapping=None):
        self.hashes.setdefault(key, {}).update(mapping or {field: value})

    def expire(self, *_args):
        return True

    def get(self, *_args):
        return None

    def set(self, *_args, **_kwargs):
        return True

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))


class FixtureProver:
    """A replay that holds a ``sleep`` process open and never checks a stop, like the provers."""

    def __init__(self, *, seconds=30.0, proven=False):
        self.seconds, self.proven = seconds, proven
        self.calls = 0
        self.ended_at: float | None = None
        self.returncode: int | None = None

    async def __call__(self, *_args, **_kwargs):
        self.calls += 1
        process = await asyncio.create_subprocess_exec("sleep", str(self.seconds))
        try:
            await process.wait()
            return proof_of_exploit.ExploitProof(proven=self.proven, confidence=0.95 if self.proven else 0.0,
                                                 evidence_type="dom_execution", technique="fixture")
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
            self.ended_at = time.monotonic()
            self.returncode = process.returncode


@pytest.fixture(autouse=True)
def _fixtures(monkeypatch):
    redis = FakeRedis()
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "_try_acquire_retest_slot", lambda _r: True)
    monkeypatch.setattr(worker, "_release_retest_slot", lambda _r: None)
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", lambda: {})  # no AI tier
    monkeypatch.setattr(worker, "record_operational_event", lambda *_a, **_k: None)
    for name in ("start_scan_session", "end_scan_session"):
        monkeypatch.setattr(proof_of_exploit, name, lambda *_a, **_k: None)
    return redis


def _use_prover(monkeypatch, prover):
    for name in ("prove_xss", "prove_xss_headless"):
        monkeypatch.setattr(proof_of_exploit, name, prover)


def _timing(monkeypatch, *, pool=None, **timing):
    """The real ``running_retest_authority`` with test timing (and, optionally, a guard pool)."""
    real = running.running_retest_authority

    async def watched(db_pool, **kwargs):
        return await real(pool or db_pool, **{**timing, **kwargs})
    monkeypatch.setattr(worker, "running_retest_authority", watched)


async def _web_target(pool, *, authorize=True, url=URL):
    async with pool.acquire() as conn:
        target_id = await conn.fetchval("INSERT INTO targets(name, url) VALUES('retest fixture', $1) RETURNING id",
                                        url)
        standing = None
        if authorize:
            standing = await target_authorization.authorize_target(conn, target_id, approved_by="fixture-owner")
        finding_id = await conn.fetchval(
            """INSERT INTO findings (target_id, fingerprint, title, severity, tool, url, evidence)
               VALUES ($1, $2, 'Reflected XSS', 'high', 'dalfox', $3, $4::jsonb) RETURNING id""",
            target_id, uuid.uuid4().hex, f"{url}/search?q=1",
            json.dumps({"type": "xss", "param": "q", "url": f"{url}/search?q=1"}))
    return target_id, finding_id, standing


async def _approval(pool, target_id, *, expires="1 hour", host="retest.fixture.test"):
    """A per-request approval receipt for a retest, bounded by an expiry."""
    async with pool.acquire() as conn:
        scope_id = "scope-" + uuid.uuid4().hex
        await conn.execute(
            """INSERT INTO scope_receipts(id, target_id, verdict, allowed_hosts)
               VALUES($1, $2, 'allowed', $3::jsonb)""", scope_id, target_id, json.dumps([host]))
        return str(await conn.fetchval(
            f"""INSERT INTO approval_receipts(scope_receipt_id, risk_tier, confirmations, action_name,
                    approved_by, expires_at)
                VALUES($1, 'active', '["confirm_authorized"]', 'finding.retest', 'fixture-owner',
                       NOW() + INTERVAL '{expires}') RETURNING id""", scope_id))


def _configure_routes(pool, redis):
    """Bind the findings routes to the test database; the receipt validator is a fixture."""
    async def validate(_conn, approval_receipt_id, **_kwargs):
        return {"approval_receipt_id": approval_receipt_id} if approval_receipt_id else None

    async def record_command_result(_conn, **_kwargs):
        return {"id": str(uuid.uuid4())}

    async def nothing(*_a, **_k):
        return None

    previous = (findings._pool_provider, dict(findings._deps))
    findings.configure_findings_router(
        lambda: pool, get_redis=lambda: redis,
        enqueue_job=lambda _r, queue, payload: redis.queued.append((queue, dict(payload))),
        validate_approval_receipt=validate, require_approval_receipt=nothing,
        record_command_result=record_command_result, record_blocked_command_result=nothing,
        load_effective_ai_settings=lambda: {})
    return previous


def _restore_routes(previous):
    findings._pool_provider = previous[0]
    findings._deps.clear()
    findings._deps.update(previous[1])


async def _admit(pool, redis, finding_id, *, approval=None, mode="deterministic"):
    """``POST /findings/{id}/retest`` (the finding page's Retest button) to its queued job."""
    previous = _configure_routes(pool, redis)
    try:
        response = await findings.retest_finding(
            str(finding_id), findings.FindingRetestRequest(requested_by="ui", approval_receipt_id=approval),
            mode=mode)
    finally:
        _restore_routes(previous)
    return response, redis.queued[-1][1]


async def _verification(pool, retest_id):
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM finding_verifications WHERE id=$1", uuid.UUID(str(retest_id)))
        finding = await conn.fetchrow(
            """SELECT f.last_verification_status, f.last_verification_verdict
                 FROM findings f JOIN finding_verifications v ON v.finding_id=f.id WHERE v.id=$1""",
            uuid.UUID(str(retest_id)))
    return dict(row), dict(finding)


async def _revoke(pool, target_id):
    async with pool.acquire() as conn:
        return await target_authorization.revoke_target_authorization(
            conn, target_id, revoked_by="fixture-owner", reason="fixture revoke mid-retest")


def _stop(row):
    artifacts = row["artifacts"]
    return (json.loads(artifacts) if isinstance(artifacts, str) else artifacts)["authority_stop"]


def _assert_no_verdict(row, finding, *, reason_code, stop_reason="authorization_withdrawn"):
    assert row["status"] == "failed" and row["result_status"] == "error" and row["verdict"] == "error"
    assert row["retry_class"] == "authorization" and row["retryable"] is False
    assert row["proof"] is None and row["confidence"] is None
    stop = _stop(row)
    assert stop["stop_reason"] == stop_reason and stop["reason_code"] == reason_code
    # Never a fix, never still vulnerable: the finding records an attempt with no verdict.
    assert finding == {"last_verification_status": "error", "last_verification_verdict": "error"}
    public = public_retest_row(row)
    assert public["stop_reason"] == stop_reason and public["authority_stop"]["reason_code"] == reason_code
    assert "admitted_authority" not in public


def test_ui_retest_revoked_mid_run_stops_within_the_tolerance_and_records_no_verdict(
        template_database, monkeypatch, _fixtures):
    """Production timing: the 2 s poll, the 10 s tolerance and the 5 s stop grace."""
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            target_id, finding_id, standing = await _web_target(pool)
            prover = FixtureProver()
            _use_prover(monkeypatch, prover)
            response, job = await _admit(pool, _fixtures, finding_id)
            row, _ = await _verification(pool, response["retest_id"])
            admitted = json.loads(row["admitted_authority"])
            assert admitted["standing_receipt_id"] == str(standing["approval_receipt_id"])
            assert admitted["target_id"] == str(target_id) and admitted["approval_receipt_id"] is None
            marks = {}

            async def revoke_soon():
                while prover.calls == 0:
                    await asyncio.sleep(0.05)
                await asyncio.sleep(0.5)
                marks["revoked_at"] = time.monotonic()
                assert await _revoke(pool, target_id) == 1

            hook = asyncio.create_task(revoke_soon())
            await worker.process_finding_retest_job(job)
            await hook
            # Stopped within one poll plus the stop grace; the replay process was killed.
            assert prover.returncode is not None and prover.returncode < 0
            assert prover.ended_at - marks["revoked_at"] < 2.0 + running.HARD_STOP_GRACE_SECONDS + 1.0
            row, finding = await _verification(pool, response["retest_id"])
            _assert_no_verdict(row, finding, reason_code="authorization_revoked")
            assert _stop(row)["interrupted_actions"] == ["finding.retest"]
            assert "revoked" in row["verdict_reason"] and "No verdict" in row["verdict_reason"]
            assert _fixtures.hashes[f"retest_job:{job['job_id']}"]["stop_reason"] == "authorization_withdrawn"
    asyncio.run(run())


def test_a_retest_whose_authorization_is_revoked_while_queued_sends_no_traffic(
        template_database, monkeypatch, _fixtures):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            target_id, finding_id, _standing = await _web_target(pool)
            prover = FixtureProver(seconds=0.1)
            _use_prover(monkeypatch, prover)
            response, job = await _admit(pool, _fixtures, finding_id)
            await _revoke(pool, target_id)
            # Authorizing again does not revive it: the retest is bound to what admitted it.
            async with pool.acquire() as conn:
                await target_authorization.authorize_target(conn, target_id, approved_by="fixture-owner")
            await worker.process_finding_retest_job(job)
            assert prover.calls == 0
            row, finding = await _verification(pool, response["retest_id"])
            _assert_no_verdict(row, finding, reason_code="authorization_revoked")
            stop = _stop(row)
            assert stop["before_start"] is True and stop["not_run_actions"] == ["finding.retest"]
    asyncio.run(run())


def test_an_approval_that_expires_mid_retest_stops_it_as_expired(template_database, monkeypatch, _fixtures):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            target_id, finding_id, _ = await _web_target(pool, authorize=False)
            approval = await _approval(pool, target_id, expires="2 seconds")
            prover = FixtureProver()
            _use_prover(monkeypatch, prover)
            _timing(monkeypatch, poll_seconds=0.2, grace_seconds=0.5)
            response, job = await _admit(pool, _fixtures, finding_id, approval=approval)
            row, _ = await _verification(pool, response["retest_id"])
            assert json.loads(row["admitted_authority"])["approval_receipt_id"] == approval
            await worker.process_finding_retest_job(job)
            assert prover.calls == 1 and prover.returncode < 0
            row, finding = await _verification(pool, response["retest_id"])
            _assert_no_verdict(row, finding, reason_code="authorization_expired")
    asyncio.run(run())


def test_a_target_url_change_mid_retest_stops_it_as_no_longer_in_scope(template_database, monkeypatch, _fixtures):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            target_id, finding_id, _ = await _web_target(pool)
            prover = FixtureProver()
            _use_prover(monkeypatch, prover)
            _timing(monkeypatch, poll_seconds=0.2, grace_seconds=0.5)
            response, job = await _admit(pool, _fixtures, finding_id)

            async def move_target():
                while prover.calls == 0:
                    await asyncio.sleep(0.05)
                async with pool.acquire() as conn:
                    await conn.execute("UPDATE targets SET url='http://elsewhere.fixture.test' WHERE id=$1",
                                       target_id)
            hook = asyncio.create_task(move_target())
            await worker.process_finding_retest_job(job)
            await hook
            row, finding = await _verification(pool, response["retest_id"])
            _assert_no_verdict(row, finding, reason_code="scope_invalid")
    asyncio.run(run())


def test_an_unreachable_database_stops_a_retest_as_unverified_never_as_revoked(
        template_database, monkeypatch, _fixtures):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            _target_id, finding_id, _ = await _web_target(pool)
            prover = FixtureProver()
            _use_prover(monkeypatch, prover)
            stalling = StallingPool(pool)
            _timing(monkeypatch, pool=stalling, poll_seconds=0.2, unverified_after_seconds=1.0,
                    grace_seconds=0.5)
            response, job = await _admit(pool, _fixtures, finding_id)

            async def stall():
                while prover.calls == 0:
                    await asyncio.sleep(0.05)
                stalling.stalled = True
            hook = asyncio.create_task(stall())
            await worker.process_finding_retest_job(job)
            await hook
            stalling.stalled = False
            row, finding = await _verification(pool, response["retest_id"])
            _assert_no_verdict(row, finding, reason_code="authorization_unverified",
                               stop_reason="authorization_unverified")
            assert "could not be confirmed" in row["verdict_reason"]
    asyncio.run(run())


def test_a_retest_that_keeps_its_authorization_records_its_verdict(template_database, monkeypatch, _fixtures):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            _target_id, finding_id, _ = await _web_target(pool)
            prover = FixtureProver(seconds=0.6, proven=True)
            _use_prover(monkeypatch, prover)
            _timing(monkeypatch, poll_seconds=0.2)
            response, job = await _admit(pool, _fixtures, finding_id)
            await worker.process_finding_retest_job(job)
            row, finding = await _verification(pool, response["retest_id"])
            assert row["status"] == "completed" and row["verdict"] == "exploited"
            assert finding["last_verification_verdict"] == "exploited"
            assert public_retest_row(row)["stop_reason"] is None
    asyncio.run(run())


def test_bulk_retest_binds_each_retest_and_a_revoke_stops_it(template_database, monkeypatch, _fixtures):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            target_id, finding_id, standing = await _web_target(pool)
            approval = await _approval(pool, target_id)
            previous = _configure_routes(pool, _fixtures)
            try:
                response = await findings.bulk_retest_findings(findings.FindingsBulkRetestRequest(
                    finding_ids=[str(finding_id)], approval_receipt_id=approval, mode="deterministic"))
            finally:
                _restore_routes(previous)
            assert len(response["queued"]) == 1
            retest_id = response["queued"][0]["retest_id"]
            row, _ = await _verification(pool, retest_id)
            admitted = json.loads(row["admitted_authority"])
            assert admitted["standing_receipt_id"] == str(standing["approval_receipt_id"])
            assert admitted["approval_receipt_id"] == approval
            await _revoke(pool, target_id)
            prover = FixtureProver(seconds=0.1)
            _use_prover(monkeypatch, prover)
            await worker.process_finding_retest_job(_fixtures.queued[-1][1])
            assert prover.calls == 0
            row, finding = await _verification(pool, retest_id)
            _assert_no_verdict(row, finding, reason_code="authorization_revoked")
    asyncio.run(run())


def test_automatic_retests_after_a_scan_are_bound_and_stopped_by_a_revoke(
        template_database, monkeypatch, _fixtures):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            target_id, finding_id, standing = await _web_target(pool)
            approval = await _approval(pool, target_id)
            scan_id = uuid.uuid4()
            async with pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO scans (id, target_id, target_url, status, options)
                       VALUES ($1, $2, $3, 'completed', $4::jsonb)""",
                    scan_id, target_id, URL, json.dumps({"approval_receipt_id": approval}))
                await conn.execute("UPDATE findings SET scan_id=$2 WHERE id=$1", finding_id, scan_id)
            monkeypatch.setattr(worker, "enqueue_job",
                                lambda _r, queue, payload: _fixtures.queued.append((queue, dict(payload))))
            policy = dataclasses.replace(
                worker.VerificationPolicy.from_env(overrides={}), auto_retest_enabled=True,
                auto_retest_max_per_scan=5, verification_min_severity="low")
            monkeypatch.setattr(worker.VerificationPolicy, "from_env",
                                classmethod(lambda cls, overrides=None: policy))
            counts = await worker.queue_auto_retests_for_scan(str(scan_id), str(target_id), URL)
            assert counts["queued"] == 1
            job = _fixtures.queued[-1][1]
            row, _ = await _verification(pool, job["verification_id"])
            admitted = json.loads(row["admitted_authority"])
            assert admitted["standing_receipt_id"] == str(standing["approval_receipt_id"])
            assert admitted["approval_receipt_id"] == approval
            prover = FixtureProver()
            _use_prover(monkeypatch, prover)
            _timing(monkeypatch, poll_seconds=0.2, grace_seconds=0.5)

            async def revoke_soon():
                while prover.calls == 0:
                    await asyncio.sleep(0.05)
                async with pool.acquire() as conn:
                    await conn.execute("UPDATE approval_receipts SET status='revoked', revoked_at=NOW() WHERE id=$1",
                                       uuid.UUID(approval))
            hook = asyncio.create_task(revoke_soon())
            await worker.process_finding_retest_job(job)
            await hook
            row, finding = await _verification(pool, job["verification_id"])
            _assert_no_verdict(row, finding, reason_code="authorization_revoked")
    asyncio.run(run())


def test_a_reaped_retest_keeps_its_binding_when_it_is_requeued(template_database, monkeypatch, _fixtures):
    """A retest whose worker died is requeued with a fresh message; the binding is durable."""
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            target_id, finding_id, _ = await _web_target(pool)
            response, _job = await _admit(pool, _fixtures, finding_id)
            async with pool.acquire() as conn:
                await conn.execute(
                    """UPDATE finding_verifications SET status='running', attempt_count=1,
                              started_at=NOW() - INTERVAL '2 days', updated_at=NOW() - INTERVAL '2 days'
                        WHERE id=$1""", uuid.UUID(response["retest_id"]))
            monkeypatch.setattr(worker, "enqueue_job",
                                lambda _r, queue, payload: _fixtures.queued.append((queue, dict(payload))))
            before = len(_fixtures.queued)
            await worker.reap_stale_retests(now=datetime.now(timezone.utc) + timedelta(days=1))
            assert len(_fixtures.queued) == before + 1
            requeued = _fixtures.queued[-1][1]
            assert "approval_receipt_id" not in requeued  # the message carries no authority
            await _revoke(pool, target_id)
            prover = FixtureProver(seconds=0.1)
            _use_prover(monkeypatch, prover)
            await worker.process_finding_retest_job(requeued)
            assert prover.calls == 0
            row, finding = await _verification(pool, response["retest_id"])
            _assert_no_verdict(row, finding, reason_code="authorization_revoked")
    asyncio.run(run())


def test_a_retest_queued_by_an_earlier_engine_is_refused_when_revoked_since_and_watched_otherwise(
        template_database, monkeypatch, _fixtures):
    """Upgrade: rows and messages 2.8.3 queued carry no binding (``admitted_authority`` NULL)."""
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            # Revoked after it was queued, and the target has no authorization now: refused.
            target_id, finding_id, _ = await _web_target(pool)
            response, job = await _admit(pool, _fixtures, finding_id)
            async with pool.acquire() as conn:
                await conn.execute("UPDATE finding_verifications SET admitted_authority=NULL WHERE id=$1",
                                   uuid.UUID(response["retest_id"]))
            await _revoke(pool, target_id)
            prover = FixtureProver(seconds=0.1)
            _use_prover(monkeypatch, prover)
            await worker.process_finding_retest_job(job)
            assert prover.calls == 0
            row, finding = await _verification(pool, response["retest_id"])
            _assert_no_verdict(row, finding, reason_code="authorization_revoked")

            # Still authorized when it starts: bound to the current authorization and watched.
            target_id, finding_id, _ = await _web_target(pool, url="http://retest-two.fixture.test")
            response, job = await _admit(pool, _fixtures, finding_id)
            async with pool.acquire() as conn:
                await conn.execute("UPDATE finding_verifications SET admitted_authority=NULL WHERE id=$1",
                                   uuid.UUID(response["retest_id"]))
            prover = FixtureProver()
            _use_prover(monkeypatch, prover)
            _timing(monkeypatch, poll_seconds=0.2, grace_seconds=0.5)

            async def revoke_soon():
                while prover.calls == 0:
                    await asyncio.sleep(0.05)
                await _revoke(pool, target_id)
            hook = asyncio.create_task(revoke_soon())
            await worker.process_finding_retest_job(job)
            await hook
            row, finding = await _verification(pool, response["retest_id"])
            _assert_no_verdict(row, finding, reason_code="authorization_revoked")
    asyncio.run(run())


def test_a_retest_admitted_without_any_authorization_is_not_watched(template_database, monkeypatch, _fixtures):
    """Nothing revocable (no target authorization, no receipt named): unchanged from 2.8.3."""
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            _target_id, finding_id, _ = await _web_target(pool, authorize=False)
            prover = FixtureProver(seconds=0.2, proven=True)
            _use_prover(monkeypatch, prover)
            response, job = await _admit(pool, _fixtures, finding_id)
            row, _ = await _verification(pool, response["retest_id"])
            assert running.retest_authority_receipts(json.loads(row["admitted_authority"])) == []
            await worker.process_finding_retest_job(job)
            row, _ = await _verification(pool, response["retest_id"])
            assert row["status"] == "completed" and row["verdict"] == "exploited"
    asyncio.run(run())


def test_an_ai_gate_replay_stopped_by_its_authorization_records_no_verdict(template_database, monkeypatch):
    """``POST /ai/findings/{id}/retest`` runs as an AI scan; a stopped replay is not a fix."""
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            target_id, finding_id, _ = await _web_target(pool)
            verification_id = uuid.uuid4()
            async with pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO finding_verifications (id, finding_id, status, finding_type, target_url,
                                                          verification_mode)
                       VALUES ($1, $2, 'running', 'generic_http', $3, 'ai_driven')""",
                    verification_id, finding_id, URL)
            stop = retest_authority_stop("authorization_revoked", before_start=False)
            result = {"findings": [], "ai_gate": {"errors": []},
                      "scan_metadata": {"stop_reason": "authorization_withdrawn", "authority_stop": stop}}
            await worker.finalize_ai_finding_retest(
                options={"ai_finding_retest": {"verification_id": str(verification_id),
                                               "finding_id": str(finding_id)}},
                result=result, scan_id=str(uuid.uuid4()), completed_at=datetime.now(timezone.utc), error=None)
            row, finding = await _verification(pool, verification_id)
            assert row["status"] == "failed" and row["verdict"] == "error"  # never likely_fixed
            assert finding["last_verification_verdict"] == "error"
            assert public_retest_row(row)["stop_reason"] == "authorization_withdrawn"
    asyncio.run(run())


def test_the_retest_watch_is_the_shared_running_authority():
    """No second implementation: a retest is watched by the device and AI run machinery."""
    assert worker.running_retest_authority is running.running_retest_authority
    authority = asyncio.run(running.running_retest_authority(
        object(), admitted={"target_id": str(uuid.uuid4()), "standing_receipt_id": str(uuid.uuid4())},
        destination=URL))
    assert isinstance(authority, running.RunningScanAuthority)
    assert all(isinstance(guard, running.ScanAuthorityGuard) for guard in authority.guard.guards)
    assert authority.action.action_id == "finding.retest"


def test_an_approval_that_does_not_cover_the_replayed_host_is_refused_at_admission(
        template_database, monkeypatch, _fixtures):
    async def run():
        async with scan_database(template_database) as pool:
            target_id, finding_id, _ = await _web_target(pool, authorize=False)
            approval = await _approval(pool, target_id, host="other.fixture.test")
            with pytest.raises(findings.HTTPException) as refused:
                await _admit(pool, _fixtures, finding_id, approval=approval)
            assert refused.value.status_code == 400
            assert refused.value.detail["error"] == "replay_url_out_of_scope"
            async with pool.acquire() as conn:
                assert await conn.fetchval("SELECT count(*) FROM finding_verifications") == 0
    asyncio.run(run())


def test_no_automatic_retests_after_a_scan_stopped_by_its_authorization_or_outside_its_approval(
        template_database, monkeypatch, _fixtures):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            monkeypatch.setattr(worker, "enqueue_job",
                                lambda _r, queue, payload: _fixtures.queued.append((queue, dict(payload))))
            policy = dataclasses.replace(
                worker.VerificationPolicy.from_env(overrides={}), auto_retest_enabled=True,
                auto_retest_max_per_scan=5, verification_min_severity="low")
            monkeypatch.setattr(worker.VerificationPolicy, "from_env",
                                classmethod(lambda cls, overrides=None: policy))
            target_id, finding_id, _ = await _web_target(pool)
            stopped_scan, other_scan = uuid.uuid4(), uuid.uuid4()
            narrow = await _approval(pool, target_id, host="other.fixture.test")
            async with pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO scans (id, target_id, target_url, status, options, result)
                       VALUES ($1, $2, $3, 'completed', '{}'::jsonb, $4::jsonb)""",
                    stopped_scan, target_id, URL,
                    json.dumps({"scan_metadata": {"stop_reason": "authorization_withdrawn"}}))
                await conn.execute(
                    """INSERT INTO scans (id, target_id, target_url, status, options)
                       VALUES ($1, $2, $3, 'completed', $4::jsonb)""",
                    other_scan, target_id, URL, json.dumps({"approval_receipt_id": narrow}))
                await conn.execute("UPDATE findings SET scan_id=$2 WHERE id=$1", finding_id, stopped_scan)
            assert (await worker.queue_auto_retests_for_scan(str(stopped_scan), str(target_id), URL))["queued"] == 0
            async with pool.acquire() as conn:
                await conn.execute("UPDATE findings SET scan_id=$2 WHERE id=$1", finding_id, other_scan)
            counts = await worker.queue_auto_retests_for_scan(str(other_scan), str(target_id), URL)
            assert counts == {"queued": 0, "skipped": 1}
            assert _fixtures.queued == []
    asyncio.run(run())


def test_an_earlier_engines_retest_is_refused_when_the_target_moved_and_its_binding_is_kept(
        template_database, monkeypatch, _fixtures):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            prover = FixtureProver(seconds=0.1)
            _use_prover(monkeypatch, prover)
            # The target's URL changed after it was queued: its receipt no longer covers it.
            target_id, finding_id, _ = await _web_target(pool)
            response, job = await _admit(pool, _fixtures, finding_id)
            async with pool.acquire() as conn:
                await conn.execute("UPDATE finding_verifications SET admitted_authority=NULL WHERE id=$1",
                                   uuid.UUID(response["retest_id"]))
                await conn.execute("UPDATE targets SET url='http://moved.fixture.test' WHERE id=$1", target_id)
            await worker.process_finding_retest_job(job)
            assert prover.calls == 0
            row, finding = await _verification(pool, response["retest_id"])
            _assert_no_verdict(row, finding, reason_code="scope_invalid")

            # Bound at start: the binding is saved on the row for any later requeue.
            target_id, finding_id, standing = await _web_target(pool, url="http://retest-three.fixture.test")
            response, job = await _admit(pool, _fixtures, finding_id)
            async with pool.acquire() as conn:
                await conn.execute("UPDATE finding_verifications SET admitted_authority=NULL WHERE id=$1",
                                   uuid.UUID(response["retest_id"]))
            await worker.process_finding_retest_job(job)
            row, _ = await _verification(pool, response["retest_id"])
            admitted = json.loads(row["admitted_authority"])
            assert admitted["legacy"] is True
            assert admitted["standing_receipt_id"] == str(standing["approval_receipt_id"])
    asyncio.run(run())


# Regression tests for the review of the first version (scope spelling, replay destination,
# target-less findings, earlier engines' retests, a settle that fails).

class RecordingProver(FixtureProver):
    """Records the URL each replay step is sent to."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.urls: list[str] = []

    async def __call__(self, *args, **kwargs):
        self.urls.append(args[0] if args else kwargs.get("url"))
        return await super().__call__(*args, **kwargs)


async def _admit_url(pool, redis, finding_id, *, approval=None, original_url=None):
    previous = _configure_routes(pool, redis)
    try:
        response = await findings.retest_finding(
            str(finding_id), findings.FindingRetestRequest(
                requested_by="ui", approval_receipt_id=approval, original_url=original_url),
            mode="deterministic")
    finally:
        _restore_routes(previous)
    return response, redis.queued[-1][1]


@pytest.mark.parametrize("approved_host,replay_url", [
    ("fass.example", "http://faß.example/search?q=1"),  # IDNA 2003 maps it; clients connect elsewhere
    ("fixture.co.uk", "http://sub.evil.co.uk/search?q=1"),  # a public-suffix root covers nothing
    ("retest.fixture.test", "http://evil.example\\@retest.fixture.test/search?q=1"),  # ambiguous authority
])
def test_an_approval_admits_only_the_strict_spelling_of_the_replay_host(
        template_database, monkeypatch, _fixtures, approved_host, replay_url):
    async def run():
        async with scan_database(template_database) as pool:
            target_id, finding_id, _ = await _web_target(pool, authorize=False)
            approval = await _approval(pool, target_id, host=approved_host)
            if "co.uk" in replay_url:
                async with pool.acquire() as conn:
                    await conn.execute(
                        """UPDATE scope_receipts SET allowed_root_domains='["co.uk"]'::jsonb
                            WHERE id=(SELECT scope_receipt_id FROM approval_receipts WHERE id=$1)""",
                        uuid.UUID(approval))
            with pytest.raises(findings.HTTPException) as refused:
                await _admit_url(pool, _fixtures, finding_id, approval=approval, original_url=replay_url)
            assert refused.value.status_code == 400
            assert refused.value.detail["error"] == "replay_url_out_of_scope"
    asyncio.run(run())


def test_the_running_check_and_admission_share_the_strict_host_rule():
    from scan.running_scan_authority import _host_in_admitted_scope
    import action_scope
    assert not _host_in_admitted_scope("faß.example", {"allowed_hosts": ["fass.example"]})
    assert not _host_in_admitted_scope("sub.evil.co.uk", {"allowed_root_domains": ["co.uk"]})
    assert _host_in_admitted_scope("2001:DB8::0001", {"allowed_hosts": ["2001:db8::1"]})
    assert _host_in_admitted_scope("good.example.", {"allowed_hosts": ["good.example"]})
    assert action_scope.url_host_for_scope("https://evil.example\\@good.example/x") is None
    import api as api_module  # noqa: F401 - the admission helper delegates to the same rule
    assert "receipt_scope_covers_host" in Path(ROOT / "api" / "api.py").read_text(encoding="utf-8")


def test_a_retest_bound_only_to_the_target_authorization_cannot_replay_another_host(
        template_database, monkeypatch, _fixtures):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            _target_id, finding_id, _ = await _web_target(pool)
            with pytest.raises(findings.HTTPException) as refused:
                await _admit_url(pool, _fixtures, finding_id, original_url="http://elsewhere.invalid/search?q=1")
            assert refused.value.detail["error"] == "replay_url_out_of_scope"
            assert "target's authorization" in refused.value.detail["message"]
            # Bulk skips it with the reason.
            previous = _configure_routes(pool, _fixtures)
            try:
                async with pool.acquire() as conn:
                    await conn.execute("UPDATE findings SET url='http://elsewhere.invalid/x', "
                                       "evidence='{\"type\":\"xss\",\"param\":\"q\"}'::jsonb WHERE id=$1", finding_id)
                response = await findings.bulk_retest_findings(findings.FindingsBulkRetestRequest(
                    finding_ids=[str(finding_id)], mode="deterministic"))
            finally:
                _restore_routes(previous)
            assert response["queued"] == []
            assert response["skipped"][0]["reason"] == "replay_url_out_of_scope"
    asyncio.run(run())


def test_a_row_whose_replay_destination_left_the_scope_is_refused_while_running(
        template_database, monkeypatch, _fixtures):
    """The destination is re-checked on every poll against the scope that admitted it."""
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            _target_id, finding_id, _ = await _web_target(pool)
            response, job = await _admit(pool, _fixtures, finding_id)
            async with pool.acquire() as conn:  # a row edited after admission
                await conn.execute("UPDATE finding_verifications SET original_url='http://elsewhere.invalid/x' "
                                   "WHERE id=$1", uuid.UUID(response["retest_id"]))
            prover = RecordingProver(seconds=0.1)
            _use_prover(monkeypatch, prover)
            await worker.process_finding_retest_job(job)
            assert prover.calls == 0
            row, finding = await _verification(pool, response["retest_id"])
            _assert_no_verdict(row, finding, reason_code="scope_invalid")
    asyncio.run(run())


def test_a_redirect_off_the_scope_is_refused_and_the_retest_records_no_fix(
        template_database, monkeypatch, _fixtures):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            _target_id, finding_id, _ = await _web_target(pool)
            sent: list[str] = []

            async def fetch_once(url, *args, **kwargs):
                sent.append(url)
                if "elsewhere" in url:
                    return {"status_code": 200, "headers": {}, "body": "", "final_url": url, "error": None}
                return {"status_code": 302, "headers": {"location": "http://elsewhere.invalid/landing"},
                        "body": "", "final_url": url, "error": None}
            monkeypatch.setattr(proof_of_exploit, "_fetch_once", fetch_once)

            async def prover(url, *args, **kwargs):
                await proof_of_exploit.fetch_with_capture(url)
                return proof_of_exploit.ExploitProof(proven=False)
            _use_prover(monkeypatch, prover)
            response, job = await _admit(pool, _fixtures, finding_id)
            await worker.process_finding_retest_job(job)
            assert sent and all("elsewhere" not in url for url in sent)
            row, finding = await _verification(pool, response["retest_id"])
            assert row["verdict"] == "inconclusive" and finding["last_verification_verdict"] == "inconclusive"
            artifacts = json.loads(row["artifacts"]) if isinstance(row["artifacts"], str) else row["artifacts"]
            assert artifacts["refused_destinations"] == ["elsewhere.invalid"]
    asyncio.run(run())


def test_fetch_without_a_guard_is_unchanged_and_with_one_checks_every_hop(monkeypatch):
    from scanner_tools.destination_guard import destination_guard
    calls = []

    async def fetch_once(url, method, data, headers, timeout, follow, *rest):
        calls.append((url, method, follow))
        if url.endswith("/a"):
            return {"status_code": 303, "headers": {"location": "/b"}, "final_url": url}
        return {"status_code": 200, "headers": {}, "final_url": url}
    monkeypatch.setattr(proof_of_exploit, "_fetch_once", fetch_once)
    asyncio.run(proof_of_exploit.fetch_with_capture("http://ok.test/a", method="POST", data="x"))
    assert calls == [("http://ok.test/a", "POST", True)]  # curl follows, as before
    calls.clear()

    async def guarded():
        with destination_guard(lambda url: "ok.test" in url) as guard:
            result = await proof_of_exploit.fetch_with_capture("http://ok.test/a", method="POST", data="x")
            refused = await proof_of_exploit.fetch_with_capture("http://bad.test/a")
            return result, refused, guard.refused
    result, refused, hosts = asyncio.run(guarded())
    assert calls == [("http://ok.test/a", "POST", False), ("http://ok.test/b", "GET", False)]
    assert result["status_code"] == 200 and refused["error"] == "destination_out_of_scope"
    assert hosts == ["bad.test"]


def test_a_targetless_finding_with_an_approval_is_watched_by_that_approval(template_database, monkeypatch, _fixtures):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            async with pool.acquire() as conn:
                finding_id = await conn.fetchval(
                    """INSERT INTO findings (target_id, fingerprint, title, severity, tool, url, evidence)
                       VALUES (NULL, $1, 'Reflected XSS', 'high', 'dalfox', $2, $3::jsonb) RETURNING id""",
                    uuid.uuid4().hex, f"{URL}/search?q=1",
                    json.dumps({"type": "xss", "param": "q", "url": f"{URL}/search?q=1"}))
            approval = await _approval(pool, None)
            prover = RecordingProver(seconds=0.6, proven=True)
            _use_prover(monkeypatch, prover)
            _timing(monkeypatch, poll_seconds=0.2)
            response, job = await _admit_url(pool, _fixtures, finding_id, approval=approval)
            await worker.process_finding_retest_job(job)
            row, _ = await _verification(pool, response["retest_id"])
            assert row["status"] == "completed" and row["verdict"] == "exploited" and prover.calls >= 1

            # The same, revoked mid-run: stopped as revoked, never "target deactivated".
            response, job = await _admit_url(pool, _fixtures, finding_id, approval=approval)
            prover = RecordingProver()
            _use_prover(monkeypatch, prover)
            _timing(monkeypatch, poll_seconds=0.2, grace_seconds=0.5)

            async def revoke_soon():
                while prover.calls == 0:
                    await asyncio.sleep(0.05)
                async with pool.acquire() as conn:
                    await conn.execute("UPDATE approval_receipts SET status='revoked', revoked_at=NOW() WHERE id=$1",
                                       uuid.UUID(approval))
            hook = asyncio.create_task(revoke_soon())
            await worker.process_finding_retest_job(job)
            await hook
            row, finding = await _verification(pool, response["retest_id"])
            _assert_no_verdict(row, finding, reason_code="authorization_revoked")
    asyncio.run(run())


def test_an_earlier_engines_retest_is_not_revived_by_authorizing_the_target_again(
        template_database, monkeypatch, _fixtures):
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            target_id, finding_id, _ = await _web_target(pool)
            response, job = await _admit(pool, _fixtures, finding_id)
            async with pool.acquire() as conn:
                await conn.execute("UPDATE finding_verifications SET admitted_authority=NULL WHERE id=$1",
                                   uuid.UUID(response["retest_id"]))
            await _revoke(pool, target_id)
            async with pool.acquire() as conn:
                await target_authorization.authorize_target(conn, target_id, approved_by="fixture-owner")
            prover = RecordingProver(seconds=0.1)
            _use_prover(monkeypatch, prover)
            await worker.process_finding_retest_job(job)
            assert prover.calls == 0
            row, finding = await _verification(pool, response["retest_id"])
            _assert_no_verdict(row, finding, reason_code="authorization_revoked")
    asyncio.run(run())


def test_an_earlier_engines_reaped_retest_keeps_the_approval_its_operation_recorded(
        template_database, monkeypatch, _fixtures):
    """A 2.8.x retest running at the upgrade is requeued by the reaper without its message."""
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            target_id, finding_id, _ = await _web_target(pool, authorize=False)
            approval = await _approval(pool, target_id)
            response, _job = await _admit(pool, _fixtures, finding_id, approval=approval)
            async with pool.acquire() as conn:
                await conn.execute("UPDATE finding_verifications SET admitted_authority=NULL WHERE id=$1",
                                   uuid.UUID(response["retest_id"]))
                await conn.execute(
                    """INSERT INTO command_results (command, status, risk_tier, approval_receipt_id, result_json,
                                                    created_by, operator_message)
                       VALUES ('finding.retest', 'retest_scheduled', 'active', $1, $2::jsonb, 'ui', 'queued')""",
                    uuid.UUID(approval), json.dumps({"retest_id": response["retest_id"]}))
            requeued = worker.build_retest_job_payload(
                job_id=_job["job_id"], verification_id=response["retest_id"], finding_id=str(finding_id),
                submitted_at=datetime.now(timezone.utc).isoformat(), trigger="stale_watchdog_requeue")
            prover = RecordingProver()
            _use_prover(monkeypatch, prover)
            _timing(monkeypatch, poll_seconds=0.2, grace_seconds=0.5)

            async def revoke_soon():
                while prover.calls == 0:
                    await asyncio.sleep(0.05)
                async with pool.acquire() as conn:
                    await conn.execute("UPDATE approval_receipts SET status='revoked', revoked_at=NOW() WHERE id=$1",
                                       uuid.UUID(approval))
            hook = asyncio.create_task(revoke_soon())
            await worker.process_finding_retest_job(requeued)
            await hook
            row, finding = await _verification(pool, response["retest_id"])
            assert json.loads(row["admitted_authority"])["approval_receipt_id"] == approval
            _assert_no_verdict(row, finding, reason_code="authorization_revoked")
    asyncio.run(run())


def test_a_stop_whose_settle_failed_is_settled_by_the_reaper_not_requeued(template_database, monkeypatch, _fixtures):
    from worker_handlers import retest_authority as handler
    async def run():
        async with scan_database(template_database) as pool:
            monkeypatch.setattr(worker, "db_pool", pool)
            target_id, finding_id, _ = await _web_target(pool)
            response, job = await _admit(pool, _fixtures, finding_id)
            prover = RecordingProver()
            _use_prover(monkeypatch, prover)
            _timing(monkeypatch, poll_seconds=0.2, grace_seconds=0.5)
            monkeypatch.setattr(handler, "SETTLE_RETRY_DELAYS", (0.0, None))
            real_once = handler._settle_once

            async def failing_once(*_a, **_k):
                raise OSError("database unreachable")
            monkeypatch.setattr(handler, "_settle_once", failing_once)

            async def revoke_soon():
                while prover.calls == 0:
                    await asyncio.sleep(0.05)
                await _revoke(pool, target_id)
            hook = asyncio.create_task(revoke_soon())
            with pytest.raises(OSError):
                await worker.process_finding_retest_job(job)
            await hook
            row, _ = await _verification(pool, response["retest_id"])
            assert row["status"] == "running"
            monkeypatch.setattr(handler, "_settle_once", real_once)
            async with pool.acquire() as conn:
                await conn.execute("UPDATE finding_verifications SET started_at=NOW() - INTERVAL '2 days' WHERE id=$1",
                                   uuid.UUID(response["retest_id"]))
            before = len(_fixtures.queued)
            counts = await worker.reap_stale_retests(now=datetime.now(timezone.utc) + timedelta(days=1))
            assert counts["failed"] == 1 and len(_fixtures.queued) == before
            row, finding = await _verification(pool, response["retest_id"])
            _assert_no_verdict(row, finding, reason_code="authorization_revoked")
    asyncio.run(run())
