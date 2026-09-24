"""Opt-in dump/restore acceptance using a labelled, disposable PostgreSQL 16 container."""
import asyncio
from datetime import datetime, timezone
import json
import os
import subprocess
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet

from tests.disposable_postgres import require_disposable_database
from tests.test_authenticated_assurance_postgres import DSN, asyncpg, exercise, write
from tests.test_authenticated_validation_worker import Fixture, SECRET, prepare, process_validation_job, result
from authenticated_assurance.evaluation import current_assurance
from authenticated_assurance.jobs import ValidationJobs
from authenticated_assurance.models import ValidationRecord, ValidationRequest
import secret_store

CONTAINER = os.environ.get("ASSURANCE_TEST_POSTGRES_CONTAINER")
RESTORED = "shakerscan_assurance_restore_test"
pytestmark = pytest.mark.skipif(not DSN or not CONTAINER, reason="requires explicitly labelled restore fixture")


def docker(*args, data=None):
    completed = subprocess.run(["docker", *args], input=data, capture_output=True, timeout=60)
    # Never include dump contents or database error text in a failure report.
    if completed.returncode:
        pytest.fail("disposable PostgreSQL restore command failed", pytrace=False)
    return completed.stdout


def require_restore_container():
    dsn = urlsplit(require_disposable_database(DSN, "shakerscan_assurance_test"))
    assert dsn.username == "postgres" and dsn.password is None
    info = json.loads(docker("inspect", CONTAINER))[0]
    assert info["Config"]["Labels"].get("shakerscan.assurance_restore_fixture") == "true"
    assert info["HostConfig"]["AutoRemove"] is True
    ports = info["NetworkSettings"]["Ports"]["5432/tcp"]
    assert ports == [{"HostIp": "127.0.0.1", "HostPort": str(dsn.port)}]
    restored = urlunsplit(dsn._replace(path="/" + RESTORED))
    return require_disposable_database(restored, RESTORED)


async def snapshot(pool):
    async with pool.acquire() as conn:
        names = await conn.fetch("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
        # Names originate in pg_catalog; quote identifiers, never interpolate user input.
        return {row["tablename"]: sorted(json.dumps(item, sort_keys=True) for item in json.loads(await conn.fetchval(
            'SELECT COALESCE(jsonb_agg(to_jsonb(t)), \'[]\'::jsonb)::text FROM "' +
            row["tablename"].replace('"', '""') + '" t'))) for row in names}


async def queue_again(pool, config, approval_id, binding, generation, revision):
    async def approve(conn, receipt, **kwargs):
        assert receipt == str(approval_id)
        return {"scope_receipt_id": binding["scope_receipt_id"]}

    async def freeze(**kwargs):
        return binding

    async with pool.acquire() as conn, conn.transaction():
        # Advance only the fixture's rate-limit timestamp, never bypass runtime admission.
        await conn.execute("UPDATE authentication_validation_requests SET created_at=NOW()-INTERVAL '1 minute'")
        return await ValidationJobs().prepare(conn, profile_id=config.credential_reference,
            request=ValidationRequest(expected_revision=revision, approval_receipt_id=approval_id,
                                      reviewed=True, allow_insecure_transport=True),
            actor="restore-fixture", generation=generation, expected_build_fingerprint="fixture-build",
            approve=approve, freeze=freeze)


def test_restore_preserves_history_but_requires_key_and_fresh_validation(monkeypatch, tmp_path):
    restored_dsn = require_restore_container()
    fixture_key = Fernet.generate_key()
    monkeypatch.setattr(Fernet, "generate_key", staticmethod(lambda: fixture_key))

    async def scenario(pool, store, config):
        fixture = Fixture()
        server, payload, config, approval_id = await prepare(pool, store, config, fixture, monkeypatch)
        key = secret_store._fernet
        async with server:
            await process_validation_job(payload, pool=pool, worker_id="before-restore")
            assert (await result(pool, payload))["validation"]["state"] == "valid"
            config = config.model_copy(update={"display_name": "Reviewed second revision"})
            await write(pool, store, config, expected=1)
            async with pool.acquire() as conn:
                binding = json.loads(await conn.fetchval(
                    "SELECT target_binding_json FROM authentication_validation_requests WHERE id=$1",
                    UUID(payload["job_id"])))
            generation = uuid4()
            payload = await queue_again(pool, config, approval_id, binding, generation, 2)
            await process_validation_job(payload, pool=pool, worker_id="before-restore")
            validated = (await result(pool, payload))["validation"]
            assert validated["state"] == "valid" and fixture.count == 2
            before = await snapshot(pool)
            dump = await asyncio.to_thread(docker, "exec", CONTAINER, "pg_dump", "-U", "postgres",
                "-d", "shakerscan_assurance_test", "--no-owner", "--no-privileges")
            assert SECRET.encode() not in dump
            assert fixture_key not in dump
            backup = tmp_path / "assurance.sql"
            with os.fdopen(os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
                stream.write(dump)
            async with pool.acquire() as conn:
                # A pre-existing database fails closed; this test never drops it.
                await conn.execute('CREATE DATABASE "' + RESTORED + '"')
            try:
                await asyncio.to_thread(docker, "exec", "-i", CONTAINER, "psql", "-U", "postgres",
                    "-d", RESTORED, "-v", "ON_ERROR_STOP=1", data=backup.read_bytes())
            finally:
                backup.unlink()
            async with asyncpg.create_pool(restored_dsn, min_size=1, max_size=4) as restored:
                assert await snapshot(restored) == before
                async with restored.acquire() as conn:
                    await store.ensure_schema(conn)
                    assert (await store.get(conn, config.credential_reference, revision=1))["configuration"]["display_name"] == "Fixture"
                    assert (await store.get(conn, config.credential_reference, revision=2))["configuration"]["display_name"] == "Reviewed second revision"
                assert await snapshot(restored) == before
                new_generation = uuid4()
                projection = current_assurance(ValidationRecord.model_validate(validated), revision=2,
                    credential_version=1, credential_record_version=1,
                    configuration_digest=config.digest(1, 1), now=datetime.now(timezone.utc),
                    process_generation=new_generation)
                assert (projection["state"], projection["reason_code"]) == ("unknown", "process_restarted")
                monkeypatch.setattr(secret_store, "_fernet", None)
                payload = await queue_again(restored, config, approval_id, binding, new_generation, 2)
                await process_validation_job(payload, pool=restored, worker_id="missing-key")
                missing = await result(restored, payload)
                assert missing["status"] == "failed"
                assert (missing["validation"]["state"], missing["validation"]["reason_code"]) == ("unknown", "validation_unavailable")
                assert missing["budget_consumed"]["http_requests"] == 0 and fixture.count == 2
                monkeypatch.setattr(secret_store, "_fernet", key)
                # Restoring the key alone does not change the failed observation.
                assert (await result(restored, payload))["validation"] == missing["validation"]
                payload = await queue_again(restored, config, approval_id, binding, new_generation, 2)
                await process_validation_job(payload, pool=restored, worker_id="reviewed-recovery")
                assert (await result(restored, payload))["validation"]["state"] == "valid"
                assert fixture.count == 3

    exercise(scenario)
