"""Synthetic loopback HTTP + disposable PostgreSQL; never dispatches a Scan."""

import asyncio
from datetime import datetime, timedelta, timezone
import json
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet

from tests.test_authenticated_assurance_postgres import exercise, write, DSN
from authenticated_assurance.jobs import ValidationJobs, SCHEMA_SQL, ACTION_NAME
from authenticated_assurance.job_lifecycle import stop_request, claim_request
from authenticated_assurance.models import ValidationRequest
from api.authenticated_assurance.models import ProfileConfiguration
from authenticated_assurance.worker import process_validation_job as _process_validation_job
from runtime.credentials import build_credential_secret
from runtime.reservation_store import PostgresBudgetReservationStore
from runtime.reservation_recovery import recover_stale_reservations
import secret_store

pytestmark = pytest.mark.skipif(not DSN, reason="requires disposable assurance PostgreSQL database")
SECRET = "synthetic-assurance-secret-never-export-this"


async def process_validation_job(payload, *, pool, worker_id, build_fingerprint="fixture-build"):
    return await _process_validation_job(payload, pool=pool, worker_id=worker_id, build_fingerprint=build_fingerprint)


class Fixture:
    def __init__(self, status=200, body=b'{"id":"test-user"}', location=None, hold=False):
        self.status, self.body, self.location = status, body, location
        self.hold = hold
        self.entered, self.release = asyncio.Event(), asyncio.Event()
        self.count, self.authenticated = 0, False

    async def handle(self, reader, writer):
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            self.count += 1
            self.authenticated = b"Authorization: Bearer " + SECRET.encode() in request
            self.entered.set()
            if self.hold:
                await self.release.wait()
            headers = f"HTTP/1.1 {self.status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {len(self.body)}\r\nSet-Cookie: fixture={SECRET}; HttpOnly\r\nConnection: close\r\n"
            if self.location:
                headers += f"Location: {self.location}\r\n"
            writer.write(headers.encode() + b"\r\n" + self.body)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()


async def prepare(pool, store, config, fixture, monkeypatch):
    server = await asyncio.start_server(fixture.handle, "127.0.0.1", 0)
    origin = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
    config = ProfileConfiguration.model_validate({**config.model_dump(), "credential_destinations": [origin],
        "validation_policy": {**config.validation_policy.model_dump(), "timeout_seconds": 1}})
    fernet = Fernet(Fernet.generate_key())
    monkeypatch.setattr(secret_store, "_fernet", fernet)
    monkeypatch.setattr(secret_store, "_loaded", True)
    encrypt = lambda value: "enc:fernet:" + fernet.encrypt(value.encode()).decode()
    approval_id, scope_id, generation = uuid4(), uuid4(), uuid4()
    async with pool.acquire() as conn:
        await PostgresBudgetReservationStore().ensure_schema(conn)
        await conn.execute(SCHEMA_SQL)
        await conn.execute("""CREATE TABLE scope_receipts(id UUID PRIMARY KEY, target_id UUID, verdict TEXT);
            CREATE TABLE approval_receipts(id UUID PRIMARY KEY, scope_receipt_id UUID, risk_tier TEXT,
            confirmations JSONB, approved_by TEXT, denial_reason TEXT, expires_at TIMESTAMPTZ,
            action_name TEXT, status TEXT, revoked_at TIMESTAMPTZ)""")
        await conn.execute("INSERT INTO scope_receipts VALUES($1,$2,'allowed')", scope_id, config.target_id)
        await conn.execute("""INSERT INTO approval_receipts VALUES($1,$2,'credential',
            '["confirm_authorized"]','fixture',NULL,$3,$4,'active',NULL)""",
            approval_id, scope_id, datetime.now(timezone.utc)+timedelta(minutes=5), ACTION_NAME)
        await conn.execute("UPDATE targets SET url=$2 WHERE id=$1", config.target_id, origin)
        await conn.execute("UPDATE credential_profile_bindings SET allowed_capabilities='[\"http.request\"]'::jsonb WHERE profile_id=$1", config.credential_reference)
        await conn.execute("""UPDATE credential_profile_versions SET encrypted_secret=$2, encrypted_metadata=$3
            WHERE profile_id=$1""", config.credential_reference,
            encrypt(build_credential_secret("bearer_token", secret=SECRET)),
            encrypt(json.dumps({"schema_version": "credential-private-metadata/v1"})))
    await write(pool, store, config)

    async def approve(conn, receipt, **kwargs):
        assert receipt == str(approval_id)
        assert kwargs["required_action_name"] == ACTION_NAME
        assert kwargs["risk_tier"] == "credential" and kwargs["always_require_receipt"]
        return {"scope_receipt_id": str(scope_id)}

    async def freeze(**kwargs):
        assert kwargs["target_url"] == origin
        return {"target_id": str(config.target_id), "target_kind": "web", "canonical_host": "127.0.0.1",
            "allowed_origins": [origin, "http://127.0.0.1:9999"], "allowed_addresses": ["127.0.0.1"],
            "scope_receipt_id": str(scope_id), "environment": "lab"}

    async with pool.acquire() as conn, conn.transaction():
        payload = await ValidationJobs().prepare(conn, profile_id=config.credential_reference,
            request=ValidationRequest(expected_revision=1, approval_receipt_id=approval_id, reviewed=True,
                                      allow_insecure_transport=True),
            actor="fixture", generation=generation, expected_build_fingerprint="fixture-build", approve=approve, freeze=freeze)
    return server, payload, config, approval_id


@pytest.mark.parametrize("change", ["approval", "credential", "metadata"])
def test_cached_scan_credential_rechecks_real_persisted_authority(monkeypatch, change):
    async def scenario(pool, store, config):
        from runtime.scan_credential_guard import build_scan_credential_check
        from authenticated_assurance.jobs import target_binding

        fixture = Fixture()
        server, payload, config, approval_id = await prepare(pool, store, config, fixture, monkeypatch)
        async with server:
            async with pool.acquire() as conn:
                binding = json.loads(await conn.fetchval("SELECT target_binding_json FROM authentication_validation_requests WHERE id=$1", UUID(payload["job_id"])))
                await conn.execute("UPDATE approval_receipts SET action_name='scan.submit' WHERE id=$1", approval_id)
            options = {"approval_receipt_id": str(approval_id), "scope_receipt_id": binding["scope_receipt_id"],
                "credential_action_name": "scan.submit", "credential_profile_refs": [{
                    "profile_id": str(config.credential_reference), "profile_version": 1, "credential_record_version": 1,
                    "auth_kind": "bearer_token", "principal_slot": "primary", "allowed_capabilities": ["http.request"],
                }]}
            check = build_scan_credential_check(pool, options=options, target=target_binding(binding), scan_id=str(uuid4()))
            assert await check(None) is None
            async with pool.acquire() as conn:
                if change == "approval":
                    await conn.execute("UPDATE approval_receipts SET status='revoked', revoked_at=NOW() WHERE id=$1", approval_id)
                elif change == "credential":
                    await conn.execute("UPDATE credential_profiles SET is_active=false WHERE id=$1", config.credential_reference)
                else:
                    await conn.execute("UPDATE credential_profiles SET record_version=record_version+1 WHERE id=$1", config.credential_reference)
            assert await check(None) == "authentication_uncertain"
            assert fixture.count == 0
    exercise(scenario)


async def result(pool, payload):
    async with pool.acquire() as conn:
        value = await ValidationJobs().read(conn, UUID(payload["job_id"]))
    assert SECRET not in json.dumps(value, default=str)
    return value


@pytest.mark.parametrize("change", ["edit", "disable", "target"])
def test_scan_rechecks_pinned_assurance_profile_authority(monkeypatch, change):
    from authenticated_assurance.snapshots import ScanProfileSelection, pin_scan_profiles, attach_scan_snapshots
    from authenticated_assurance.jobs import target_binding
    from runtime.scan_credential_guard import build_scan_credential_check

    async def scenario(pool, store, config):
        fixture = Fixture()
        config = config.model_copy(update={"lifecycle_state": "ready"})
        server, payload, config, approval_id = await prepare(pool, store, config, fixture, monkeypatch)
        async with server:
            await process_validation_job(payload, pool=pool, worker_id="profile-snapshot-fixture")
            validation = (await result(pool, payload))["validation"]
            refs = [{"profile_id": str(config.credential_reference), "profile_version": 1,
                "credential_record_version": 1, "auth_kind": "bearer_token", "principal_slot": "primary",
                "allowed_capabilities": ["http.request"]}]
            async with pool.acquire() as conn, conn.transaction():
                binding = json.loads(await conn.fetchval(
                    "SELECT target_binding_json FROM authentication_validation_requests WHERE id=$1", UUID(payload["job_id"])))
                snapshots = await pin_scan_profiles(conn, [ScanProfileSelection(
                    profile_id=config.credential_reference, revision=1, reviewed=True)], refs,
                    target_id=config.target_id, target_url=config.credential_destinations[0],
                    now=datetime.now(timezone.utc), generation=UUID(validation["process_generation"]))
                await conn.execute("UPDATE approval_receipts SET action_name='scan.submit' WHERE id=$1", approval_id)
            options = {"approval_receipt_id": str(approval_id), "scope_receipt_id": binding["scope_receipt_id"],
                "credential_action_name": "scan.submit", "credential_profile_refs": attach_scan_snapshots(refs, snapshots)}
            check = build_scan_credential_check(pool, options=options, target=target_binding(binding), scan_id=str(uuid4()))
            assert await check(None) is None
            if change == "target":
                async with pool.acquire() as conn:
                    await conn.execute("UPDATE targets SET url='http://127.0.0.1:9999' WHERE id=$1", config.target_id)
            else:
                updated = config.model_copy(update={"display_name": "Edited"} if change == "edit" else {"lifecycle_state": "disabled"})
                await write(pool, store, updated, expected=1)
            assert await check(None) == "authentication_uncertain"
            assert fixture.count == 1
            assert options["credential_profile_refs"][0]["authenticated_profile_snapshot"]["revision"] == 1
    exercise(scenario)


@pytest.mark.parametrize("status,body,location,state,reason", [
    (200, b'{"id":"test-user"}', None, "valid", "identity_confirmed"),
    (200, json.dumps({"id": "test-user", "private": SECRET}).encode(), None, "valid", "identity_confirmed"),
    (200, b'{"page":"login"}', None, "invalid", "expected_identity_missing"),
    (403, b'{}', None, "unknown", "access_denied"),
    (401, b'{}', None, "invalid", "expected_identity_missing"),
    (500, b'{}', None, "unknown", "application_error"),
    (200, b'{"id":"another-user"}', None, "invalid", "unexpected_identity"),
    (302, b'{}', "/login", "unknown", "login_redirect"),
    (302, b'{}', "http://127.0.0.1:9999/leak", "unknown", "destination_rejected"),
    (200, b'{"id":"test-user"}' + b' ' * 20000, None, "unknown", "invalid_response"),
])
def test_real_bounded_health_response(monkeypatch, status, body, location, state, reason):
    async def scenario(pool, store, config):
        fixture = Fixture(status, body, location)
        server, payload, config, _ = await prepare(pool, store, config, fixture, monkeypatch)
        async with server:
            await process_validation_job(payload, pool=pool, worker_id="fixture-worker")
            await process_validation_job(payload, pool=pool, worker_id="duplicate-worker")
        value = await result(pool, payload)
        assert fixture.count == 1 and fixture.authenticated, value
        assert value["status"] == "completed", value
        assert (value["validation"]["state"], value["validation"]["reason_code"]) == (state, reason)
        assert value["budget_consumed"]["http_requests"] == 1
        assert value["receipt"]["validation_id"] == payload["job_id"]
        assert value["receipt"]["observations"][0]["response_content_retained"] is False
    exercise(scenario)


@pytest.mark.parametrize("change,expected", [("revoke", "credential_revoked"), ("reactivate", "credential_changed"),
    ("approval", "approval_unavailable"), ("cancel", "validation_cancelled"), ("timeout", "validation_timeout")])
def test_inflight_revocation_cancellation_and_timeout(monkeypatch, change, expected):
    async def scenario(pool, store, config):
        fixture = Fixture(hold=True)
        server, payload, config, approval_id = await prepare(pool, store, config, fixture, monkeypatch)
        async with server:
            task = asyncio.create_task(process_validation_job(payload, pool=pool, worker_id="fixture-worker"))
            await asyncio.wait_for(fixture.entered.wait(), 3)
            await process_validation_job(payload, pool=pool, worker_id="concurrent-duplicate")
            async with pool.acquire() as conn, conn.transaction():
                if change in {"revoke", "reactivate"}:
                    await conn.execute("UPDATE credential_profiles SET is_active=false, record_version=record_version+1 WHERE id=$1", config.credential_reference)
                    if change == "reactivate":
                        await conn.execute("UPDATE credential_profiles SET is_active=true, record_version=record_version+1 WHERE id=$1", config.credential_reference)
                elif change == "approval":
                    await conn.execute("UPDATE approval_receipts SET status='revoked', revoked_at=NOW() WHERE id=$1", approval_id)
                elif change == "cancel":
                    await stop_request(conn, UUID(payload["job_id"]))
            if change not in {"cancel", "timeout"}:
                fixture.release.set()
            await asyncio.wait_for(task, 4)
            fixture.release.set()
        value = await result(pool, payload)
        assert fixture.count == 1
        assert value["validation"]["state"] != "valid"
        assert value["reason_code"] == expected
        assert value["budget_consumed"]["http_requests"] == 1
    exercise(scenario)


@pytest.mark.parametrize("mode", ["queued_cancel", "expired", "changed", "missing_key", "recovery", "stale_worker"])
def test_no_wire_after_admission_loss(monkeypatch, mode):
    async def scenario(pool, store, config):
        fixture = Fixture()
        server, payload, config, _ = await prepare(pool, store, config, fixture, monkeypatch)
        job_id = UUID(payload["job_id"])
        async with pool.acquire() as conn, conn.transaction():
            if mode == "queued_cancel":
                await stop_request(conn, job_id)
            elif mode == "expired":
                await conn.execute("UPDATE credential_profiles SET expires_at=NOW() WHERE id=$1", config.credential_reference)
            elif mode == "changed":
                await conn.execute("UPDATE credential_profiles SET record_version=record_version+1 WHERE id=$1", config.credential_reference)
            elif mode == "missing_key":
                monkeypatch.setattr(secret_store, "_fernet", Fernet(Fernet.generate_key()))
            elif mode == "recovery":
                await claim_request(conn, job_id, "crashed-worker", "fixture-build")
                events = await recover_stale_reservations(conn, now=datetime.now(timezone.utc)+timedelta(seconds=100))
                assert events[0].execution_uncertain
        async with server:
            await process_validation_job(payload, pool=pool, worker_id="fixture-worker", build_fingerprint="stale" if mode == "stale_worker" else "fixture-build")
        value = await result(pool, payload)
        assert fixture.count == 0
        assert value["status"] in {"failed", "cancelled"}
        assert value["budget_consumed"]["http_requests"] == (1 if mode == "recovery" else 0)
        assert value["validation"] is None or value["validation"]["state"] != "valid"
    exercise(scenario)


def test_validation_api_admission_queue_and_cancel(monkeypatch):
    async def scenario(pool, store, config):
        from api import api as app_module
        from authenticated_assurance import router as routes
        import httpx

        fixture = Fixture()
        server, first, config, approval_id = await prepare(pool, store, config, fixture, monkeypatch)
        async with pool.acquire() as conn, conn.transaction():
            first_id = UUID(first["job_id"])
            binding = await conn.fetchval("SELECT target_binding_json FROM authentication_validation_requests WHERE id=$1", first_id)
            binding = json.loads(binding)
            await stop_request(conn, first_id)
            await conn.execute("UPDATE authentication_validation_requests SET created_at=NOW()-INTERVAL '1 minute' WHERE id=$1", first_id)

        async def approve(conn, receipt, **kwargs):
            assert receipt == str(approval_id) and kwargs["required_action_name"] == ACTION_NAME
            return {"scope_receipt_id": binding["scope_receipt_id"]}

        async def freeze(**kwargs):
            return binding

        queued = []
        monkeypatch.setattr(routes, "_engine", {"approve": approve, "freeze": freeze, "enqueue": queued.append, "build": lambda: "fixture-build"})
        monkeypatch.setattr(app_module.app.state, "db_pool", pool, raising=False)
        monkeypatch.setenv("SHAKERSCAN_AUTHENTICATED_ASSURANCE", "1")
        monkeypatch.setenv("SHAKERSCAN_BIND_HOST", "127.0.0.1")
        url = f"/authenticated-scan-profiles/{config.credential_reference}/validate"
        body = {"expected_revision": 1, "approval_receipt_id": str(approval_id), "reviewed": True, "allow_insecure_transport": True}
        async with server, httpx.AsyncClient(transport=httpx.ASGITransport(app=app_module.app), base_url="http://localhost") as client:
            bad = await client.post(url, json={**body, "secret": SECRET})
            assert bad.status_code == 422 and SECRET not in bad.text
            denied = await client.post(url, json={**body, "allow_insecure_transport": False})
            assert denied.status_code == 409
            stale = await client.post(url, json={**body, "expected_revision": 2})
            assert stale.status_code == 409
            from authenticated_assurance.evaluation import evaluate_health_response
            async with pool.acquire() as conn, conn.transaction():
                await store.record(conn, evaluate_health_response(config, revision=1, credential_version=1,
                    credential_record_version=1, checked_at=datetime.now(timezone.utc),
                    process_generation=routes.PROCESS_GENERATION, status_code=200,
                    response_url=config.credential_destinations[0] + "/me", content_type="application/json",
                    body=b'{"id":"test-user"}'))
            profile_url = f"/authenticated-scan-profiles/{config.credential_reference}"
            assert (await client.get(profile_url)).json()["assurance"]["state"] == "valid"
            started = await client.post(url, json=body)
            assert started.status_code == 202, started.text
            assert len(queued) == 1 and fixture.count == 0
            pending = (await client.get(profile_url)).json()
            assert pending["assurance"]["state"] == "unknown"
            assert pending["assurance"]["reason_code"] == "validation_pending"
            assert pending["assurance"]["last_validated_at"] is not None
            history = await client.get(profile_url + "/history?limit=2")
            assert history.status_code == 200
            assert history.json()["records"][0]["request_id"] == started.json()["request_id"]
            assert history.json()["records"][0]["state"] == "unknown"
            assert SECRET not in history.text
            assert set(queued[0]) == {"type", "job_id", "validation_id"}
            limited = await client.post(url, json=body)
            assert limited.status_code == 429
            status_url = started.json()["status_url"]
            cancelled = await client.post(status_url + "/cancel")
            assert cancelled.status_code == 200
            assert cancelled.json()["status"] == "cancelled"
            await process_validation_job(queued[0], pool=pool, worker_id="fixture-worker")
            assert fixture.count == 0
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_module.app, client=("8.8.8.8", 1234)), base_url="http://localhost") as remote:
            assert (await remote.post(url, json=body)).status_code == 403
    exercise(scenario)
