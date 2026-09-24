"""Opt-in real persistence tests. No health requests or scan submissions."""
import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "api"), str(ROOT / "scanner")]

import pytest

from tests.disposable_postgres import require_disposable_database
from api.runtime.credential_store import PostgresCredentialProfileStore
from api.authenticated_assurance.models import ProfileConfiguration, ProfileWrite
from api.authenticated_assurance.store import AssuranceStore, ProfileConflict
from api.authenticated_assurance.evaluation import evaluate_health_response

asyncpg = pytest.importorskip("asyncpg")
DSN = os.environ.get("ASSURANCE_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="requires disposable assurance PostgreSQL database")


def exercise(scenario):
    async def run():
        dsn = require_disposable_database(DSN, "shakerscan_assurance_test")
        async with asyncpg.create_pool(dsn, min_size=1, max_size=4) as pool:
            async with pool.acquire() as conn:
                await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
                await conn.execute("CREATE TABLE targets(id UUID PRIMARY KEY, url TEXT NOT NULL, is_active BOOLEAN NOT NULL DEFAULT true)")
                credential_store = PostgresCredentialProfileStore()
                await credential_store.ensure_schema(conn)
                store = AssuranceStore()
                await store.ensure_schema(conn)
                # An upgrade is idempotent and additive.
                await store.ensure_schema(conn)
                target = uuid4()
                await conn.execute("INSERT INTO targets(id,url) VALUES($1,'https://fixture.example.test')", target)
                async with conn.transaction():
                    credential = await credential_store.create_profile(
                        conn, target_kind="web", target_id=target, name="Fixture", auth_kind="bearer_token",
                        principal_slot="primary", principal_label="Fixture user",
                        configuration={"auth_kind": "bearer_token", "secret_values_visible": False},
                        encrypted_secret="enc:fernet:synthetic-ciphertext", encrypted_metadata="enc:fernet:synthetic-metadata",
                        expires_at=None, now=datetime.now(timezone.utc),
                    )
                config = ProfileConfiguration(
                    target_id=target, credential_reference=credential.profile_id, display_name="Fixture",
                    environment_label="lab", credential_destinations=["https://fixture.example.test"],
                    validation_policy={"path": "/me", "identity_field": "id", "expected_identity": "test-user", "owner_confirmed_read_only": True},
                )
            await scenario(pool, store, config)
    asyncio.run(run())


async def write(pool, store, config, expected=0):
    async with pool.acquire() as conn, conn.transaction():
        return await store.write(conn, ProfileWrite(configuration=config, expected_revision=expected, reviewed=True), actor="fixture")


def test_atomic_edits_and_immutable_history():
    async def scenario(pool, store, config):
        first = await write(pool, store, config)
        changed = ProfileConfiguration.model_validate({**config.model_dump(), "display_name": "Changed"})
        outcomes = await asyncio.gather(write(pool, store, changed, 1), write(pool, store, changed, 1), return_exceptions=True)
        assert sum(isinstance(result, ProfileConflict) for result in outcomes) == 1
        async with pool.acquire() as conn:
            historical = await store.get(conn, config.credential_reference, revision=1)
            assert historical["configuration_digest"] == first["configuration_digest"]
            assert historical["configuration"]["display_name"] == "Fixture"
            assert await conn.fetchval("SELECT COUNT(*) FROM authenticated_profile_revisions") == 2
    exercise(scenario)


def test_revocation_rejects_inflight_validity_and_duplicate_conflicts():
    async def scenario(pool, store, config):
        await write(pool, store, config)
        record = evaluate_health_response(config, revision=1, credential_version=1, credential_record_version=1,
            checked_at=datetime.now(timezone.utc), process_generation=uuid4(), status_code=200,
            response_url="https://fixture.example.test/me", content_type="application/json", body=b'{"id":"test-user"}')
        async with pool.acquire() as conn, conn.transaction():
            await conn.execute("UPDATE credential_profiles SET is_active=false WHERE id=$1", config.credential_reference)
        async with pool.acquire() as conn, conn.transaction():
            saved = await store.record(conn, record)
            assert saved.state == "revoked"
            assert await store.record(conn, record) == saved
            assert await conn.fetchval("SELECT COUNT(*) FROM authentication_validations") == 1
    exercise(scenario)


def test_destination_and_target_boundaries():
    async def scenario(pool, store, config):
        for changes in [{"target_id": uuid4()}, {"credential_destinations": ["http://fixture.example.test"]},
                        {"credential_destinations": ["https://fixture.example.test:8443"]}]:
            invalid = ProfileConfiguration.model_validate({**config.model_dump(), **changes})
            with pytest.raises(ProfileConflict):
                await write(pool, store, invalid)
        async with pool.acquire() as conn:
            assert await conn.fetchval("SELECT COUNT(*) FROM authenticated_profile_revisions") == 0
    exercise(scenario)


def test_reactivation_cannot_resurrect_inflight_validity():
    async def scenario(pool, store, config):
        await write(pool, store, config)
        record = evaluate_health_response(config, revision=1, credential_version=1, credential_record_version=1,
            checked_at=datetime.now(timezone.utc), process_generation=uuid4(), status_code=200,
            response_url="https://fixture.example.test/me", content_type="application/json", body=b'{"id":"test-user"}')
        async with pool.acquire() as conn:
            await conn.execute("UPDATE credential_profiles SET is_active=false, record_version=record_version+1 WHERE id=$1", config.credential_reference)
            await conn.execute("UPDATE credential_profiles SET is_active=true, record_version=record_version+1 WHERE id=$1", config.credential_reference)
            async with conn.transaction():
                saved = await store.record(conn, record)
            assert saved.state == "unknown"
            assert saved.reason_code == "credential_changed"
    exercise(scenario)


def test_out_of_order_observations_do_not_replace_latest():
    async def scenario(pool, store, config):
        await write(pool, store, config)
        generation = uuid4()
        records = [evaluate_health_response(config, revision=1, credential_version=1, credential_record_version=1,
            checked_at=datetime(2026, 9, day, tzinfo=timezone.utc), process_generation=generation,
            timed_out=True) for day in (14, 13)]
        for record in records:
            async with pool.acquire() as conn, conn.transaction():
                await store.record(conn, record)
        async with pool.acquire() as conn:
            profile = await store.get(conn, config.credential_reference)
            assert profile["validation"]["validation_id"] == str(records[0].validation_id)
    exercise(scenario)


def test_full_api_redaction_and_preview_authority(monkeypatch):
    async def scenario(pool, store, config):
        import httpx
        from api import api as app_module
        app = app_module.app
        monkeypatch.setattr(app.state, "db_pool", pool, raising=False)
        monkeypatch.setenv("SHAKERSCAN_AUTHENTICATED_ASSURANCE", "1")
        monkeypatch.setenv("SHAKERSCAN_BIND_HOST", "127.0.0.1")
        body = {"configuration": config.model_dump(mode="json"), "expected_revision": 0, "reviewed": True}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            invalid = {**body, "secret": "SEEDED-SECRET-MUST-NOT-BE-ECHOED"}
            response = await client.post("/authenticated-scan-profiles", json=invalid)
            assert response.status_code == 422, response.text
            assert "SEEDED-SECRET" not in response.text
            saved = await client.post("/authenticated-scan-profiles", json=body)
            assert saved.status_code == 200, saved.text
            assert saved.json()["assurance"]["state"] == "unknown"
            assert saved.json()["scan_selection_supported"] is False
            listed = await client.get(f"/authenticated-scan-profiles?target_id={config.target_id}")
            assert listed.status_code == 200
            assert len(listed.json()["profiles"]) == 1
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("8.8.8.8", 1234)), base_url="http://localhost") as remote:
            response = await remote.post("/authenticated-scan-profiles", json=body)
            assert response.status_code == 403
        monkeypatch.setenv("SHAKERSCAN_AUTHENTICATED_ASSURANCE", "0")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            response = await client.post("/authenticated-scan-profiles", json=body)
            assert response.status_code == 404
    exercise(scenario)


def test_validation_owner_migration_preserves_existing_reservation():
    async def scenario(pool, store, config):
        from runtime.reservation_store import PostgresBudgetReservationStore
        from runtime.budget_reservations import DurableBudgetReservation
        reservations = PostgresBudgetReservationStore()
        async with pool.acquire() as conn, conn.transaction():
            await reservations.ensure_schema(conn)
            scan = DurableBudgetReservation.request(owner_kind="scan", owner_id=str(uuid4()),
                capability_name="http.request", amounts={"http_requests": 1})
            before = await reservations.create_requested(conn, action_id="fixture", action_digest="a" * 64, record=scan)
            await conn.execute("""ALTER TABLE budget_reservations DROP CONSTRAINT budget_reservations_owner_kind_check;
                ALTER TABLE budget_reservations ADD CONSTRAINT budget_reservations_owner_kind_check
                CHECK (owner_kind IN ('scan','hunt'))""")
            await reservations.ensure_schema(conn)
            await reservations.ensure_schema(conn)
            after = await reservations.load(conn, scan.reservation_id)
            assert after.record.state_digest == before.record.state_digest
            assert after.record.canonical_dict() == before.record.canonical_dict()
            validation = DurableBudgetReservation.request(owner_kind="validation", owner_id=str(uuid4()),
                capability_name="http.request", amounts={"http_requests": 1})
            saved = await reservations.create_requested(conn, action_id="identity.health", action_digest="b" * 64, record=validation)
            assert saved.record.owner_kind == "validation"
            assert await conn.fetchval("SELECT COUNT(*) FROM app_schema_migrations WHERE name='v2_budget_validation_owner_v1'") == 1
    exercise(scenario)


def test_history_pagination_and_additive_record_compatibility():
    async def scenario(pool, store, config):
        await write(pool, store, config)
        now = datetime.now(timezone.utc)
        records = [evaluate_health_response(config, revision=1, credential_version=1, credential_record_version=1,
            checked_at=now + timedelta(seconds=index), process_generation=uuid4(), timed_out=True) for index in range(5)]
        async with pool.acquire() as conn, conn.transaction():
            for record in reversed(records):
                await store.record(conn, record)
            # A pre-history record lacks the additive request_id field. It must
            # remain readable and idempotent after upgrading the parser.
            await conn.execute("UPDATE authentication_validations SET record_json=record_json-'request_id' WHERE id=$1", records[0].validation_id)
            assert await store.record(conn, records[0]) == records[0]
            first = await store.history(conn, config.credential_reference, limit=2)
            second = await store.history(conn, config.credential_reference, limit=2, before=UUID(first["next_cursor"]))
            third = await store.history(conn, config.credential_reference, limit=2, before=UUID(second["next_cursor"]))
            ids = [row["validation_id"] for page in (first, second, third) for row in page["records"]]
            assert ids == [str(record.validation_id) for record in reversed(records)]
            assert third["next_cursor"] is None
            with pytest.raises(ProfileConflict, match="invalid_history_cursor"):
                await store.history(conn, config.credential_reference, before=uuid4())
    exercise(scenario)


def test_validation_without_credential_capability_is_rejected_before_admission():
    async def scenario(pool, store, config):
        from authenticated_assurance.jobs import ValidationJobs, SCHEMA_SQL
        from authenticated_assurance.models import ValidationRequest
        from authenticated_assurance.store import ProfileConflict as JobConflict
        from runtime.reservation_store import PostgresBudgetReservationStore

        await write(pool, store, config)

        async def forbidden(**kwargs):
            raise AssertionError("Unauthorized validation must not reach approval or DNS resolution")

        async with pool.acquire() as conn, conn.transaction():
            await PostgresBudgetReservationStore().ensure_schema(conn)
            await conn.execute(SCHEMA_SQL)
            with pytest.raises(JobConflict, match="credential_capability_not_allowed"):
                await ValidationJobs().prepare(conn, profile_id=config.credential_reference,
                    request=ValidationRequest(expected_revision=1, approval_receipt_id=uuid4(), reviewed=True),
                    actor="fixture", generation=uuid4(), expected_build_fingerprint="fixture-build",
                    approve=forbidden, freeze=forbidden)
            assert await conn.fetchval("SELECT COUNT(*) FROM authentication_validation_requests") == 0
            assert await conn.fetchval("SELECT COUNT(*) FROM budget_reservations") == 0
    exercise(scenario)


def test_future_worker_timestamp_cannot_resurrect_validity_after_a_new_request():
    async def scenario(pool, store, config):
        from authenticated_assurance.jobs import ValidationJobs, SCHEMA_SQL
        from authenticated_assurance.models import ValidationRequest
        from runtime.reservation_store import PostgresBudgetReservationStore
        from api.authenticated_assurance.models import ValidationRecord
        from api.authenticated_assurance.evaluation import current_assurance

        await write(pool, store, config)
        generation, scope_id = uuid4(), uuid4()
        future = datetime.now(timezone.utc) + timedelta(seconds=60)
        async with pool.acquire() as conn, conn.transaction():
            await PostgresBudgetReservationStore().ensure_schema(conn)
            await conn.execute(SCHEMA_SQL)
            await conn.execute("UPDATE credential_profile_bindings SET allowed_capabilities='[\"http.request\"]'::jsonb WHERE profile_id=$1", config.credential_reference)
            await store.record(conn, evaluate_health_response(config, revision=1, credential_version=1,
                credential_record_version=1, checked_at=future, process_generation=generation, status_code=200,
                response_url="https://fixture.example.test/me", content_type="application/json", body=b'{"id":"test-user"}'))

            async def approve(*args, **kwargs):
                return {"scope_receipt_id": str(scope_id)}

            async def freeze(**kwargs):
                return {"target_id": str(config.target_id), "target_kind": "web", "canonical_host": "fixture.example.test",
                    "allowed_origins": ["https://fixture.example.test"], "allowed_addresses": ["192.0.2.1"], "scope_receipt_id": str(scope_id)}

            await ValidationJobs().prepare(conn, profile_id=config.credential_reference,
                request=ValidationRequest(expected_revision=1, approval_receipt_id=uuid4(), reviewed=True),
                actor="fixture", generation=generation, expected_build_fingerprint="fixture-build", approve=approve, freeze=freeze)
            profile = await store.get(conn, config.credential_reference)
            assert profile["validation"]["reason_code"] == "validation_pending"
            state = current_assurance(ValidationRecord.model_validate(profile["validation"]), revision=1,
                credential_version=1, credential_record_version=1, configuration_digest=config.digest(1, 1),
                now=future+timedelta(seconds=1), process_generation=generation)
            assert state["state"] == "unknown" and state["reason_code"] == "validation_pending"
    exercise(scenario)
