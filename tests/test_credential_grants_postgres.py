"""Credential grants on real PostgreSQL: one profile, many targets, by explicit operator grant.

Only CREDENTIAL_GRANTS_TEST_DATABASE_URL on localhost/shakerscan_credential_grants_test is
permitted. Its public schema is RESET at module setup and only the credential store's own
schema is installed: these tests exercise the grant SQL itself, not a fake of it.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import json
import os
import uuid

import pytest

from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get("CREDENTIAL_GRANTS_TEST_DATABASE_URL")
REQUIRED = os.environ.get("CREDENTIAL_GRANTS_POSTGRES_REQUIRED") == "1"
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable credential PostgreSQL database"
)

from api.runtime.credential_store import (  # noqa: E402
    CREDENTIAL_PROFILE_SCHEMA_SQL,
    CredentialStoreError,
    PostgresCredentialProfileStore,
)

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
HOME = uuid.UUID("11111111-1111-4111-8111-111111111111")
SHARED = uuid.UUID("22222222-2222-4222-8222-222222222222")
OTHER = uuid.UUID("33333333-3333-4333-8333-333333333333")
DEVICE = uuid.UUID("44444444-4444-4444-8444-444444444444")
STORE = PostgresCredentialProfileStore()


def _configuration():
    return {"schema_version": 1, "auth_kind": "bearer_token", "secret_configured": True,
            "secret_values_visible": False}


def run(scenario):
    dsn = require_disposable_database(DSN or "", "shakerscan_credential_grants_test")

    async def go():
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
            await STORE.ensure_schema(conn)
            return await scenario(conn)
        finally:
            await conn.close()

    return asyncio.run(go())


async def _profile(conn, *, capabilities=("request.replay",), target=HOME, kind="api"):
    return await STORE.create_profile(
        conn, target_kind=kind, target_id=target, name=f"profile-{uuid.uuid4().hex[:6]}",
        auth_kind="bearer_token", principal_slot="primary", principal_label="alice",
        configuration=_configuration(), encrypted_secret="enc:fernet:secret",
        encrypted_metadata="enc:fernet:metadata", expires_at=NOW + timedelta(days=30),
        allowed_capabilities=list(capabilities), created_by="test", now=NOW,
    )


async def _loads(conn, profile_id, *, target, kind="api", capability="request.replay"):
    try:
        loaded = await STORE.load_for_worker(
            conn, profile_id=profile_id, target_kind=kind, target_id=target, capability=capability,
        )
    except CredentialStoreError:
        return None
    return loaded.metadata.granted_target_id


def test_a_profile_serves_its_home_target_and_only_targets_it_was_granted_to():
    async def scenario(conn):
        profile = await _profile(conn)
        pid = profile.profile_id
        assert await _loads(conn, pid, target=HOME) == str(HOME)
        assert await _loads(conn, pid, target=SHARED) is None
        assert not await STORE.has_active_grant(conn, profile_id=pid, target_kind="api", target_id=SHARED)

        grant = await STORE.grant_profile(conn, profile_id=pid, target_kind="web", target_id=SHARED,
                                          granted_by="operator@example.test", now=NOW)
        assert grant["active"] and grant["granted_by"] == "operator@example.test" and not grant["home"]
        # Web, api and network are one asset: the api profile serves a web view of the target.
        assert await _loads(conn, pid, target=SHARED, kind="web") == str(SHARED)
        assert await STORE.has_active_grant(conn, profile_id=pid, target_kind="web", target_id=SHARED)
        # Still nowhere else.
        assert await _loads(conn, pid, target=OTHER) is None

        listed = await STORE.list_profiles(conn, target_kind="web", target_id=SHARED)
        assert [(item.profile_id, item.shared, item.target_id) for item in listed] == [(pid, True, str(HOME))]
        own = await STORE.list_profiles(conn, target_kind="api", target_id=HOME)
        assert [(item.profile_id, item.shared) for item in own] == [(pid, False)]

        with pytest.raises(CredentialStoreError, match="cannot be shared with a device target"):
            await STORE.grant_profile(conn, profile_id=pid, target_kind="device", target_id=DEVICE,
                                      granted_by="operator", now=NOW)
        with pytest.raises(CredentialStoreError, match="already belongs to this target"):
            await STORE.grant_profile(conn, profile_id=pid, target_kind="api", target_id=HOME,
                                      granted_by="operator", now=NOW)
    run(scenario)


def test_a_revoked_grant_stays_revoked_through_deactivation_and_reactivation():
    async def scenario(conn):
        profile = await _profile(conn)
        pid = profile.profile_id
        await STORE.grant_profile(conn, profile_id=pid, target_kind="api", target_id=SHARED, granted_by="op", now=NOW)
        await STORE.grant_profile(conn, profile_id=pid, target_kind="api", target_id=OTHER, granted_by="op", now=NOW)
        revoked = await STORE.revoke_grant(conn, profile_id=pid, target_id=SHARED, now=NOW + timedelta(minutes=1))
        assert not revoked["active"] and revoked["revoked_at"] is not None
        assert await _loads(conn, pid, target=SHARED) is None
        assert await STORE.list_profiles(conn, target_kind="api", target_id=SHARED) == []

        current = await STORE.get_profile(conn, profile_id=pid)
        await STORE.deactivate_profile(conn, profile_id=pid, target_kind="api", target_id=HOME, now=NOW + timedelta(minutes=2))
        assert await _loads(conn, pid, target=HOME) is None
        assert await _loads(conn, pid, target=OTHER) is None

        current = await STORE.get_profile(conn, profile_id=pid)
        await STORE.update_profile_metadata(
            conn, profile_id=pid, expected_record_version=current.record_version, name=current.name,
            principal_label=current.principal_label, principal_slot=current.principal_slot,
            expires_at=None, expires_at_changed=False, is_active=True, allowed_capabilities=None,
            now=NOW + timedelta(minutes=3),
        )
        assert await _loads(conn, pid, target=HOME) == str(HOME)
        assert await _loads(conn, pid, target=OTHER) == str(OTHER)
        # Reactivating the profile never restores a share the operator revoked.
        assert await _loads(conn, pid, target=SHARED) is None
        await STORE.grant_profile(conn, profile_id=pid, target_kind="api", target_id=SHARED, granted_by="op", now=NOW + timedelta(minutes=4))
        assert await _loads(conn, pid, target=SHARED) == str(SHARED)

        with pytest.raises(CredentialStoreError, match="home target cannot be revoked"):
            await STORE.revoke_grant(conn, profile_id=pid, target_id=HOME, now=NOW)
    run(scenario)


def test_capabilities_follow_the_profile_to_every_grant():
    async def scenario(conn):
        profile = await _profile(conn, capabilities=("request.replay",))
        pid = profile.profile_id
        await STORE.grant_profile(conn, profile_id=pid, target_kind="api", target_id=SHARED, granted_by="op", now=NOW)
        assert await _loads(conn, pid, target=SHARED, capability="web.crawl") is None
        current = await STORE.get_profile(conn, profile_id=pid)
        await STORE.update_profile_metadata(
            conn, profile_id=pid, expected_record_version=current.record_version, name=current.name,
            principal_label=current.principal_label, principal_slot=current.principal_slot,
            expires_at=None, expires_at_changed=False, is_active=True,
            allowed_capabilities=["request.replay", "web.crawl"], now=NOW + timedelta(minutes=1),
        )
        assert await _loads(conn, pid, target=SHARED, capability="web.crawl") == str(SHARED)
    run(scenario)


def test_an_inactive_profile_cannot_be_shared_and_the_library_counts_shares():
    async def scenario(conn):
        shared = await _profile(conn)
        alone = await _profile(conn)
        await STORE.grant_profile(conn, profile_id=shared.profile_id, target_kind="api", target_id=SHARED, granted_by="op", now=NOW)
        await STORE.grant_profile(conn, profile_id=shared.profile_id, target_kind="network", target_id=OTHER, granted_by="op", now=NOW)
        library, total = await STORE.list_library(conn)
        counts = {profile.profile_id: count for profile, count in library}
        assert total == 2 and counts == {shared.profile_id: 2, alone.profile_id: 0}

        grants = await STORE.list_grants(conn, profile_id=shared.profile_id)
        assert [(grant["target_id"], grant["home"]) for grant in grants] == [
            (str(HOME), True), (str(SHARED), False), (str(OTHER), False)]

        await STORE.deactivate_profile(conn, profile_id=alone.profile_id, target_kind="api", target_id=HOME, now=NOW)
        with pytest.raises(CredentialStoreError, match="inactive credential profile cannot be shared"):
            await STORE.grant_profile(conn, profile_id=alone.profile_id, target_kind="api", target_id=SHARED, granted_by="op", now=NOW)
        rows = await conn.fetch("SELECT binding_id, granted_by FROM credential_profile_bindings WHERE binding_id=$1", str(OTHER))
        assert [json.loads(json.dumps(dict(row))) for row in rows] == [{"binding_id": str(OTHER), "granted_by": "op"}]
    run(scenario)


# --- The grant routes, on the same database ------------------------------------------------------

def _routes(scenario):
    """A real FastAPI app over the credential router; the pool lives in the app's own loop."""
    dsn = require_disposable_database(DSN or "", "shakerscan_credential_grants_test")
    from contextlib import asynccontextmanager

    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient

    import api.credential_api as credential_api

    approvals: list[tuple[str | None, str]] = []

    async def validate_approval(conn, receipt_id, *, target_id, **_):
        approvals.append((receipt_id, str(target_id)))
        if receipt_id != "receipt-for-shared-target":
            raise HTTPException(status_code=403, detail="active capabilities need this target's approval")

    async def prepare():
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
            await STORE.ensure_schema(conn)
            await conn.execute("""
                CREATE TABLE targets (id UUID PRIMARY KEY, name TEXT, url TEXT, is_active BOOLEAN DEFAULT true);
                CREATE TABLE device_targets (id UUID PRIMARY KEY, name TEXT, primary_locator TEXT, is_active BOOLEAN DEFAULT true);
            """)
            for target, name in ((HOME, "home.example.test"), (SHARED, "shared.example.test"), (OTHER, "other.example.test")):
                await conn.execute("INSERT INTO targets (id, name, url) VALUES ($1, $2, $3)", target, name, f"https://{name}")
            await conn.execute("INSERT INTO device_targets (id, name, primary_locator) VALUES ($1, 'router', '10.0.0.1')", DEVICE)
            passive = await _profile(conn, capabilities=("http.request",))
            active = await _profile(conn, capabilities=("request.replay",))
            return passive.profile_id, active.profile_id
        finally:
            await conn.close()

    passive_id, active_id = asyncio.run(prepare())

    @asynccontextmanager
    async def lifespan(app):
        app.state.db_pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2)
        yield
        await app.state.db_pool.close()

    app = FastAPI(lifespan=lifespan)
    app.include_router(credential_api.router)
    credential_api.configure_credential_api(approval_validator=validate_approval)
    with TestClient(app) as client:
        scenario(client, passive_id, active_id, approvals)


def test_grant_routes_share_list_and_revoke_with_target_names():
    def scenario(client, passive_id, _active_id, _approvals):
        shared = client.post(f"/credential-profiles/{passive_id}/grants",
                             json={"target_kind": "web", "target_id": str(SHARED), "granted_by": "operator"})
        assert shared.status_code == 201, shared.text
        assert shared.json()["grant"]["target_name"] == "shared.example.test"

        listed = client.get("/credential-profiles", params={"target_kind": "web", "target_id": str(SHARED)}).json()
        assert [(item["id"], item["shared"], item["home_target_name"]) for item in listed["profiles"]] == [
            (passive_id, True, "home.example.test")]

        library = client.get("/credential-profiles").json()
        counts = {item["id"]: item["shared_target_count"] for item in library["profiles"]}
        assert counts[passive_id] == 1 and library["total"] == 2

        grants = client.get(f"/credential-profiles/{passive_id}/grants").json()["grants"]
        assert [(grant["target_name"], grant["home"]) for grant in grants] == [
            ("home.example.test", True), ("shared.example.test", False)]

        assert client.delete(f"/credential-profiles/{passive_id}/grants/{SHARED}").status_code == 200
        listed = client.get("/credential-profiles", params={"target_kind": "web", "target_id": str(SHARED)}).json()
        assert listed["profiles"] == []
        # The home target is removed by deactivating the profile, not by revoking it.
        assert client.delete(f"/credential-profiles/{passive_id}/grants/{HOME}").status_code == 422
        # A device is a different asset; a missing target is not granted anything.
        assert client.post(f"/credential-profiles/{passive_id}/grants",
                           json={"target_kind": "device", "target_id": str(DEVICE)}).status_code == 422
        assert client.post(f"/credential-profiles/{passive_id}/grants",
                           json={"target_kind": "web", "target_id": str(uuid.uuid4())}).status_code == 404
        assert client.get("/credential-profiles", params={"target_kind": "web"}).status_code == 422
    _routes(scenario)


def test_sharing_active_capabilities_needs_the_receiving_targets_approval():
    def scenario(client, passive_id, active_id, approvals):
        refused = client.post(f"/credential-profiles/{active_id}/grants",
                              json={"target_kind": "api", "target_id": str(SHARED)})
        assert refused.status_code == 403
        assert approvals[-1] == (None, str(SHARED))
        allowed = client.post(f"/credential-profiles/{active_id}/grants",
                              json={"target_kind": "api", "target_id": str(SHARED),
                                    "approval_receipt_id": "receipt-for-shared-target"})
        assert allowed.status_code == 201, allowed.text
        # A passive profile needs no approval to be shared.
        count = len(approvals)
        assert client.post(f"/credential-profiles/{passive_id}/grants",
                           json={"target_kind": "api", "target_id": str(OTHER)}).status_code == 201
        assert len(approvals) == count
    _routes(scenario)


# --- Reusing a live login across runs ------------------------------------------------------------

def test_a_live_login_is_reused_only_for_the_same_target_credential_version_and_origin(monkeypatch):
    from cryptography.fernet import Fernet
    import secret_store

    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, "_fernet", None)
    monkeypatch.setattr(secret_store, "_loaded", False)
    from capabilities.auth import TargetBoundSessionCredential
    from capabilities.session_reuse import reuse_or_establish_session
    from runtime.auth_session_store import AUTH_SESSION_SCHEMA_SQL
    from runtime.models import TargetBinding

    origin = "https://app.example.test"

    def target_for(target_id):
        return TargetBinding(
            target_id=str(target_id), target_kind="web", canonical_host="app.example.test",
            allowed_origins=(origin,), allowed_addresses=("192.0.2.10",),
            allowed_root_domains=("example.test",), environment="test", scope_receipt_id="scope-new-run",
        )

    async def scenario(conn):
        await conn.execute(AUTH_SESSION_SCHEMA_SQL)
        # The service-origin column comes from the Hunt session migration (which also touches
        # unrelated graph tables this database does not have).
        await conn.execute("ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS service_origin TEXT")
        configuration = {"schema_version": 1, "auth_kind": "form_login", "secret_configured": True,
                         "username_configured": True, "endpoint_configured": True, "secret_values_visible": False}
        profile = await STORE.create_profile(
            conn, target_kind="web", target_id=HOME, name="login", auth_kind="form_login",
            principal_slot="primary", principal_label="alice", configuration=configuration,
            encrypted_secret="enc:fernet:x", encrypted_metadata="enc:fernet:y", expires_at=NOW + timedelta(days=30),
            allowed_capabilities=["auth.session.establish", "http.request"], created_by="test", now=NOW,
        )
        await STORE.grant_profile(conn, profile_id=profile.profile_id, target_kind="web", target_id=SHARED,
                                  granted_by="op", now=NOW)

        async def store_session(target_id, *, expires_in=timedelta(hours=1), service_origin=origin, version=1):
            await conn.execute(
                """INSERT INTO auth_sessions (id, owner_kind, owner_id, target_kind, target_id, target_binding_digest,
                       service_origin, profile_id, profile_version, principal_slot, principal_label, auth_kind,
                       compatible_capabilities, encrypted_headers, status, established_at, expires_at, refresh_after,
                       evidence_receipt_digest, source_action_id)
                   VALUES ($1,'hunt',$2,'web',$3,$4,$5,$6,$7,'primary','alice','form_login','["http.request"]'::jsonb,
                           $8,'active',$9,$10,$11,$12,$13)""",
                uuid.uuid4(), uuid.uuid4(), target_id, "a" * 64, service_origin, uuid.UUID(profile.profile_id), version,
                secret_store.encrypt_secret(json.dumps({"Cookie": f"sid={target_id}"})),
                NOW - timedelta(minutes=10), NOW + expires_in, NOW + min(expires_in, timedelta(minutes=30)) - timedelta(seconds=1),
                "b" * 64, uuid.uuid4(),
            )

        class Pool:
            @asynccontextmanager
            async def acquire(self):
                yield conn

        async def reused(target_id, *, version=1, endpoint=f"{origin}/login"):
            target = target_for(target_id)
            credential = TargetBoundSessionCredential(
                lane="primary", auth_kind="form_login", endpoint_url=endpoint, binding_digest=target.digest,
                username="alice", secret="never-sent", profile_id=profile.profile_id, profile_version=version,
                principal="alice", compatible_capabilities=("http.request",),
            )

            async def login(_credential, *, target):
                return None

            session = await reuse_or_establish_session(Pool(), credential, target=target, now=NOW, establish=login)
            return session.headers() if session is not None else None

        await store_session(HOME)
        assert await reused(HOME) == {"Cookie": f"sid={HOME}"}
        # A login is bound to the target it was made on, even when the credential is shared.
        assert await reused(SHARED) is None
        await store_session(SHARED)
        assert await reused(SHARED) == {"Cookie": f"sid={SHARED}"}
        # Revoking the share stops reuse there at once.
        await STORE.revoke_grant(conn, profile_id=profile.profile_id, target_id=SHARED, now=NOW)
        assert await reused(SHARED) is None
        # A different service origin, or too little time left, is not reused.
        await conn.execute("UPDATE auth_sessions SET service_origin='https://other.example.test' WHERE target_id=$1", HOME)
        assert await reused(HOME) is None
        await conn.execute("UPDATE auth_sessions SET service_origin=$2 WHERE target_id=$1", HOME, origin)
        await conn.execute("UPDATE auth_sessions SET expires_at=$2, refresh_after=$3 WHERE target_id=$1",
                           HOME, NOW + timedelta(minutes=3), NOW + timedelta(minutes=2))
        assert await reused(HOME) is None
        await conn.execute("UPDATE auth_sessions SET expires_at=$2, refresh_after=$3 WHERE target_id=$1",
                           HOME, NOW + timedelta(hours=1), NOW + timedelta(minutes=30))
        assert await reused(HOME) == {"Cookie": f"sid={HOME}"}
        # A rotated credential never reuses a login made with its previous version.
        await STORE.rotate_profile(conn, profile_id=profile.profile_id, target_kind="web", target_id=HOME,
                                   expected_record_version=(await STORE.get_profile(conn, profile_id=profile.profile_id)).record_version,
                                   encrypted_secret="enc:fernet:z", encrypted_metadata="enc:fernet:w",
                                   configuration=configuration, expires_at=NOW + timedelta(days=30),
                                   created_by="test", now=NOW + timedelta(seconds=1))
        assert await reused(HOME, version=2) is None
    run(scenario)
