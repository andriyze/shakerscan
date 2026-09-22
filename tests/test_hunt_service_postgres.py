"""Real PostgreSQL acceptance for Hunt service sessions and device-owned graph records.

Only an explicitly disposable test database is accepted. Tables live in a fresh
per-test schema; cleanup drops only that schema. No external scan is executed.
"""
import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet

asyncpg = pytest.importorskip("asyncpg")
DSN = os.environ.get("ASSURANCE_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="requires disposable PostgreSQL")

from tests.disposable_postgres import require_disposable_database
from api.runtime import auth_session_store as sessions
from api.runtime.credential_resolver import CredentialResolutionError
from api.runtime.credential_store import PostgresCredentialProfileStore
from api.runtime.hunt_service_schema import HUNT_SERVICE_SCHEMA_SQL
from api.runtime.models import TargetBinding
from api.hunt.authorization_repository import PostgresAuthorizationRepository, PROPOSAL_TYPE


@pytest.mark.parametrize("kind", ["web", "network", "device"])
def test_device_schema_session_roundtrip_and_graph_owner(monkeypatch, kind):
    key = Fernet(Fernet.generate_key())
    monkeypatch.setattr(sessions, "encrypt_secret", lambda s: "enc:fernet:" + key.encrypt(s.encode()).decode())
    monkeypatch.setattr(sessions, "decrypt_secret", lambda s: key.decrypt(s.removeprefix("enc:fernet:").encode()).decode())

    async def scenario():
        conn = await asyncpg.connect(require_disposable_database(DSN, "shakerscan_assurance_test"))
        schema = "pr204_" + uuid4().hex
        try:
            await conn.execute(f'CREATE SCHEMA "{schema}"; SET search_path TO "{schema}"')
            await conn.execute("CREATE TABLE targets(id UUID PRIMARY KEY)")
            await conn.execute("CREATE TABLE device_targets(id UUID PRIMARY KEY)")
            await conn.execute("""CREATE TABLE application_graph_nodes (
                id UUID PRIMARY KEY, target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
                node_type TEXT NOT NULL,node_key TEXT NOT NULL,label TEXT,attributes JSONB,
                UNIQUE(target_id,node_type,node_key))""")
            await conn.execute("""CREATE TABLE hunt_runs (
                id UUID PRIMARY KEY,target_id UUID,device_target_id UUID,target_kind TEXT,
                status TEXT,context_pack JSONB,policy_json JSONB)""")
            await conn.execute("""CREATE TABLE scope_receipts (
                id TEXT PRIMARY KEY,target_id UUID,verdict TEXT);
                CREATE TABLE approval_receipts (
                id UUID PRIMARY KEY,scope_receipt_id TEXT,risk_tier TEXT,confirmations JSONB,
                approved_by TEXT,denial_reason TEXT,expires_at TIMESTAMPTZ,
                action_name TEXT,status TEXT,revoked_at TIMESTAMPTZ)""")
            credentials = PostgresCredentialProfileStore()
            await credentials.ensure_schema(conn)
            store = sessions.PostgresAuthSessionStore()
            await store.ensure_schema(conn)
            await conn.execute(HUNT_SERVICE_SCHEMA_SQL)
            await conn.execute(HUNT_SERVICE_SCHEMA_SQL)
            owner, target_id, profile_id, action, graph_id, approval_id = [uuid4() for _ in range(6)]
            await conn.execute(f"INSERT INTO {'device_targets' if kind == 'device' else 'targets'} VALUES($1)", target_id)
            now = datetime.now(timezone.utc)
            await credentials.create_profile(conn, profile_id=profile_id, target_kind=kind, target_id=target_id,
                name="Synthetic service", auth_kind="json_login", principal_slot="primary", principal_label="Fixture",
                configuration={"auth_kind": "json_login", "secret_values_visible": False}, encrypted_secret="enc:fernet:synthetic", encrypted_metadata="enc:fernet:synthetic",
                expires_at=now+timedelta(hours=2), allowed_capabilities=["http.request", "auth.session.refresh"], now=now)
            target = TargetBinding(target_id=str(target_id), target_kind=kind, canonical_host="fixture.test",
                                   allowed_origins=("https://fixture.test:8443",), allowed_addresses=("127.0.0.1",),
                                   allowed_root_domains=("fixture.test",), scope_receipt_id="scope")
            context = {"target": {"url": target.allowed_origins[0], "origins": list(target.allowed_origins)},
                       "authorized_target_addresses": list(target.allowed_addresses)}
            policy = {"active_testing": True, "network_discovery": False,
                      "scope_receipt_id": "scope", "approval_receipt_id": str(approval_id)}
            await conn.execute("INSERT INTO hunt_runs VALUES($1,$2,$3,$4,'active',$5::jsonb,$6::jsonb)",
                               owner, None if kind == "device" else target_id, target_id if kind == "device" else None,
                               kind, json.dumps(context), json.dumps(policy))
            await conn.execute("INSERT INTO scope_receipts VALUES('scope',$1,'allowed')", target_id)
            await conn.execute("""INSERT INTO approval_receipts VALUES (
                $1,'scope','active','["confirm_authorized"]','fixture',NULL,NULL,
                'target.authorization','active',NULL)""", approval_id)
            metadata = await store.create(conn, owner_kind="hunt", owner_id=owner, target=target,
                profile_id=profile_id, profile_version=1, principal_slot="primary", principal_label="Fixture", auth_kind="json_login",
                compatible_capabilities=["http.request", "auth.session.refresh"], headers={"Cookie": "session=synthetic"},
                established_at=now, expires_at=now+timedelta(hours=1), refresh_after=now+timedelta(minutes=50),
                evidence_receipt_digest="a"*64, source_action_id=action, service_origin=target.allowed_origins[0])
            alternate = replace(target, allowed_origins=("https://fixture.test:9443",))
            loaded = await store.load_for_worker(conn, session_ref=metadata.session_ref, owner_kind="hunt", owner_id=owner,
                                               target=alternate, capability="http.request")
            assert loaded.headers() == {"Cookie": "session=synthetic"}
            loaded.close()
            refreshed = await store.load_for_refresh(conn, session_ref=metadata.session_ref, owner_kind="hunt", owner_id=owner, target=alternate)
            assert refreshed.service_origin == "https://fixture.test:8443"
            with pytest.raises(sessions.AuthSessionStoreError):
                await store.load_for_worker(conn, session_ref=metadata.session_ref, owner_kind="hunt", owner_id=owner,
                    target=replace(alternate, allowed_addresses=("127.0.0.2",)), capability="http.request")
            await conn.execute("UPDATE approval_receipts SET status='revoked' WHERE id=$1", approval_id)
            with pytest.raises(CredentialResolutionError):
                await store.load_for_worker(conn, session_ref=metadata.session_ref, owner_kind="hunt", owner_id=owner,
                                            target=alternate, capability="http.request")
            repository = PostgresAuthorizationRepository()
            run = await repository.run(conn, owner)
            await repository.insert_node(conn, run, graph_id, PROPOSAL_TYPE, "synthetic", {"hunt_id": str(owner)})
            row = await conn.fetchrow("SELECT target_id,device_target_id FROM application_graph_nodes WHERE id=$1", graph_id)
            assert row["device_target_id" if kind == "device" else "target_id"] == target_id
            assert row["target_id" if kind == "device" else "device_target_id"] is None
            await conn.execute(f"DELETE FROM {'device_targets' if kind == 'device' else 'targets'} WHERE id=$1", target_id)
            assert await conn.fetchval("SELECT count(*) FROM application_graph_nodes") == 0
        finally:
            await conn.execute(f'SET search_path TO public; DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            await conn.close()
    asyncio.run(scenario())
