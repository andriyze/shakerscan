"""Hunt credential uses on real PostgreSQL: migration, attached-list SQL and the use ledger.

The Hunt tables come from db/init.sql; the credential tables from the credential store's own
schema; the registered-principal tables are the minimal columns the resolver reads. Secrets are
fixture ciphertext decrypted by ``fixture_decrypt``: no secret store is involved.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
import uuid

import pytest

from hunt.credential_uses import (
    HUNT_CREDENTIAL_USES_SCHEMA_SQL,
    HuntCredentialRefusal,
    admit_action_credentials,
    read_credential_uses,
    record_credential_uses,
)
from hunt.verification_credentials import (
    HuntCredentialScope,
    HuntVerificationCredentialRefused,
    resolve_hunt_workflow_principal_contexts,
)
from runtime.credential_store import PostgresCredentialProfileStore
from runtime.credentials import public_credential_configuration

DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")

ROOT = Path(__file__).resolve().parents[1]
STORE = PostgresCredentialProfileStore()
TARGET, OTHER, THIRD = (uuid.uuid4() for _ in range(3))
SECRETS: dict[str, str] = {}


def fixture_decrypt(value):
    return SECRETS[value]


def _table(ddl: str, name: str) -> str:
    return re.search(rf"CREATE TABLE {name} \(.*?\n\);", ddl, re.S)[0]


async def _schema(conn, schema: str, *, bootstrap: bool) -> None:
    await conn.execute(f'CREATE SCHEMA "{schema}"; SET search_path TO "{schema}"')
    ddl = (ROOT / "db/init.sql").read_text()
    await conn.execute("CREATE TABLE targets(id UUID PRIMARY KEY); CREATE TABLE device_targets(id UUID PRIMARY KEY)")
    for table in ("hunt_runs", "hunt_actions"):
        await conn.execute(_table(ddl, table))
    if bootstrap:  # a fresh install creates the table from db/init.sql
        await conn.execute(_table(ddl, "hunt_credential_uses"))
        await conn.execute(re.search(r"CREATE INDEX idx_hunt_credential_uses_run\n.*?;", ddl, re.S)[0])
    for _ in range(2):  # the startup migration, repeated: idempotent on both paths
        await conn.execute(HUNT_CREDENTIAL_USES_SCHEMA_SQL)


async def _definition(conn, schema: str) -> dict:
    columns = await conn.fetch(
        """SELECT column_name, data_type, is_nullable, column_default
           FROM information_schema.columns WHERE table_schema=$1 AND table_name='hunt_credential_uses'
           ORDER BY column_name""", schema)
    constraints = await conn.fetch(
        """SELECT replace(pg_get_constraintdef(c.oid), quote_ident($1)||'.', '') AS definition
           FROM pg_constraint c
           JOIN pg_namespace n ON n.oid=c.connamespace
           WHERE n.nspname=$1 AND c.conrelid=to_regclass(quote_ident($1)||'.hunt_credential_uses')
           ORDER BY 1""", schema)
    indexes = await conn.fetch(
        """SELECT replace(indexdef, quote_ident($1)||'.', '') AS definition FROM pg_indexes
           WHERE schemaname=$1 AND tablename='hunt_credential_uses' ORDER BY 1""", schema)
    return {
        "columns": [dict(row) for row in columns],
        "constraints": [row["definition"] for row in constraints],
        "indexes": [row["definition"] for row in indexes],
    }


@pytest.mark.asyncio
async def test_fresh_install_and_upgrade_define_the_same_idempotent_table():
    import asyncpg

    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
    conn = await asyncpg.connect(DSN)
    upgrade, fresh = "hunt_cred_up_" + uuid.uuid4().hex, "hunt_cred_new_" + uuid.uuid4().hex
    try:
        await _schema(conn, upgrade, bootstrap=False)
        await _schema(conn, fresh, bootstrap=True)
        assert await _definition(conn, upgrade) == await _definition(conn, fresh)
        definition = await _definition(conn, upgrade)
        assert {c["column_name"] for c in definition["columns"]} == {
            "id", "hunt_run_id", "action_id", "profile_id", "profile_version", "source", "slot", "used_at",
        }
        # Ids and digests only: no column can hold secret material.
        assert not {"secret", "encrypted_secret", "headers", "cookies"} & {
            c["column_name"] for c in definition["columns"]}
    finally:
        await conn.execute(f'DROP SCHEMA IF EXISTS "{upgrade}" CASCADE; DROP SCHEMA IF EXISTS "{fresh}" CASCADE')
        await conn.close()


async def _profile(conn, *, home, slot, name, kind="authorization_header", secret,
                   capabilities=("authz.verify", "http.request"), profile_id=None):
    now = datetime.now(timezone.utc)
    profile_id = profile_id or uuid.uuid4()
    SECRETS[f"enc:fernet:{profile_id}"] = secret
    created = await STORE.create_profile(
        conn, profile_id=profile_id, target_kind="web", target_id=home, name=name, auth_kind=kind,
        principal_slot=slot, principal_label=name,
        configuration=public_credential_configuration({"auth_kind": kind}),
        encrypted_secret=f"enc:fernet:{profile_id}", encrypted_metadata="enc:fernet:metadata",
        expires_at=now + timedelta(days=30), allowed_capabilities=list(capabilities),
        created_by="fixture", now=now - timedelta(minutes=1),
    )
    return created.profile_id


@pytest.mark.asyncio
async def test_attached_credentials_resolve_through_real_grants_and_every_use_is_recorded():
    import asyncpg

    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
    conn = await asyncpg.connect(DSN)
    schema = "hunt_cred_uses_" + uuid.uuid4().hex
    try:
        await _schema(conn, schema, bootstrap=False)
        await STORE.ensure_schema(conn)
        await conn.execute("""
            CREATE TABLE target_credential_profiles (
                id UUID PRIMARY KEY, target_id UUID NOT NULL, name TEXT NOT NULL,
                auth_kind TEXT NOT NULL, secret_value TEXT NOT NULL,
                metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb);
            CREATE TABLE target_principals (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(), target_id UUID NOT NULL,
                label TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', tenant_id TEXT,
                auth_state TEXT NOT NULL, credential_profile TEXT,
                is_active BOOLEAN NOT NULL DEFAULT true,
                metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
        """)
        await conn.executemany("INSERT INTO targets VALUES($1)", [(TARGET,), (OTHER,), (THIRD,)])
        hunt, action, second_action = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        await conn.execute(
            "INSERT INTO hunt_runs(id,target_kind,target_id) VALUES($1,'web',$2)", hunt, TARGET)
        await conn.executemany(
            "INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status) VALUES($1,$2,$3,'running')",
            [(action, hunt, "candidate.verify"), (second_action, hunt, "http.request")])

        # The target's own principal: a legacy profile mirrored under the same id.
        own = await _profile(conn, home=TARGET, slot="primary", name="alice", secret="Bearer own-alice")
        await conn.execute(
            "INSERT INTO target_credential_profiles VALUES($1,$2,'alice','authorization_header','enc:fernet:legacy')",
            uuid.UUID(own), TARGET)
        await conn.execute(
            """INSERT INTO target_principals(target_id,label,auth_state,credential_profile,metadata_json)
               VALUES($1,'alice','user1','alice',$2::jsonb)""",
            TARGET, json.dumps({"captured_refs": {"order_id": "1001"}, "user_id": "alice"}))
        shared = await _profile(conn, home=OTHER, slot="secondary", name="bob", secret="Bearer shared-bob")
        unshared = await _profile(conn, home=THIRD, slot="secondary", name="eve", secret="Bearer eve")
        await STORE.grant_profile(conn, profile_id=shared, target_kind="web", target_id=TARGET,
                                  granted_by="fixture", now=datetime.now(timezone.utc))

        scope = HuntCredentialScope(hunt_id=hunt, action_id=action, target_kind="web", target_id=TARGET)
        decrypted = []

        def spy(value):
            decrypted.append(value)
            return fixture_decrypt(value)

        for _ in range(2):  # resolving again for the same action records nothing new
            contexts = await resolve_hunt_workflow_principal_contexts(
                conn, scope, TARGET, {"user1", "user2"}, decryptor=spy)
        assert contexts["user1"]["headers"] == {"Authorization": "Bearer own-alice"}
        assert contexts["user1"]["captured_refs"] == {"order_id": "1001"}
        assert contexts["user2"]["headers"] == {"Authorization": "Bearer shared-bob"}
        assert f"enc:fernet:{unshared}" not in decrypted
        uses = await read_credential_uses(conn, hunt)
        assert sorted((u["slot"], u["profile_id"], u["profile_version"], u["source"]) for u in uses) == [
            ("primary", own, 1, "target_own"),
            ("secondary", shared, 1, f"shared_from:{OTHER}"),
        ]
        assert all(u["action_id"] == str(action) and u["secret_values_visible"] is False for u in uses)
        assert "shared-bob" not in json.dumps(uses) and "own-alice" not in json.dumps(uses)

        # Selecting the unshared credential is refused with the reason code, never decrypted.
        selected = HuntCredentialScope(
            hunt_id=hunt, action_id=action, target_kind="web", target_id=TARGET,
            credential_refs=({"source": "credential_profiles", "principal_slot": "secondary",
                              "profile_id": unshared, "profile_version": 1},))
        with pytest.raises(HuntVerificationCredentialRefused) as exc:
            await resolve_hunt_workflow_principal_contexts(
                conn, selected, TARGET, {"user1", "user2"}, decryptor=spy)
        assert exc.value.code == "credential_not_attached" and exc.value.profile_id == unshared
        assert f"enc:fernet:{unshared}" not in decrypted

        # A Hunt action's selected credential: recorded while attached, refused once revoked.
        context = {"credential_refs": [{
            "source": "credential_profiles", "principal_slot": "secondary", "profile_id": shared,
            "profile_version": 1, "auth_kind": "authorization_header",
            "allowed_capabilities": ["authz.verify", "http.request"]}]}
        run = {"id": hunt, "target_id": TARGET, "device_target_id": None}
        admitted = await admit_action_credentials(
            conn, run=run, capability="http.request",
            capability_input={"as_principal": "secondary"}, context=context)
        # D38: selected at start, and still recorded as another target's credential.
        assert [(u.profile_id, u.source, u.slot) for u in admitted] == [
            (shared, f"selected_shared_from:{OTHER}", "secondary")]
        await record_credential_uses(conn, hunt_id=hunt, action_id=second_action, uses=admitted)
        (recorded,) = [u for u in await read_credential_uses(conn, hunt)
                       if u["action_id"] == str(second_action)]
        assert (recorded["selected"], recorded["shared_from_target_id"]) == (True, str(OTHER))
        # The verifier records a selected shared credential the same way.
        selected_shared = HuntCredentialScope(
            hunt_id=hunt, action_id=second_action, target_kind="web", target_id=TARGET,
            credential_refs=({"source": "credential_profiles", "principal_slot": "secondary",
                              "profile_id": shared, "profile_version": 1},))
        await resolve_hunt_workflow_principal_contexts(
            conn, selected_shared, TARGET, {"user1", "user2"}, decryptor=spy)
        assert {(u["slot"], u["source"]) for u in await read_credential_uses(conn, hunt)
                if u["action_id"] == str(second_action)} == {
            ("primary", "target_own"), ("secondary", f"selected_shared_from:{OTHER}")}
        await STORE.revoke_grant(conn, profile_id=shared, target_id=TARGET, now=datetime.now(timezone.utc))
        with pytest.raises(HuntCredentialRefusal) as exc:
            await admit_action_credentials(
                conn, run=run, capability="http.request",
                capability_input={"as_principal": "secondary"}, context=context)
        assert exc.value.code == "credential_not_attached"
        # Verification no longer reaches the revoked credential either.
        with pytest.raises(HuntVerificationCredentialRefused) as exc:
            await resolve_hunt_workflow_principal_contexts(
                conn, scope, TARGET, {"user1", "user2"}, decryptor=spy)
        assert (exc.value.code, exc.value.slot) == ("credential_missing_for_slot", "user2")

        # The ledger rejects anything but the closed sources and safe slots.
        for source, slot in (("granted", "primary"), ("shared_from:not-a-target", "primary"),
                             ("selected_shared_from:not-a-target", "primary"),
                             ("selected", "Primary Slot")):
            with pytest.raises(asyncpg.CheckViolationError):
                await conn.execute(
                    """INSERT INTO hunt_credential_uses
                       (hunt_run_id,action_id,profile_id,profile_version,source,slot)
                       VALUES($1,$2,$3,1,$4,$5)""", hunt, second_action, uuid.UUID(own), source, slot)
        # Deleting the Hunt removes its ledger with it.
        await conn.execute("DELETE FROM hunt_runs WHERE id=$1", hunt)
        assert await conn.fetchval("SELECT count(*) FROM hunt_credential_uses") == 0
    finally:
        await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await conn.close()


# The ledger exactly as its first release (b849c3b4) created it, before selected_shared_from.
FIRST_RELEASE_LEDGER = """
CREATE TABLE hunt_credential_uses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_run_id UUID NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
    action_id UUID NOT NULL REFERENCES hunt_actions(id) ON DELETE CASCADE,
    profile_id UUID NOT NULL,
    profile_version INTEGER NOT NULL CHECK (profile_version > 0),
    source TEXT NOT NULL CHECK (
        source IN ('selected','target_own')
        OR source ~ '^shared_from:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    ),
    slot TEXT NOT NULL CHECK (slot ~ '^[a-z0-9:_.-]{1,80}$'),
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT hunt_credential_uses_action_slot_unique UNIQUE (action_id, profile_id, slot)
);
CREATE INDEX idx_hunt_credential_uses_run ON hunt_credential_uses(hunt_run_id, used_at, id);
"""


@pytest.mark.asyncio
async def test_restart_lets_a_first_release_ledger_record_a_selected_shared_credential():
    """D38: the startup migration widens the first release's source check in place."""
    import asyncpg

    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
    conn = await asyncpg.connect(DSN)
    old, fresh = "hunt_cred_old_" + uuid.uuid4().hex, "hunt_cred_new_" + uuid.uuid4().hex
    ddl = (ROOT / "db/init.sql").read_text()
    try:
        await _schema(conn, fresh, bootstrap=True)
        await conn.execute(f'CREATE SCHEMA "{old}"; SET search_path TO "{old}"')
        await conn.execute("CREATE TABLE targets(id UUID PRIMARY KEY); CREATE TABLE device_targets(id UUID PRIMARY KEY)")
        for table in ("hunt_runs", "hunt_actions"):
            await conn.execute(_table(ddl, table))
        await conn.execute(FIRST_RELEASE_LEDGER)
        hunt, action = uuid.uuid4(), uuid.uuid4()
        await conn.execute("INSERT INTO targets VALUES($1)", TARGET)
        await conn.execute("INSERT INTO hunt_runs(id,target_kind,target_id) VALUES($1,'web',$2)", hunt, TARGET)
        await conn.execute("INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status) "
                           "VALUES($1,$2,'http.request','running')", action, hunt)
        insert = ("INSERT INTO hunt_credential_uses(hunt_run_id,action_id,profile_id,profile_version,"
                  "source,slot) VALUES($1,$2,$3,1,$4,'secondary')")
        selected_shared = f"selected_shared_from:{OTHER}"
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(insert, hunt, action, uuid.uuid4(), selected_shared)
        await conn.execute(insert, hunt, action, uuid.uuid4(), "selected")
        for _ in range(2):  # restart twice: the widening is idempotent and keeps rows
            await conn.execute(HUNT_CREDENTIAL_USES_SCHEMA_SQL)
        await conn.execute(insert, hunt, action, uuid.uuid4(), selected_shared)
        assert await conn.fetchval("SELECT count(*) FROM hunt_credential_uses") == 2
        assert await _definition(conn, old) == await _definition(conn, fresh)
    finally:
        for schema in (old, fresh):
            await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await conn.close()
