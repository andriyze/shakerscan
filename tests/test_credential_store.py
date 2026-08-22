from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import uuid

import pytest

from api.runtime.credential_store import (
    CREDENTIAL_PROFILE_SCHEMA_SQL,
    CredentialProfileMetadata,
    CredentialStoreConflict,
    CredentialStoreError,
    PostgresCredentialProfileStore,
)
from api.runtime.credentials import (
    build_credential_secret,
    parse_credential_secret,
    public_credential_configuration,
)


NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
PROFILE_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
TARGET_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")
OTHER_TARGET_ID = uuid.UUID("33333333-3333-4333-8333-333333333333")
SECRET = "enc:fernet:ciphertext-secret"
METADATA = "enc:fernet:ciphertext-metadata"


def _configuration(kind="bearer_token"):
    kwargs = {"secret": "opaque-token"}
    if kind == "ssh_password":
        kwargs["username"] = "operator"
    return public_credential_configuration(
        parse_credential_secret(kind, build_credential_secret(kind, **kwargs))
    )


class MemoryCredentialConn:
    def __init__(self):
        self.profile = None
        self.versions = {}
        self.binding = None
        self.executed = []

    async def execute(self, query, *args):
        self.executed.append((query, args))
        normalized = query.lstrip()
        if query == CREDENTIAL_PROFILE_SCHEMA_SQL:
            return "OK"
        if normalized.startswith("INSERT INTO credential_profile_versions"):
            if len(args) == 6:
                profile_id, auth_kind, secret, metadata, actor, created_at = args
                version = 1
            else:
                profile_id, version, auth_kind, secret, metadata, actor, created_at = args
            self.versions[(profile_id, version)] = {
                "profile_id": profile_id,
                "version": version,
                "auth_kind": auth_kind,
                "encrypted_secret": secret,
                "encrypted_metadata": metadata,
                "created_by": actor,
                "created_at": created_at,
            }
            return "INSERT 0 1"
        if normalized.startswith("INSERT INTO credential_profile_bindings"):
            binding_id, profile_id, target_id, capabilities, created_at = args
            self.binding = {
                "id": binding_id,
                "profile_id": profile_id,
                "binding_kind": "target",
                "binding_id": target_id,
                "allowed_capabilities": json.loads(capabilities),
                "is_active": True,
                "created_at": created_at,
                "updated_at": created_at,
            }
            return "INSERT 0 1"
        if normalized.startswith("UPDATE credential_profile_bindings"):
            if "allowed_capabilities=COALESCE" in query:
                capabilities, active, changed_at, _profile_id, _binding_id = args
                if capabilities is not None:
                    self.binding["allowed_capabilities"] = json.loads(capabilities)
                self.binding["is_active"] = active
                self.binding["updated_at"] = changed_at
            else:
                self.binding["is_active"] = False
                self.binding["updated_at"] = args[0]
            return "UPDATE 1"
        raise AssertionError(query)

    async def fetchrow(self, query, *args):
        normalized = query.lstrip()
        if normalized.startswith("INSERT INTO credential_profiles"):
            (
                profile_id,
                target_kind,
                target_id,
                name,
                auth_kind,
                principal_label,
                principal_slot,
                configuration,
                expires_at,
                created_at,
            ) = args
            self.profile = {
                "id": profile_id,
                "target_kind": target_kind,
                "target_id": target_id,
                "name": name,
                "auth_kind": auth_kind,
                "principal_label": principal_label,
                "principal_slot": principal_slot,
                "configuration_json": json.loads(configuration),
                "current_version": 1,
                "record_version": 1,
                "is_active": True,
                "expires_at": expires_at,
                "rotated_at": created_at,
                "created_at": created_at,
                "updated_at": created_at,
            }
            return dict(self.profile)
        if normalized.startswith("SELECT p.*, b.allowed_capabilities"):
            if not self.profile or self.profile["id"] != args[0]:
                return None
            return {
                **self.profile,
                "allowed_capabilities": (
                    self.binding["allowed_capabilities"] if self.binding else []
                ),
            }
        if normalized.startswith("SELECT * FROM credential_profiles"):
            if not self.profile:
                return None
            if len(args) == 1:
                return dict(self.profile) if self.profile["id"] == args[0] else None
            if (
                self.profile["id"] != args[0]
                or self.profile["target_kind"] != args[1]
                or self.profile["target_id"] != args[2]
            ):
                return None
            return dict(self.profile)
        if normalized.startswith("UPDATE credential_profiles") and "current_version" in query:
            next_version, configuration, expires_at, changed_at, profile_id, expected = args
            if not self.profile or self.profile["id"] != profile_id:
                return None
            if self.profile["record_version"] != expected:
                return None
            self.profile.update({
                "current_version": next_version,
                "record_version": expected + 1,
                "configuration_json": json.loads(configuration),
                "expires_at": expires_at,
                "is_active": True,
                "rotated_at": changed_at,
                "updated_at": changed_at,
            })
            return dict(self.profile)
        if normalized.startswith("UPDATE credential_profiles") and "SET name=" in query:
            (
                name,
                principal_label,
                principal_slot,
                expires_at,
                active,
                changed_at,
                profile_id,
                expected,
            ) = args
            if not self.profile or self.profile["id"] != profile_id:
                return None
            if self.profile["record_version"] != expected:
                return None
            self.profile.update({
                "name": name,
                "principal_label": principal_label,
                "principal_slot": principal_slot,
                "expires_at": expires_at,
                "is_active": active,
                "record_version": expected + 1,
                "updated_at": changed_at,
            })
            return dict(self.profile)
        if normalized.startswith("SELECT p.*, v.encrypted_secret"):
            if not self.profile or not self.binding or not self.binding["is_active"]:
                return None
            if (
                self.profile["id"] != args[0]
                or self.profile["target_kind"] != args[1]
                or self.profile["target_id"] != args[2]
                or not self.profile["is_active"]
            ):
                return None
            version = self.versions[(self.profile["id"], self.profile["current_version"])]
            return {
                **self.profile,
                "encrypted_secret": version["encrypted_secret"],
                "encrypted_metadata": version["encrypted_metadata"],
                "allowed_capabilities": self.binding["allowed_capabilities"],
            }
        if normalized.startswith("UPDATE credential_profiles") and "is_active=false" in query:
            changed_at, profile_id, target_kind, target_id = args
            if not self.profile or (
                self.profile["id"], self.profile["target_kind"], self.profile["target_id"]
            ) != (profile_id, target_kind, target_id):
                return None
            self.profile.update({
                "is_active": False,
                "record_version": self.profile["record_version"] + 1,
                "updated_at": changed_at,
            })
            return dict(self.profile)
        raise AssertionError(query)

    async def fetch(self, query, *args):
        if not self.profile:
            return []
        target_kind, target_id, include_inactive = args
        if self.profile["target_kind"] != target_kind or self.profile["target_id"] != target_id:
            return []
        if not include_inactive and not self.profile["is_active"]:
            return []
        return [dict(self.profile)]


async def _created(*, allowed_capabilities=()):
    conn = MemoryCredentialConn()
    profile = await PostgresCredentialProfileStore().create_profile(
        conn,
        profile_id=PROFILE_ID,
        target_kind="api",
        target_id=TARGET_ID,
        name="Primary API",
        auth_kind="bearer_token",
        principal_slot="primary",
        principal_label="primary-user",
        configuration=_configuration(),
        encrypted_secret=SECRET,
        encrypted_metadata=METADATA,
        expires_at=NOW + timedelta(days=30),
        allowed_capabilities=allowed_capabilities,
        created_by="test",
        now=NOW,
    )
    return conn, profile


def test_schema_installs_all_three_tables_and_migration_marker():
    conn = MemoryCredentialConn()
    asyncio.run(PostgresCredentialProfileStore().ensure_schema(conn))
    assert conn.executed == [(CREDENTIAL_PROFILE_SCHEMA_SQL, ())]
    assert "CREATE TABLE IF NOT EXISTS credential_profiles" in CREDENTIAL_PROFILE_SCHEMA_SQL
    assert "CREATE TABLE IF NOT EXISTS credential_profile_versions" in CREDENTIAL_PROFILE_SCHEMA_SQL
    assert "CREATE TABLE IF NOT EXISTS credential_profile_bindings" in CREDENTIAL_PROFILE_SCHEMA_SQL
    assert "v2_credential_profiles_v1" in CREDENTIAL_PROFILE_SCHEMA_SQL


def test_runtime_schema_and_repair_schema_do_not_drift():
    repair = Path("db/repairs/2026-08-22_v2_credential_profiles.sql").read_text()
    body = repair.split("BEGIN;", 1)[1].rsplit("COMMIT;", 1)[0]
    squash = lambda value: " ".join(value.split())
    assert squash(body) == squash(CREDENTIAL_PROFILE_SCHEMA_SQL)


def test_create_persists_one_profile_one_immutable_version_and_target_binding():
    conn, profile = asyncio.run(_created(allowed_capabilities=["request.replay"]))

    assert profile.profile_id == str(PROFILE_ID)
    assert profile.target_id == str(TARGET_ID)
    assert profile.current_version == 1
    assert conn.versions[(PROFILE_ID, 1)]["encrypted_secret"] == SECRET
    assert conn.binding["binding_id"] == str(TARGET_ID)
    assert conn.binding["allowed_capabilities"] == ["request.replay"]
    public = json.dumps(profile.public_dict(), default=str)
    assert "ciphertext-secret" not in public
    assert "opaque-token" not in public


def test_plaintext_storage_and_secret_bearing_public_configuration_fail_before_sql():
    conn = MemoryCredentialConn()
    store = PostgresCredentialProfileStore()
    with pytest.raises(CredentialStoreError, match="Fernet ciphertext"):
        asyncio.run(store.create_profile(
            conn,
            profile_id=PROFILE_ID,
            target_kind="api",
            target_id=TARGET_ID,
            name="Unsafe",
            auth_kind="bearer_token",
            principal_slot="primary",
            principal_label=None,
            configuration=_configuration(),
            encrypted_secret="plaintext",
            encrypted_metadata=METADATA,
            expires_at=None,
            now=NOW,
        ))
    assert conn.profile is None

    unsafe = {**_configuration(), "secret": "opaque-token"}
    with pytest.raises(CredentialStoreError, match="unsupported keys: secret"):
        asyncio.run(store.create_profile(
            conn,
            profile_id=PROFILE_ID,
            target_kind="api",
            target_id=TARGET_ID,
            name="Unsafe",
            auth_kind="bearer_token",
            principal_slot="primary",
            principal_label=None,
            configuration=unsafe,
            encrypted_secret=SECRET,
            encrypted_metadata=METADATA,
            expires_at=None,
            now=NOW,
        ))


def test_worker_lookup_requires_exact_target_and_capability_binding():
    conn, _ = asyncio.run(_created(allowed_capabilities=["request.replay"]))
    store = PostgresCredentialProfileStore()

    resolved = asyncio.run(store.load_for_worker(
        conn,
        profile_id=PROFILE_ID,
        target_kind="api",
        target_id=TARGET_ID,
        capability="request.replay",
    ))
    assert resolved.encrypted_secret == SECRET
    assert resolved.allowed_capabilities == ("request.replay",)

    with pytest.raises(CredentialStoreError, match="unavailable for target"):
        asyncio.run(store.load_for_worker(
            conn,
            profile_id=PROFILE_ID,
            target_kind="api",
            target_id=OTHER_TARGET_ID,
            capability="request.replay",
        ))
    with pytest.raises(CredentialStoreError, match="not allowed for capability"):
        asyncio.run(store.load_for_worker(
            conn,
            profile_id=PROFILE_ID,
            target_kind="api",
            target_id=TARGET_ID,
            capability="web.crawl",
        ))


def test_rotation_is_immutable_and_optimistically_versioned():
    conn, profile = asyncio.run(_created())
    store = PostgresCredentialProfileStore()

    rotated = asyncio.run(store.rotate_profile(
        conn,
        profile_id=PROFILE_ID,
        target_kind="api",
        target_id=TARGET_ID,
        expected_record_version=profile.record_version,
        encrypted_secret="enc:fernet:second-secret",
        encrypted_metadata="enc:fernet:second-metadata",
        configuration=_configuration(),
        expires_at=NOW + timedelta(days=60),
        created_by="rotation-test",
        now=NOW + timedelta(minutes=1),
    ))
    assert rotated.current_version == 2
    assert rotated.record_version == 2
    assert conn.versions[(PROFILE_ID, 1)]["encrypted_secret"] == SECRET
    assert conn.versions[(PROFILE_ID, 2)]["encrypted_secret"] == "enc:fernet:second-secret"

    with pytest.raises(CredentialStoreConflict, match="modified concurrently"):
        asyncio.run(store.rotate_profile(
            conn,
            profile_id=PROFILE_ID,
            target_kind="api",
            target_id=TARGET_ID,
            expected_record_version=1,
            encrypted_secret="enc:fernet:third-secret",
            encrypted_metadata="enc:fernet:third-metadata",
            configuration=_configuration(),
            expires_at=None,
            created_by="stale-test",
            now=NOW + timedelta(minutes=2),
        ))


def test_deactivation_revokes_profile_and_binding():
    conn, _ = asyncio.run(_created())
    store = PostgresCredentialProfileStore()
    deactivated = asyncio.run(store.deactivate_profile(
        conn,
        profile_id=PROFILE_ID,
        target_kind="api",
        target_id=TARGET_ID,
        now=NOW + timedelta(minutes=1),
    ))
    assert deactivated.is_active is False
    assert conn.binding["is_active"] is False
    with pytest.raises(CredentialStoreError, match="unavailable for target"):
        asyncio.run(store.load_for_worker(
            conn,
            profile_id=PROFILE_ID,
            target_kind="api",
            target_id=TARGET_ID,
            capability="request.replay",
        ))


@pytest.mark.parametrize(
    ("target_kind", "auth_kind", "principal_slot", "message"),
    [
        ("web", "ssh_password", "ssh", "network or device"),
        ("device", "ssh_password", "primary", "principal_slot=ssh"),
        ("network", "bearer_token", "primary", "HTTP credentials"),
        ("api", "bearer_token", "ssh", "principal_slot=ssh"),
    ],
)
def test_auth_kind_target_and_principal_slot_placement_is_fail_closed(
    target_kind, auth_kind, principal_slot, message
):
    conn = MemoryCredentialConn()
    with pytest.raises(CredentialStoreError, match=message):
        asyncio.run(PostgresCredentialProfileStore().create_profile(
            conn,
            profile_id=PROFILE_ID,
            target_kind=target_kind,
            target_id=TARGET_ID,
            name="Misbound",
            auth_kind=auth_kind,
            principal_slot=principal_slot,
            principal_label=None,
            configuration=_configuration(auth_kind),
            encrypted_secret=SECRET,
            encrypted_metadata=METADATA,
            expires_at=None,
            now=NOW,
        ))


def test_metadata_parser_rejects_invalid_record_versions():
    with pytest.raises((CredentialStoreError, ValueError)):
        CredentialProfileMetadata.from_row({
            "id": PROFILE_ID,
            "target_kind": "api",
            "target_id": TARGET_ID,
            "name": "Bad",
            "auth_kind": "bearer_token",
            "principal_label": None,
            "principal_slot": "primary",
            "configuration_json": _configuration(),
            "current_version": 0,
            "record_version": 0,
            "is_active": True,
            "expires_at": None,
            "rotated_at": NOW,
            "created_at": NOW,
            "updated_at": NOW,
        })
