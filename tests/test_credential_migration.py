import asyncio
from datetime import datetime, timedelta, timezone
import json
import uuid

import pytest

from api.runtime import credential_migration as migration
from api.runtime.credential_store import CredentialProfileMetadata, CredentialStoreError


NOW = datetime(2026, 8, 22, 15, 0, tzinfo=timezone.utc)
TARGET_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
PROFILE_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")


def _metadata(**overrides):
    values = {
        "profile_id": str(PROFILE_ID),
        "target_kind": "web",
        "target_id": str(TARGET_ID),
        "name": "legacy-user",
        "auth_kind": "authorization_header",
        "principal_label": "User two",
        "principal_slot": "secondary",
        "configuration": {
            "schema_version": "credential-secret/v1",
            "auth_kind": "authorization_header",
            "secret_values_visible": False,
        },
        "current_version": 1,
        "record_version": 1,
        "is_active": True,
        "expires_at": NOW + timedelta(days=1),
        "rotated_at": NOW,
        "created_at": NOW,
        "updated_at": NOW,
        "allowed_capabilities": migration.LEGACY_WEB_CAPABILITIES,
    }
    values.update(overrides)
    if "configuration" not in overrides:
        values["configuration"] = {
            "schema_version": "credential-secret/v1",
            "auth_kind": values["auth_kind"],
            "secret_values_visible": False,
        }
    return CredentialProfileMetadata(**values)


class FakeConn:
    def __init__(self, *, legacy=None, principals=None, current_cipher="enc:fernet:old"):
        self.legacy = legacy or {
            "id": PROFILE_ID,
            "target_id": TARGET_ID,
            "name": "legacy-user",
            "auth_kind": "authorization_header",
            "secret_value": "enc:fernet:legacy-secret",
            "expires_at": NOW + timedelta(days=1),
            "is_active": True,
        }
        self.principals = principals or [{"auth_state": "user2", "label": "User two"}]
        self.current_cipher = current_cipher
        self.marker = False

    async def fetchrow(self, query, *args):
        if "SELECT * FROM target_credential_profiles WHERE id" in query:
            return self.legacy if args[0] == PROFILE_ID else None
        if "SELECT encrypted_secret FROM credential_profile_versions" in query:
            return {"encrypted_secret": self.current_cipher}
        if "SELECT id FROM target_credential_profiles" in query:
            return {"id": PROFILE_ID}
        raise AssertionError(query)

    async def fetch(self, query, *args):
        if "FROM target_principals" in query:
            return self.principals
        if "SELECT id FROM target_credential_profiles ORDER BY" in query:
            return [{"id": PROFILE_ID}]
        raise AssertionError(query)

    async def fetchval(self, query, *args):
        assert "app_schema_migrations" in query
        return 1 if self.marker else None

    async def execute(self, query, *args):
        assert "app_schema_migrations" in query
        self.marker = True


class DeviceConn(FakeConn):
    def __init__(self, legacy):
        super().__init__()
        self.device_legacy = legacy

    async def fetchrow(self, query, *args):
        if "SELECT * FROM device_credential_profiles WHERE id" in query:
            return self.device_legacy if args[0] == PROFILE_ID else None
        return await super().fetchrow(query, *args)


class AiConn(FakeConn):
    def __init__(self, *, default=None, principal=None):
        super().__init__()
        self.ai_default = default
        self.ai_principal = principal

    async def fetchrow(self, query, *args):
        if "FROM ai_target_credentials c" in query:
            return self.ai_default if self.ai_default and args[0] == self.ai_default["id"] else None
        if "FROM ai_target_principals p" in query:
            return self.ai_principal if self.ai_principal and args[0] == self.ai_principal["id"] else None
        return await super().fetchrow(query, *args)

    async def fetch(self, query, *args):
        if "SELECT id FROM ai_target_credentials ORDER BY" in query:
            return [{"id": self.ai_default["id"]}] if self.ai_default else []
        if "SELECT id FROM ai_target_principals ORDER BY" in query:
            return [{"id": self.ai_principal["id"]}] if self.ai_principal else []
        return await super().fetch(query, *args)


class FakeStore:
    def __init__(self, existing=None):
        self.profile = existing
        self.calls = []

    async def get_profile(self, _conn, *, profile_id):
        if self.profile is None:
            raise CredentialStoreError("credential profile not found")
        return self.profile

    async def create_profile(self, _conn, **kwargs):
        self.calls.append(("create", kwargs))
        self.profile = _metadata(
            profile_id=str(kwargs["profile_id"]),
            target_kind=kwargs["target_kind"],
            target_id=str(kwargs["target_id"]),
            name=kwargs["name"],
            auth_kind=kwargs["auth_kind"],
            principal_label=kwargs["principal_label"],
            principal_slot=kwargs["principal_slot"],
            expires_at=kwargs["expires_at"],
        )
        return self.profile

    async def rotate_profile(self, _conn, **kwargs):
        self.calls.append(("rotate", kwargs))
        self.profile = _metadata(
            profile_id=self.profile.profile_id,
            target_kind=self.profile.target_kind,
            target_id=self.profile.target_id,
            current_version=self.profile.current_version + 1,
            record_version=self.profile.record_version + 1,
            name=self.profile.name,
            principal_label=self.profile.principal_label,
            principal_slot=self.profile.principal_slot,
            expires_at=kwargs["expires_at"],
            allowed_capabilities=self.profile.allowed_capabilities,
            auth_kind=self.profile.auth_kind,
        )
        return self.profile

    async def update_profile_metadata(self, _conn, **kwargs):
        self.calls.append(("update", kwargs))
        self.profile = _metadata(
            profile_id=self.profile.profile_id,
            target_kind=self.profile.target_kind,
            target_id=self.profile.target_id,
            current_version=self.profile.current_version,
            record_version=self.profile.record_version + 1,
            name=kwargs["name"],
            principal_label=kwargs["principal_label"],
            principal_slot=kwargs["principal_slot"],
            expires_at=kwargs["expires_at"],
            is_active=kwargs["is_active"],
            allowed_capabilities=tuple(kwargs["allowed_capabilities"]),
            auth_kind=self.profile.auth_kind,
        )
        return self.profile

    async def deactivate_profile(self, _conn, **kwargs):
        self.calls.append(("deactivate", kwargs))
        self.profile = _metadata(
            profile_id=self.profile.profile_id,
            target_kind=self.profile.target_kind,
            target_id=self.profile.target_id,
            name=self.profile.name,
            auth_kind=self.profile.auth_kind,
            principal_label=self.profile.principal_label,
            principal_slot=self.profile.principal_slot,
            current_version=self.profile.current_version,
            is_active=False,
            record_version=self.profile.record_version + 1,
            expires_at=self.profile.expires_at,
            allowed_capabilities=self.profile.allowed_capabilities,
        )
        return self.profile


def test_legacy_web_backfill_copies_only_ciphertext_and_derives_secondary_slot(monkeypatch):
    monkeypatch.setattr(
        migration,
        "encrypt_secret",
        lambda value: "enc:fernet:metadata" if not str(value).startswith("enc:fernet:") else value,
    )
    conn = FakeConn()
    store = FakeStore()

    profile = asyncio.run(
        migration.sync_legacy_web_credential(conn, PROFILE_ID, store=store, now=NOW)
    )

    assert profile.principal_slot == "secondary"
    kind, call = store.calls[0]
    assert kind == "create"
    assert call["profile_id"] == PROFILE_ID
    assert call["encrypted_secret"] == "enc:fernet:legacy-secret"
    assert call["encrypted_metadata"] == "enc:fernet:metadata"
    assert call["allowed_capabilities"] == migration.LEGACY_WEB_CAPABILITIES
    assert "legacy-secret" not in repr(profile.public_dict())


def test_legacy_web_rotation_appends_generic_version_and_resynchronizes_metadata(monkeypatch):
    monkeypatch.setattr(migration, "encrypt_secret", lambda _value: "enc:fernet:metadata")
    existing = _metadata(
        name="old-name",
        principal_label=None,
        principal_slot="primary",
        expires_at=None,
        allowed_capabilities=(),
    )
    conn = FakeConn(current_cipher="enc:fernet:old")
    store = FakeStore(existing)

    profile = asyncio.run(
        migration.sync_legacy_web_credential(conn, PROFILE_ID, store=store, now=NOW)
    )

    assert [name for name, _call in store.calls] == ["rotate", "update"]
    assert profile.current_version == 2
    assert profile.name == "legacy-user"
    assert profile.principal_slot == "secondary"
    assert profile.allowed_capabilities == migration.LEGACY_WEB_CAPABILITIES


def test_inactive_legacy_web_profile_deactivates_generic_profile():
    legacy = {
        "id": PROFILE_ID,
        "target_id": TARGET_ID,
        "name": "legacy-user",
        "auth_kind": "authorization_header",
        "secret_value": "enc:fernet:legacy-secret",
        "expires_at": None,
        "is_active": False,
    }
    store = FakeStore(_metadata())
    profile = asyncio.run(
        migration.sync_legacy_web_credential(
            FakeConn(legacy=legacy), PROFILE_ID, store=store, now=NOW,
        )
    )
    assert profile.is_active is False
    assert store.calls[0][0] == "deactivate"


def test_inactive_legacy_web_history_is_backfilled_then_deactivated(monkeypatch):
    monkeypatch.setattr(migration, "encrypt_secret", lambda _value: "enc:fernet:metadata")
    legacy = {
        "id": PROFILE_ID,
        "target_id": TARGET_ID,
        "name": "legacy-user",
        "auth_kind": "authorization_header",
        "secret_value": "enc:fernet:legacy-secret",
        "created_at": NOW - timedelta(days=30),
        "expires_at": NOW - timedelta(days=1),
        "is_active": True,
    }
    store = FakeStore()
    profile = asyncio.run(
        migration.sync_legacy_web_credential(
            FakeConn(legacy=legacy), PROFILE_ID, store=store, now=NOW,
        )
    )
    assert [name for name, _call in store.calls] == ["create", "deactivate"]
    assert profile.is_active is False


def test_legacy_web_migration_marker_makes_backfill_idempotent(monkeypatch):
    monkeypatch.setattr(migration, "encrypt_secret", lambda _value: "enc:fernet:metadata")
    conn = FakeConn()
    store = FakeStore()
    first = asyncio.run(
        migration.migrate_legacy_web_credentials(conn, store=store, now=NOW)
    )
    second = asyncio.run(
        migration.migrate_legacy_web_credentials(conn, store=store, now=NOW)
    )
    assert first == 1
    assert second == 0
    assert conn.marker is True


def test_legacy_web_profile_id_collision_fails_closed():
    store = FakeStore(_metadata(target_id=str(uuid.uuid4())))
    with pytest.raises(migration.LegacyCredentialMigrationError, match="conflicts"):
        asyncio.run(
            migration.sync_legacy_web_credential(
                FakeConn(), PROFILE_ID, store=store, now=NOW,
            )
        )


@pytest.mark.parametrize(
    ("legacy_kind", "secondary", "expected_kind", "expected_slot", "username", "login_path"),
    [
        ("ssh_password", None, "ssh_password", "ssh", "root", None),
        ("ssh_private_key", None, "ssh_private_key", "ssh", "root", None),
        (
            "ssh_private_key", "passphrase", "ssh_private_key_with_passphrase",
            "ssh", "root", None,
        ),
        (
            "web_authorization_header", None, "authorization_header",
            "service", None, None,
        ),
        ("web_cookie", None, "cookie", "service", None, None),
        ("web_form", None, "form_login", "service", "operator", "/login"),
    ],
)
def test_legacy_device_envelopes_map_to_generic_contracts(
    monkeypatch, legacy_kind, secondary, expected_kind, expected_slot, username, login_path,
):
    monkeypatch.setattr(
        migration,
        "decrypt_secret",
        lambda _value: json.dumps({
            "secret": "worker-secret",
            "secondary_secret": secondary,
        }),
    )
    monkeypatch.setattr(migration, "encrypt_secret", lambda _value: "enc:fernet:canonical")
    legacy = {
        "id": PROFILE_ID,
        "device_target_id": TARGET_ID,
        "name": "Device identity",
        "auth_kind": legacy_kind,
        "username": username,
        "secret_value": "enc:fernet:legacy-device",
        "login_path": login_path,
        "port": 22 if legacy_kind.startswith("ssh_") else 443,
        "expires_at": NOW + timedelta(days=1),
        "is_active": True,
        "created_at": NOW,
        "rotated_at": NOW,
    }
    store = FakeStore()

    profile = asyncio.run(
        migration.sync_legacy_device_credential(
            DeviceConn(legacy), PROFILE_ID, store=store, now=NOW,
        )
    )

    assert profile.target_kind == "device"
    assert profile.auth_kind == expected_kind
    assert profile.principal_slot == expected_slot
    create = store.calls[0][1]
    assert create["encrypted_secret"] == "enc:fernet:canonical"
    expected_capabilities = (
        migration.LEGACY_DEVICE_SSH_CAPABILITIES
        if expected_slot == "ssh"
        else migration.LEGACY_DEVICE_WEB_CAPABILITIES
    )
    assert create["allowed_capabilities"] == expected_capabilities


def test_device_passphrase_shape_cannot_change_under_same_migrated_identity(monkeypatch):
    monkeypatch.setattr(
        migration,
        "decrypt_secret",
        lambda _value: '{"secret":"key","secondary_secret":"new-passphrase"}',
    )
    monkeypatch.setattr(migration, "encrypt_secret", lambda _value: "enc:fernet:canonical")
    legacy = {
        "id": PROFILE_ID,
        "device_target_id": TARGET_ID,
        "name": "Device key",
        "auth_kind": "ssh_private_key",
        "username": "root",
        "secret_value": "enc:fernet:legacy-device",
        "login_path": None,
        "port": 22,
        "expires_at": None,
        "is_active": True,
        "created_at": NOW,
        "rotated_at": NOW + timedelta(seconds=1),
    }
    existing = _metadata(
        target_kind="device",
        target_id=str(TARGET_ID),
        auth_kind="ssh_private_key",
        principal_slot="ssh",
        principal_label=None,
        name="Device key",
        expires_at=None,
        allowed_capabilities=migration.LEGACY_DEVICE_SSH_CAPABILITIES,
    )
    with pytest.raises(migration.LegacyCredentialMigrationError, match="authentication kind"):
        asyncio.run(
            migration.sync_legacy_device_credential(
                DeviceConn(legacy), PROFILE_ID, store=FakeStore(existing), now=NOW,
            )
        )


@pytest.mark.parametrize(
    ("legacy_kind", "secret", "header_name", "metadata", "expected_kind", "expected"),
    [
        ("bearer", "token", None, {}, "bearer_token", {"secret": "token"}),
        (
            "api_key_header", "key", "X-API-Key", {}, "api_key_header",
            {"secret": "key", "header_name": "X-API-Key"},
        ),
        (
            "custom_header", "tenant", "X-Tenant", {}, "api_key_header",
            {"secret": "tenant", "header_name": "X-Tenant"},
        ),
        (
            "basic_auth", "analyst:password", None, {}, "basic_auth",
            {"username": "analyst", "secret": "password"},
        ),
        ("cookie", "sid=value", None, {}, "cookie", {"secret": "sid=value"}),
        (
            "multi_header",
            '[{"name":"X-Tenant","value":"blue"},{"name":"X-Key","value":"key"}]',
            None,
            {},
            "custom_headers",
            {"custom_headers": {"X-Key": "key", "X-Tenant": "blue"}},
        ),
        (
            "query_param", "query-key", None, {"param_name": "access_key"},
            "query_parameter", {"secret": "query-key", "parameter_name": "access_key"},
        ),
    ],
)
def test_legacy_ai_target_credentials_map_to_generic_contracts(
    monkeypatch, legacy_kind, secret, header_name, metadata, expected_kind, expected,
):
    monkeypatch.setattr(migration, "decrypt_secret", lambda _value: secret)
    monkeypatch.setattr(migration, "encrypt_secret", lambda value: f"enc:fernet:{value}")
    legacy = {
        "id": PROFILE_ID,
        "ai_target_id": TARGET_ID,
        "auth_kind": legacy_kind,
        "header_name": header_name,
        "secret_value": "enc:fernet:legacy-ai",
        "metadata_json": metadata,
        "target_is_active": True,
        "created_at": NOW,
        "rotated_at": NOW,
    }
    store = FakeStore()

    profile = asyncio.run(
        migration.sync_legacy_ai_target_credential(
            AiConn(default=legacy), PROFILE_ID, store=store, now=NOW,
        )
    )

    assert profile.target_kind == "api"
    assert profile.target_id == str(TARGET_ID)
    assert profile.auth_kind == expected_kind
    assert profile.principal_slot == "service"
    create = store.calls[0][1]
    envelope = migration.parse_credential_secret(
        expected_kind, create["encrypted_secret"].removeprefix("enc:fernet:")
    )
    for key, value in expected.items():
        assert envelope[key] == value
    assert create["allowed_capabilities"] == migration.LEGACY_AI_CAPABILITIES


@pytest.mark.parametrize(
    ("role", "expected_slot"),
    [("victim", "primary"), ("attacker", "secondary"), ("admin", "service")],
)
def test_legacy_ai_principals_preserve_identity_and_derive_slot(
    monkeypatch, role, expected_slot,
):
    monkeypatch.setattr(migration, "decrypt_secret", lambda _value: "principal-token")
    monkeypatch.setattr(migration, "encrypt_secret", lambda value: f"enc:fernet:{value}")
    legacy = {
        "id": PROFILE_ID,
        "ai_target_id": TARGET_ID,
        "label": "Tenant operator",
        "role": role,
        "auth_kind": "bearer",
        "header_name": None,
        "secret_value": "enc:fernet:legacy-ai-principal",
        "metadata_json": {},
        "is_active": True,
        "target_is_active": True,
        "created_at": NOW,
        "rotated_at": NOW,
    }
    store = FakeStore()

    profile = asyncio.run(
        migration.sync_legacy_ai_principal_credential(
            AiConn(principal=legacy), PROFILE_ID, store=store, now=NOW,
        )
    )

    assert profile.principal_slot == expected_slot
    create = store.calls[0][1]
    assert create["principal_label"] == "Tenant operator"
    assert str(PROFILE_ID).replace("-", "")[:8] in create["name"]


def test_legacy_ai_none_credentials_do_not_create_secret_profiles():
    legacy = {
        "id": PROFILE_ID,
        "ai_target_id": TARGET_ID,
        "auth_kind": "none",
        "target_is_active": True,
        "created_at": NOW,
        "rotated_at": NOW,
    }
    store = FakeStore()
    profile = asyncio.run(
        migration.sync_legacy_ai_target_credential(
            AiConn(default=legacy), PROFILE_ID, store=store, now=NOW,
        )
    )
    assert profile is None
    assert store.calls == []


def test_legacy_ai_migration_marker_is_idempotent(monkeypatch):
    monkeypatch.setattr(migration, "decrypt_secret", lambda _value: "token")
    monkeypatch.setattr(migration, "encrypt_secret", lambda value: f"enc:fernet:{value}")
    legacy = {
        "id": PROFILE_ID,
        "ai_target_id": TARGET_ID,
        "auth_kind": "bearer",
        "header_name": None,
        "secret_value": "enc:fernet:legacy-ai",
        "metadata_json": {},
        "target_is_active": True,
        "created_at": NOW,
        "rotated_at": NOW,
    }
    conn = AiConn(default=legacy)
    store = FakeStore()
    first = asyncio.run(
        migration.migrate_legacy_ai_credentials(conn, store=store, now=NOW)
    )
    second = asyncio.run(
        migration.migrate_legacy_ai_credentials(conn, store=store, now=NOW)
    )
    assert first == 1
    assert second == 0


def test_scan_execute_only_binding_is_migrated_to_semantic_capabilities():
    class CapabilityMigrationConn:
        def __init__(self):
            self.applied = False
            self.calls = []

        async def fetchval(self, query, *args):
            assert "app_schema_migrations" in query
            assert args == (migration.SCAN_EXECUTE_CAPABILITY_MIGRATION,)
            return 1 if self.applied else None

        async def execute(self, query, *args):
            self.calls.append((query, args))
            if query.lstrip().startswith("UPDATE credential_profile_bindings"):
                return "UPDATE 1"
            if query.lstrip().startswith("INSERT INTO app_schema_migrations"):
                self.applied = True
                return "INSERT 0 1"
            raise AssertionError(query)

    conn = CapabilityMigrationConn()
    first = asyncio.run(migration.migrate_scan_execute_capabilities(conn))
    second = asyncio.run(migration.migrate_scan_execute_capabilities(conn))

    assert first == 1
    assert second == 0
    update_query, update_args = conn.calls[0]
    assert "item <> 'scan.execute'" in update_query
    replacement = set(update_args[0])
    assert "scan.execute" not in replacement
    assert replacement >= {
        "auth.session.establish", "http.request", "web.probe", "authz.verify",
    }
    assert "scan.execute" not in migration.LEGACY_WEB_CAPABILITIES
