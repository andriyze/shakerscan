"""Authoritative PostgreSQL storage for generic V2 credential profiles.

The control plane writes encrypted envelopes and content-free configuration.  Only a
worker lookup returns ciphertext, and that lookup requires an exact target binding and
an active consumer binding.  Secret rotation appends an immutable version instead of
overwriting audit history.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from typing import Any, Mapping, NoReturn, Protocol
import uuid

from .credentials import CREDENTIAL_KINDS, SSH_CREDENTIAL_KINDS


MIGRATION_NAME = "v2_credential_profiles_v1"
TARGET_KINDS = frozenset({"web", "api", "network", "device"})
PRINCIPAL_SLOTS = frozenset({"primary", "secondary", "service", "ssh"})
PUBLIC_CONFIGURATION_KEYS = frozenset({
    "schema_version",
    "auth_kind",
    "username_configured",
    "secondary_secret_configured",
    "header_name",
    "endpoint_configured",
    "client_id_configured",
    "scope_count",
    "custom_header_names",
    "parameter_name",
    "interactive_exchange_required",
    "secret_values_visible",
})
_NAME_RE = re.compile(r"^.{1,120}$", re.DOTALL)
_CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,119}$")
_CIPHERTEXT_PREFIX = "enc:fernet:"


CREDENTIAL_PROFILE_SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS credential_profiles (
    id UUID PRIMARY KEY,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('web','api','network','device')),
    target_id UUID NOT NULL,
    name TEXT NOT NULL,
    auth_kind TEXT NOT NULL CHECK (auth_kind IN (
        'authorization_header','bearer_token','api_key_header','cookie','basic_auth',
        'form_login','oauth_client_credentials','oauth_password','custom_headers','query_parameter',
        'ssh_password','ssh_private_key','ssh_private_key_with_passphrase'
    )),
    principal_label TEXT,
    principal_slot TEXT NOT NULL CHECK (principal_slot IN ('primary','secondary','service','ssh')),
    configuration_json JSONB NOT NULL CHECK (jsonb_typeof(configuration_json) = 'object'),
    current_version INTEGER NOT NULL DEFAULT 1 CHECK (current_version > 0),
    record_version INTEGER NOT NULL DEFAULT 1 CHECK (record_version > 0),
    is_active BOOLEAN NOT NULL DEFAULT true,
    expires_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT credential_profiles_target_name_unique
        UNIQUE (target_kind, target_id, name),
    CONSTRAINT credential_profiles_id_target_unique
        UNIQUE (id, target_kind, target_id),
    CONSTRAINT credential_profiles_id_auth_unique
        UNIQUE (id, auth_kind),
    CONSTRAINT credential_profiles_expiry_check
        CHECK (expires_at IS NULL OR expires_at > created_at)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_credential_profiles_target_name_ci
    ON credential_profiles(target_kind, target_id, lower(name));
CREATE INDEX IF NOT EXISTS idx_credential_profiles_target_active
    ON credential_profiles(target_kind, target_id, is_active, expires_at);

CREATE TABLE IF NOT EXISTS credential_profile_versions (
    profile_id UUID NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    auth_kind TEXT NOT NULL,
    encrypted_secret TEXT NOT NULL CHECK (encrypted_secret LIKE 'enc:fernet:%'),
    encrypted_metadata TEXT NOT NULL CHECK (encrypted_metadata LIKE 'enc:fernet:%'),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (profile_id, version),
    CONSTRAINT credential_profile_versions_profile_auth_fk
        FOREIGN KEY (profile_id, auth_kind)
        REFERENCES credential_profiles(id, auth_kind) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS credential_profile_bindings (
    id UUID PRIMARY KEY,
    profile_id UUID NOT NULL REFERENCES credential_profiles(id) ON DELETE CASCADE,
    binding_kind TEXT NOT NULL CHECK (binding_kind IN ('target','scan','hunt')),
    binding_id TEXT NOT NULL,
    allowed_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(allowed_capabilities) = 'array'),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT credential_profile_bindings_unique
        UNIQUE (profile_id, binding_kind, binding_id)
);
CREATE INDEX IF NOT EXISTS idx_credential_profile_bindings_consumer
    ON credential_profile_bindings(binding_kind, binding_id, is_active);

CREATE TABLE IF NOT EXISTS app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO app_schema_migrations(name)
VALUES ('v2_credential_profiles_v1')
ON CONFLICT (name) DO NOTHING;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname='credential_profiles_auth_kind_check'
          AND conrelid='credential_profiles'::regclass
          AND pg_get_constraintdef(oid) NOT LIKE '%query_parameter%'
    ) THEN
        ALTER TABLE credential_profiles DROP CONSTRAINT credential_profiles_auth_kind_check;
        ALTER TABLE credential_profiles ADD CONSTRAINT credential_profiles_auth_kind_check
            CHECK (auth_kind IN (
                'authorization_header','bearer_token','api_key_header','cookie','basic_auth',
                'form_login','oauth_client_credentials','oauth_password','custom_headers','query_parameter',
                'ssh_password','ssh_private_key','ssh_private_key_with_passphrase'
            ));
    END IF;
END
$$;

INSERT INTO app_schema_migrations(name)
VALUES ('v2_credential_query_parameter_v1')
ON CONFLICT (name) DO NOTHING;
"""


class CredentialStoreError(RuntimeError):
    """Stored credential state is invalid or unavailable."""


class CredentialStoreConflict(CredentialStoreError):
    """A stale rotation or duplicate identity conflicts with current state."""


class CredentialDatabase(Protocol):
    async def execute(self, query: str, *args: Any) -> Any: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetch(self, query: str, *args: Any) -> Any: ...


def _row(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    try:
        return dict(value)
    except (TypeError, ValueError) as exc:
        raise CredentialStoreError("credential database row is invalid") from exc


def _target_kind(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in TARGET_KINDS:
        raise CredentialStoreError("target_kind is invalid")
    return normalized


def _target_id(value: Any) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise CredentialStoreError("target_id must be a UUID") from exc


def _profile_id(value: Any) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise CredentialStoreError("profile_id must be a UUID") from exc


def _name(value: Any) -> str:
    normalized = re.sub(r"\s+", " ", str(value or "").strip())
    if not _NAME_RE.fullmatch(normalized):
        raise CredentialStoreError("credential profile name must be 1 to 120 characters")
    return normalized


def _auth_kind(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in CREDENTIAL_KINDS:
        raise CredentialStoreError("auth_kind is invalid")
    return normalized


def _principal_slot(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in PRINCIPAL_SLOTS:
        raise CredentialStoreError("principal_slot is invalid")
    return normalized


def _principal_label(value: Any) -> str | None:
    normalized = re.sub(r"\s+", " ", str(value or "").strip())
    if not normalized:
        return None
    if len(normalized) > 120:
        raise CredentialStoreError("principal_label exceeds 120 characters")
    return normalized


def _now(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise CredentialStoreError("now must be timezone-aware")
    return value.astimezone(timezone.utc)


def _expiry(value: Any, *, now: datetime) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise CredentialStoreError("expires_at must be timezone-aware")
    normalized = value.astimezone(timezone.utc)
    if normalized <= now:
        raise CredentialStoreError("expires_at must be in the future")
    return normalized


def _validate_kind_placement(*, auth_kind: str, target_kind: str, principal_slot: str) -> None:
    if auth_kind in SSH_CREDENTIAL_KINDS:
        if target_kind not in {"network", "device"}:
            raise CredentialStoreError("SSH credentials require a network or device target")
        if principal_slot != "ssh":
            raise CredentialStoreError("SSH credentials require principal_slot=ssh")
    elif target_kind == "network":
        raise CredentialStoreError("HTTP credentials cannot bind to a network target")
    elif principal_slot == "ssh":
        raise CredentialStoreError("HTTP credentials cannot use principal_slot=ssh")


def _ciphertext(value: Any, *, name: str) -> str:
    normalized = str(value or "")
    if not normalized.startswith(_CIPHERTEXT_PREFIX) or len(normalized) <= len(_CIPHERTEXT_PREFIX):
        raise CredentialStoreError(f"{name} must be Fernet ciphertext")
    if len(normalized) > 1_000_000:
        raise CredentialStoreError(f"{name} exceeds the storage limit")
    return normalized


def _positive_version(value: Any, *, name: str) -> int:
    if isinstance(value, bool):
        raise CredentialStoreError(f"{name} must be a positive integer")
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise CredentialStoreError(f"{name} must be a positive integer") from exc
    if normalized <= 0:
        raise CredentialStoreError(f"{name} must be a positive integer")
    return normalized


def _public_configuration(value: Any, *, auth_kind: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CredentialStoreError("configuration must be an object")
    result = dict(value)
    unknown = set(result) - PUBLIC_CONFIGURATION_KEYS
    if unknown:
        raise CredentialStoreError(
            f"configuration contains unsupported keys: {', '.join(sorted(unknown))}"
        )
    if str(result.get("auth_kind") or "") != auth_kind:
        raise CredentialStoreError("configuration auth_kind does not match profile")
    if result.get("secret_values_visible") is not False:
        raise CredentialStoreError("configuration must declare secret_values_visible=false")
    return result


def _capabilities(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or len(value) > 128:
        raise CredentialStoreError("allowed_capabilities must contain at most 128 names")
    result: list[str] = []
    for raw in value:
        name = str(raw or "").strip()
        if not _CAPABILITY_RE.fullmatch(name):
            raise CredentialStoreError("allowed_capabilities contains an invalid name")
        if name not in result:
            result.append(name)
    return result


def _raise_write_error(exc: Exception, *, conflict_message: str) -> NoReturn:
    if str(getattr(exc, "sqlstate", "") or "") == "23505":
        raise CredentialStoreConflict(conflict_message) from exc
    raise CredentialStoreError("credential profile database write failed") from exc


@dataclass(frozen=True)
class CredentialProfileMetadata:
    profile_id: str
    target_kind: str
    target_id: str
    name: str
    auth_kind: str
    principal_label: str | None
    principal_slot: str
    configuration: Mapping[str, Any]
    current_version: int
    record_version: int
    is_active: bool
    expires_at: datetime | None
    rotated_at: datetime
    created_at: datetime
    updated_at: datetime
    allowed_capabilities: tuple[str, ...] = ()

    @classmethod
    def from_row(cls, value: Any) -> "CredentialProfileMetadata":
        item = _row(value)
        configuration = item.get("configuration_json")
        if isinstance(configuration, str):
            try:
                configuration = json.loads(configuration)
            except json.JSONDecodeError as exc:
                raise CredentialStoreError("stored configuration is invalid JSON") from exc
        kind = _auth_kind(item.get("auth_kind"))
        raw_capabilities = item.get("allowed_capabilities") or []
        if isinstance(raw_capabilities, str):
            try:
                raw_capabilities = json.loads(raw_capabilities)
            except json.JSONDecodeError as exc:
                raise CredentialStoreError("stored capability binding is invalid") from exc
        return cls(
            profile_id=str(_profile_id(item.get("id"))),
            target_kind=_target_kind(item.get("target_kind")),
            target_id=str(_target_id(item.get("target_id"))),
            name=_name(item.get("name")),
            auth_kind=kind,
            principal_label=_principal_label(item.get("principal_label")),
            principal_slot=_principal_slot(item.get("principal_slot")),
            configuration=_public_configuration(configuration, auth_kind=kind),
            current_version=_positive_version(
                item.get("current_version"), name="current_version"
            ),
            record_version=_positive_version(
                item.get("record_version"), name="record_version"
            ),
            is_active=bool(item.get("is_active")),
            expires_at=item.get("expires_at"),
            rotated_at=item["rotated_at"],
            created_at=item["created_at"],
            updated_at=item["updated_at"],
            allowed_capabilities=tuple(_capabilities(raw_capabilities)),
        )

    def public_dict(self) -> dict[str, Any]:
        return {
            "id": self.profile_id,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "name": self.name,
            "auth_kind": self.auth_kind,
            "principal_label": self.principal_label,
            "principal_slot": self.principal_slot,
            "configuration": dict(self.configuration),
            "current_version": self.current_version,
            "record_version": self.record_version,
            "is_active": self.is_active,
            "expires_at": self.expires_at,
            "rotated_at": self.rotated_at,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "allowed_capabilities": list(self.allowed_capabilities),
            "secret_configured": True,
            "secret_values_visible": False,
        }


@dataclass(frozen=True)
class WorkerCredentialCiphertext:
    metadata: CredentialProfileMetadata
    encrypted_secret: str
    encrypted_metadata: str
    allowed_capabilities: tuple[str, ...]


class PostgresCredentialProfileStore:
    async def ensure_schema(self, conn: CredentialDatabase) -> None:
        await conn.execute(CREDENTIAL_PROFILE_SCHEMA_SQL)

    async def create_profile(
        self,
        conn: CredentialDatabase,
        *,
        target_kind: str,
        target_id: Any,
        name: str,
        auth_kind: str,
        principal_slot: str,
        principal_label: str | None,
        configuration: Mapping[str, Any],
        encrypted_secret: str,
        encrypted_metadata: str,
        expires_at: datetime | None,
        allowed_capabilities: list[str] | tuple[str, ...] = (),
        created_by: str = "api",
        profile_id: Any | None = None,
        now: datetime,
    ) -> CredentialProfileMetadata:
        timestamp = _now(now)
        kind = _auth_kind(auth_kind)
        profile_uuid = _profile_id(profile_id or uuid.uuid4())
        target_uuid = _target_id(target_id)
        normalized_target_kind = _target_kind(target_kind)
        normalized_name = _name(name)
        slot = _principal_slot(principal_slot)
        _validate_kind_placement(
            auth_kind=kind, target_kind=normalized_target_kind, principal_slot=slot
        )
        label = _principal_label(principal_label)
        public = _public_configuration(configuration, auth_kind=kind)
        secret = _ciphertext(encrypted_secret, name="encrypted_secret")
        metadata = _ciphertext(encrypted_metadata, name="encrypted_metadata")
        capabilities = _capabilities(allowed_capabilities)
        actor = str(created_by or "api").strip()[:120] or "api"
        try:
            row = await conn.fetchrow(
                """INSERT INTO credential_profiles (
                       id, target_kind, target_id, name, auth_kind, principal_label,
                       principal_slot, configuration_json, current_version, record_version,
                       is_active, expires_at, rotated_at, created_at, updated_at
                   ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,1,1,true,$9,$10,$10,$10)
                   RETURNING *""",
                profile_uuid,
                normalized_target_kind,
                target_uuid,
                normalized_name,
                kind,
                label,
                slot,
                json.dumps(public, sort_keys=True, separators=(",", ":")),
                _expiry(expires_at, now=timestamp),
                timestamp,
            )
        except Exception as exc:
            _raise_write_error(
                exc, conflict_message="credential profile identity already exists"
            )
        if not row:
            raise CredentialStoreError("credential profile insert returned no row")
        await conn.execute(
            """INSERT INTO credential_profile_versions (
                   profile_id, version, auth_kind, encrypted_secret, encrypted_metadata,
                   created_by, created_at
               ) VALUES ($1,1,$2,$3,$4,$5,$6)""",
            profile_uuid,
            kind,
            secret,
            metadata,
            actor,
            timestamp,
        )
        await conn.execute(
            """INSERT INTO credential_profile_bindings (
                   id, profile_id, binding_kind, binding_id, allowed_capabilities,
                   is_active, created_at, updated_at
               ) VALUES ($1,$2,'target',$3,$4::jsonb,true,$5,$5)""",
            uuid.uuid4(),
            profile_uuid,
            str(target_uuid),
            json.dumps(capabilities, separators=(",", ":")),
            timestamp,
        )
        return await self.get_profile(conn, profile_id=profile_uuid)

    async def list_profiles(
        self,
        conn: CredentialDatabase,
        *,
        target_kind: str,
        target_id: Any,
        include_inactive: bool = False,
    ) -> list[CredentialProfileMetadata]:
        rows = await conn.fetch(
            """SELECT p.*, b.allowed_capabilities
               FROM credential_profiles p
               LEFT JOIN credential_profile_bindings b
                 ON b.profile_id=p.id AND b.binding_kind='target'
                AND b.binding_id=p.target_id::text
               WHERE p.target_kind=$1 AND p.target_id=$2
                 AND ($3::boolean OR p.is_active=true)
               ORDER BY p.is_active DESC, lower(p.name), p.id""",
            _target_kind(target_kind),
            _target_id(target_id),
            bool(include_inactive),
        )
        return [CredentialProfileMetadata.from_row(item) for item in rows]

    async def get_profile(
        self,
        conn: CredentialDatabase,
        *,
        profile_id: Any,
    ) -> CredentialProfileMetadata:
        row = await conn.fetchrow(
            """SELECT p.*, b.allowed_capabilities
               FROM credential_profiles p
               LEFT JOIN credential_profile_bindings b
                 ON b.profile_id=p.id AND b.binding_kind='target'
                AND b.binding_id=p.target_id::text
               WHERE p.id=$1""",
            _profile_id(profile_id),
        )
        if not row:
            raise CredentialStoreError("credential profile not found")
        return CredentialProfileMetadata.from_row(row)

    async def update_profile_metadata(
        self,
        conn: CredentialDatabase,
        *,
        profile_id: Any,
        expected_record_version: int,
        name: str,
        principal_label: str | None,
        principal_slot: str,
        expires_at: datetime | None,
        expires_at_changed: bool,
        is_active: bool,
        allowed_capabilities: list[str] | tuple[str, ...] | None,
        now: datetime,
    ) -> CredentialProfileMetadata:
        timestamp = _now(now)
        profile_uuid = _profile_id(profile_id)
        row = await conn.fetchrow(
            "SELECT * FROM credential_profiles WHERE id=$1 FOR UPDATE",
            profile_uuid,
        )
        if not row:
            raise CredentialStoreError("credential profile not found")
        existing = CredentialProfileMetadata.from_row(row)
        if existing.record_version != _positive_version(
            expected_record_version, name="expected_record_version"
        ):
            raise CredentialStoreConflict("credential profile was modified concurrently")
        slot = _principal_slot(principal_slot)
        _validate_kind_placement(
            auth_kind=existing.auth_kind,
            target_kind=existing.target_kind,
            principal_slot=slot,
        )
        normalized_expiry = (
            _expiry(expires_at, now=timestamp)
            if expires_at_changed
            else existing.expires_at
        )
        capabilities_json = (
            json.dumps(_capabilities(allowed_capabilities), separators=(",", ":"))
            if allowed_capabilities is not None
            else None
        )
        try:
            updated = await conn.fetchrow(
                """UPDATE credential_profiles
                   SET name=$1, principal_label=$2, principal_slot=$3, expires_at=$4,
                       is_active=$5, record_version=record_version+1, updated_at=$6
                   WHERE id=$7 AND record_version=$8
                   RETURNING *""",
                _name(name),
                _principal_label(principal_label),
                slot,
                normalized_expiry,
                bool(is_active),
                timestamp,
                profile_uuid,
                existing.record_version,
            )
        except Exception as exc:
            _raise_write_error(
                exc, conflict_message="credential profile identity already exists"
            )
        if not updated:
            raise CredentialStoreConflict("credential profile was modified concurrently")
        await conn.execute(
            """UPDATE credential_profile_bindings
               SET allowed_capabilities=COALESCE($1::jsonb, allowed_capabilities),
                   is_active=$2, updated_at=$3
               WHERE profile_id=$4 AND binding_kind='target'
                 AND binding_id=$5""",
            capabilities_json,
            bool(is_active),
            timestamp,
            profile_uuid,
            existing.target_id,
        )
        return await self.get_profile(conn, profile_id=profile_uuid)

    async def rotate_profile(
        self,
        conn: CredentialDatabase,
        *,
        profile_id: Any,
        target_kind: str,
        target_id: Any,
        expected_record_version: int,
        encrypted_secret: str,
        encrypted_metadata: str,
        configuration: Mapping[str, Any],
        expires_at: datetime | None,
        created_by: str,
        now: datetime,
    ) -> CredentialProfileMetadata:
        timestamp = _now(now)
        profile_uuid = _profile_id(profile_id)
        row = await conn.fetchrow(
            """SELECT * FROM credential_profiles
               WHERE id=$1 AND target_kind=$2 AND target_id=$3
               FOR UPDATE""",
            profile_uuid,
            _target_kind(target_kind),
            _target_id(target_id),
        )
        if not row:
            raise CredentialStoreError("credential profile is unavailable for target")
        existing = CredentialProfileMetadata.from_row(row)
        if existing.record_version != int(expected_record_version):
            raise CredentialStoreConflict("credential profile was modified concurrently")
        secret = _ciphertext(encrypted_secret, name="encrypted_secret")
        metadata = _ciphertext(encrypted_metadata, name="encrypted_metadata")
        public = _public_configuration(configuration, auth_kind=existing.auth_kind)
        next_version = existing.current_version + 1
        await conn.execute(
            """INSERT INTO credential_profile_versions (
                   profile_id, version, auth_kind, encrypted_secret, encrypted_metadata,
                   created_by, created_at
               ) VALUES ($1,$2,$3,$4,$5,$6,$7)""",
            profile_uuid,
            next_version,
            existing.auth_kind,
            secret,
            metadata,
            str(created_by or "api").strip()[:120] or "api",
            timestamp,
        )
        updated = await conn.fetchrow(
            """UPDATE credential_profiles
               SET current_version=$1, record_version=record_version+1,
                   configuration_json=$2::jsonb, expires_at=$3, is_active=true,
                   rotated_at=$4, updated_at=$4
               WHERE id=$5 AND record_version=$6
               RETURNING *""",
            next_version,
            json.dumps(public, sort_keys=True, separators=(",", ":")),
            _expiry(expires_at, now=timestamp),
            timestamp,
            profile_uuid,
            existing.record_version,
        )
        if not updated:
            raise CredentialStoreConflict("credential profile was modified concurrently")
        return await self.get_profile(conn, profile_id=profile_uuid)

    async def load_for_worker(
        self,
        conn: CredentialDatabase,
        *,
        profile_id: Any,
        target_kind: str,
        target_id: Any,
        capability: str,
    ) -> WorkerCredentialCiphertext:
        capability_name = str(capability or "").strip()
        if not _CAPABILITY_RE.fullmatch(capability_name):
            raise CredentialStoreError("capability is invalid")
        row = await conn.fetchrow(
            """SELECT p.*, v.encrypted_secret, v.encrypted_metadata,
                      b.allowed_capabilities
               FROM credential_profiles p
               JOIN credential_profile_versions v
                 ON v.profile_id=p.id AND v.version=p.current_version
               JOIN credential_profile_bindings b
                 ON b.profile_id=p.id AND b.binding_kind='target'
                AND b.binding_id=p.target_id::text AND b.is_active=true
               WHERE p.id=$1 AND p.target_kind=$2 AND p.target_id=$3
                 AND p.is_active=true
                 AND (p.expires_at IS NULL OR p.expires_at > NOW())""",
            _profile_id(profile_id),
            _target_kind(target_kind),
            _target_id(target_id),
        )
        if not row:
            raise CredentialStoreError("credential profile is unavailable for target")
        item = _row(row)
        raw_capabilities = item.get("allowed_capabilities") or []
        if isinstance(raw_capabilities, str):
            try:
                raw_capabilities = json.loads(raw_capabilities)
            except json.JSONDecodeError as exc:
                raise CredentialStoreError("stored capability binding is invalid") from exc
        allowed = tuple(_capabilities(raw_capabilities))
        if allowed and capability_name not in allowed:
            raise CredentialStoreError("credential profile is not allowed for capability")
        return WorkerCredentialCiphertext(
            metadata=CredentialProfileMetadata.from_row(item),
            encrypted_secret=_ciphertext(item.get("encrypted_secret"), name="encrypted_secret"),
            encrypted_metadata=_ciphertext(
                item.get("encrypted_metadata"), name="encrypted_metadata"
            ),
            allowed_capabilities=allowed,
        )

    async def deactivate_profile(
        self,
        conn: CredentialDatabase,
        *,
        profile_id: Any,
        target_kind: str,
        target_id: Any,
        now: datetime,
    ) -> CredentialProfileMetadata:
        timestamp = _now(now)
        profile_uuid = _profile_id(profile_id)
        row = await conn.fetchrow(
            """UPDATE credential_profiles
               SET is_active=false, record_version=record_version+1, updated_at=$1
               WHERE id=$2 AND target_kind=$3 AND target_id=$4
               RETURNING *""",
            timestamp,
            profile_uuid,
            _target_kind(target_kind),
            _target_id(target_id),
        )
        if not row:
            raise CredentialStoreError("credential profile is unavailable for target")
        await conn.execute(
            """UPDATE credential_profile_bindings
               SET is_active=false, updated_at=$1
               WHERE profile_id=$2 AND is_active=true""",
            timestamp,
            profile_uuid,
        )
        return await self.get_profile(conn, profile_id=profile_uuid)
