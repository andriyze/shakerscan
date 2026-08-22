"""One-way compatibility adapters from legacy credential tables to V2 profiles.

The adapters never return or log secret material. Existing Fernet ciphertext is copied
into an immutable generic version and is parsed only after worker-side authorization.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Mapping
import uuid

from .credential_store import (
    CredentialProfileMetadata,
    CredentialStoreError,
    PostgresCredentialProfileStore,
)
from .credentials import public_credential_configuration

try:
    from secret_store import SecretStoreUnavailable, encrypt_secret
except ModuleNotFoundError:
    from api.secret_store import SecretStoreUnavailable, encrypt_secret


LEGACY_WEB_MIGRATION = "v2_target_credentials_to_generic_v1"
LEGACY_WEB_CAPABILITIES = ("request.replay", "scan.execute")
_CIPHERTEXT_PREFIX = "enc:fernet:"


class LegacyCredentialMigrationError(RuntimeError):
    """A legacy credential cannot be represented without weakening V2 invariants."""


def _row(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    try:
        return dict(value)
    except (TypeError, ValueError) as exc:
        raise LegacyCredentialMigrationError("legacy credential row is invalid") from exc


def _utc(value: Any) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise LegacyCredentialMigrationError("legacy credential expiry is invalid")
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _encrypted(value: Any) -> str:
    text = str(value or "")
    if not text:
        raise LegacyCredentialMigrationError("legacy credential has no secret material")
    if text.startswith(_CIPHERTEXT_PREFIX):
        return text
    try:
        encrypted = encrypt_secret(text)
    except SecretStoreUnavailable as exc:
        raise LegacyCredentialMigrationError(
            "legacy plaintext credential cannot be migrated because encryption is unavailable"
        ) from exc
    if not isinstance(encrypted, str) or not encrypted.startswith(_CIPHERTEXT_PREFIX):
        raise LegacyCredentialMigrationError("legacy credential encryption is unavailable")
    return encrypted


def _private_metadata(*, source_id: str) -> str:
    payload = json.dumps({
        "schema_version": "credential-private-metadata/v1",
        "created_by": "migration:target_credential_profiles",
        "legacy_source": "target_credential_profiles",
        "legacy_source_id": source_id,
    }, sort_keys=True, separators=(",", ":"))
    return _encrypted(payload)


async def _legacy_web_slot(
    conn: Any, *, target_id: uuid.UUID, profile_name: str,
) -> tuple[str, str | None]:
    rows = await conn.fetch(
        """SELECT auth_state, label
           FROM target_principals
           WHERE target_id=$1 AND lower(credential_profile)=lower($2)
             AND is_active=true AND auth_state IN ('user1','user2')
           ORDER BY CASE auth_state WHEN 'user1' THEN 0 ELSE 1 END, updated_at DESC""",
        target_id,
        profile_name,
    )
    states = {str(row["auth_state"]) for row in rows}
    slot = "secondary" if states == {"user2"} else "primary"
    label = next(
        (str(row["label"]) for row in rows if str(row["auth_state"]) == ("user2" if slot == "secondary" else "user1")),
        None,
    )
    return slot, label


def _same_time(left: datetime | None, right: datetime | None) -> bool:
    return _utc(left) == _utc(right)


async def _existing_profile(
    store: PostgresCredentialProfileStore, conn: Any, profile_id: uuid.UUID,
) -> CredentialProfileMetadata | None:
    try:
        return await store.get_profile(conn, profile_id=profile_id)
    except CredentialStoreError as exc:
        if "not found" in str(exc):
            return None
        raise


async def sync_legacy_web_credential(
    conn: Any,
    profile_id: Any,
    *,
    store: PostgresCredentialProfileStore | None = None,
    now: datetime | None = None,
) -> CredentialProfileMetadata | None:
    """Mirror one legacy Web credential into its deterministic generic profile ID."""
    try:
        legacy_id = uuid.UUID(str(profile_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise LegacyCredentialMigrationError("legacy credential id is invalid") from exc
    row_value = await conn.fetchrow(
        "SELECT * FROM target_credential_profiles WHERE id=$1",
        legacy_id,
    )
    if not row_value:
        raise LegacyCredentialMigrationError("legacy Web credential is unavailable")
    legacy = _row(row_value)
    target_id = uuid.UUID(str(legacy.get("target_id") or ""))
    name = str(legacy.get("name") or "").strip()
    kind = str(legacy.get("auth_kind") or "").strip().lower()
    if kind not in {"authorization_header", "cookie"}:
        raise LegacyCredentialMigrationError("legacy Web credential kind is unsupported")
    if not name:
        raise LegacyCredentialMigrationError("legacy Web credential name is invalid")

    repository = store or PostgresCredentialProfileStore()
    raw_now = now or datetime.now(timezone.utc)
    if raw_now.tzinfo is None:
        raise LegacyCredentialMigrationError("legacy credential migration time is invalid")
    timestamp = raw_now.astimezone(timezone.utc)
    expires_at = _utc(legacy.get("expires_at"))
    active = bool(legacy.get("is_active", True)) and (
        expires_at is None or expires_at > timestamp
    )
    existing = await _existing_profile(repository, conn, legacy_id)
    slot, principal_label = await _legacy_web_slot(
        conn, target_id=target_id, profile_name=name,
    )
    configuration = public_credential_configuration({"auth_kind": kind})
    ciphertext = _encrypted(legacy.get("secret_value"))
    created_new = existing is None
    if existing is None:
        created_at = min(_utc(legacy.get("created_at")) or timestamp, timestamp)
        create_expiry = (
            expires_at if expires_at is not None and expires_at > created_at else None
        )
        existing = await repository.create_profile(
            conn,
            profile_id=legacy_id,
            target_kind="web",
            target_id=target_id,
            name=name,
            auth_kind=kind,
            principal_slot=slot,
            principal_label=principal_label,
            configuration=configuration,
            encrypted_secret=ciphertext,
            encrypted_metadata=_private_metadata(source_id=str(legacy_id)),
            expires_at=create_expiry,
            allowed_capabilities=LEGACY_WEB_CAPABILITIES,
            created_by="migration:target_credential_profiles",
            now=created_at,
        )

    if not active:
        if existing.is_active:
            return await repository.deactivate_profile(
                conn,
                profile_id=legacy_id,
                target_kind=existing.target_kind,
                target_id=existing.target_id,
                now=timestamp,
            )
        return existing
    if created_new:
        return existing

    if (
        existing.target_kind != "web"
        or existing.target_id != str(target_id)
        or existing.auth_kind != kind
    ):
        raise LegacyCredentialMigrationError(
            "legacy credential ID conflicts with a different generic profile"
        )
    current = await conn.fetchrow(
        """SELECT encrypted_secret FROM credential_profile_versions
           WHERE profile_id=$1 AND version=$2 AND auth_kind=$3""",
        legacy_id,
        existing.current_version,
        kind,
    )
    if not current:
        raise LegacyCredentialMigrationError("generic credential version is unavailable")
    if str(current["encrypted_secret"] or "") != ciphertext:
        existing = await repository.rotate_profile(
            conn,
            profile_id=legacy_id,
            target_kind="web",
            target_id=target_id,
            expected_record_version=existing.record_version,
            encrypted_secret=ciphertext,
            encrypted_metadata=_private_metadata(source_id=str(legacy_id)),
            configuration=configuration,
            expires_at=expires_at,
            created_by="migration:target_credential_profiles",
            now=timestamp,
        )

    metadata_changed = (
        existing.name != name
        or existing.principal_slot != slot
        or existing.principal_label != principal_label
        or not existing.is_active
        or not _same_time(existing.expires_at, expires_at)
        or tuple(existing.allowed_capabilities) != LEGACY_WEB_CAPABILITIES
    )
    if metadata_changed:
        existing = await repository.update_profile_metadata(
            conn,
            profile_id=legacy_id,
            expected_record_version=existing.record_version,
            name=name,
            principal_label=principal_label,
            principal_slot=slot,
            expires_at=expires_at,
            expires_at_changed=not _same_time(existing.expires_at, expires_at),
            is_active=True,
            allowed_capabilities=LEGACY_WEB_CAPABILITIES,
            now=timestamp,
        )
    return existing


async def sync_legacy_web_credential_by_name(
    conn: Any,
    *,
    target_id: Any,
    profile_name: str | None,
    store: PostgresCredentialProfileStore | None = None,
    now: datetime | None = None,
) -> CredentialProfileMetadata | None:
    name = str(profile_name or "").strip()
    if not name:
        return None
    row = await conn.fetchrow(
        """SELECT id FROM target_credential_profiles
           WHERE target_id=$1 AND lower(name)=lower($2)""",
        uuid.UUID(str(target_id)),
        name,
    )
    if not row:
        return None
    return await sync_legacy_web_credential(
        conn, row["id"], store=store, now=now,
    )


async def migrate_legacy_web_credentials(
    conn: Any,
    *,
    store: PostgresCredentialProfileStore | None = None,
    now: datetime | None = None,
) -> int:
    """Backfill every legacy Web credential once under the schema migration lock."""
    marker = await conn.fetchval(
        "SELECT 1 FROM app_schema_migrations WHERE name=$1",
        LEGACY_WEB_MIGRATION,
    )
    if marker:
        return 0
    rows = await conn.fetch("SELECT id FROM target_credential_profiles ORDER BY created_at, id")
    migrated = 0
    for row in rows:
        profile = await sync_legacy_web_credential(
            conn, row["id"], store=store, now=now,
        )
        if profile is not None:
            migrated += 1
    await conn.execute(
        "INSERT INTO app_schema_migrations(name) VALUES ($1) ON CONFLICT DO NOTHING",
        LEGACY_WEB_MIGRATION,
    )
    return migrated
