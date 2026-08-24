"""Compatibility adapters from legacy credential tables to V2 profiles.

The adapters never return or log secret material. Legacy Web ciphertext can be copied
unchanged; older device envelopes are canonicalized only in bounded migration memory.
Normal execution still resolves and decrypts generic profiles only on authorized workers.
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
from .credentials import (
    build_credential_secret,
    parse_credential_secret,
    public_credential_configuration,
)

try:
    from secret_store import SecretStoreUnavailable, decrypt_secret, encrypt_secret
except ModuleNotFoundError:
    from api.secret_store import SecretStoreUnavailable, decrypt_secret, encrypt_secret


LEGACY_WEB_MIGRATION = "v2_target_credentials_to_generic_v1"
LEGACY_DEVICE_MIGRATION = "v2_device_credentials_to_generic_v1"
LEGACY_AI_MIGRATION = "v2_ai_credentials_to_generic_v1"
LEGACY_WEB_CAPABILITIES = (
    "auth.session.establish",
    "auth.session.refresh",
    "auth.session.revoke",
    "authz.verify",
    "http.request",
    "request.replay",
    "scan.execute",
)
LEGACY_DEVICE_WEB_CAPABILITIES = ("request.replay", "device.http.probe")
LEGACY_DEVICE_SSH_CAPABILITIES = ("device.ssh.propose",)
LEGACY_AI_CAPABILITIES = (
    "ai_gate.scan",
    "ai_gate.connectivity",
    "ai_gate.mcp_readiness",
)
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


def _device_private_metadata(legacy: Mapping[str, Any]) -> str:
    payload = json.dumps({
        "schema_version": "credential-private-metadata/v1",
        "created_by": "migration:device_credential_profiles",
        "legacy_source": "device_credential_profiles",
        "legacy_source_id": str(legacy.get("id") or ""),
        "legacy_port": legacy.get("port"),
    }, sort_keys=True, separators=(",", ":"))
    return _encrypted(payload)


def _ai_private_metadata(legacy: Mapping[str, Any], *, source: str) -> str:
    payload = json.dumps({
        "schema_version": "credential-private-metadata/v1",
        "created_by": f"migration:{source}",
        "legacy_source": source,
        "legacy_source_id": str(legacy.get("id") or ""),
    }, sort_keys=True, separators=(",", ":"))
    return _encrypted(payload)


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str) and value.strip():
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise LegacyCredentialMigrationError(
                "legacy credential metadata is invalid"
            ) from exc
        if isinstance(decoded, Mapping):
            return dict(decoded)
    return {}


def _legacy_ai_material(
    legacy: Mapping[str, Any],
) -> tuple[str, str, dict[str, Any]] | None:
    legacy_kind = str(legacy.get("auth_kind") or "none").strip().lower()
    if legacy_kind == "none":
        return None
    try:
        decrypted = decrypt_secret(legacy.get("secret_value"))
    except SecretStoreUnavailable as exc:
        raise LegacyCredentialMigrationError(
            "legacy AI credential cannot be decrypted for migration"
        ) from exc
    secret = str(decrypted or "")
    metadata = _json_object(legacy.get("metadata_json"))
    header_name = str(legacy.get("header_name") or "").strip() or None
    kwargs: dict[str, Any] = {}
    if legacy_kind == "bearer":
        generic_kind = "bearer_token"
        kwargs["secret"] = secret
    elif legacy_kind in {"api_key_header", "custom_header"}:
        generic_kind = "api_key_header"
        kwargs.update(secret=secret, header_name=header_name)
    elif legacy_kind == "basic_auth":
        generic_kind = "basic_auth"
        username, separator, password = secret.partition(":")
        if not separator:
            raise LegacyCredentialMigrationError(
                "legacy AI basic authentication must contain username:password"
            )
        kwargs.update(username=username, secret=password)
    elif legacy_kind == "cookie":
        generic_kind = "cookie"
        kwargs["secret"] = secret
    elif legacy_kind == "multi_header":
        generic_kind = "custom_headers"
        try:
            pairs = json.loads(secret)
        except json.JSONDecodeError as exc:
            raise LegacyCredentialMigrationError(
                "legacy AI multi-header credential is invalid"
            ) from exc
        if not isinstance(pairs, list):
            raise LegacyCredentialMigrationError(
                "legacy AI multi-header credential is invalid"
            )
        headers: dict[str, str] = {}
        lowered: set[str] = set()
        for pair in pairs:
            if not isinstance(pair, Mapping):
                raise LegacyCredentialMigrationError(
                    "legacy AI multi-header credential is invalid"
                )
            name = str(pair.get("name") or "").strip()
            value = str(pair.get("value") or "")
            if not name or not value or name.lower() in lowered:
                raise LegacyCredentialMigrationError(
                    "legacy AI multi-header credential is invalid"
                )
            lowered.add(name.lower())
            headers[name] = value
        kwargs["custom_headers"] = headers
    elif legacy_kind == "query_param":
        generic_kind = "query_parameter"
        kwargs.update(
            secret=secret,
            parameter_name=header_name or str(metadata.get("param_name") or "").strip(),
        )
    else:
        raise LegacyCredentialMigrationError(
            "legacy AI credential kind is unsupported"
        )
    try:
        envelope = build_credential_secret(generic_kind, **kwargs)
        configuration = public_credential_configuration(
            parse_credential_secret(generic_kind, envelope)
        )
    except Exception as exc:
        raise LegacyCredentialMigrationError(
            "legacy AI credential cannot satisfy the generic credential contract"
        ) from exc
    return generic_kind, envelope, configuration


def _ai_profile_identity(
    legacy: Mapping[str, Any], *, source: str,
) -> tuple[str, str | None, str]:
    if source == "ai_target_credentials":
        return "AI Gate default", None, "service"
    label = str(legacy.get("label") or "").strip()
    role = str(legacy.get("role") or "service").strip().lower()
    if not label:
        raise LegacyCredentialMigrationError("legacy AI principal label is invalid")
    suffix = str(legacy.get("id") or "").replace("-", "")[:8]
    name = f"AI Gate principal: {label} ({suffix})"
    if len(name) > 120:
        name = f"AI Gate principal: {label[:88].rstrip()} ({suffix})"
    slot = "primary" if role == "victim" else "secondary" if role == "attacker" else "service"
    return name, label, slot


def _legacy_device_material(
    legacy: Mapping[str, Any],
) -> tuple[str, str, str, dict[str, Any], tuple[str, ...]]:
    legacy_kind = str(legacy.get("auth_kind") or "").strip().lower()
    try:
        decrypted = decrypt_secret(legacy.get("secret_value"))
    except SecretStoreUnavailable as exc:
        raise LegacyCredentialMigrationError(
            "legacy device credential cannot be decrypted for migration"
        ) from exc
    try:
        secret_payload = json.loads(str(decrypted or ""))
    except json.JSONDecodeError as exc:
        raise LegacyCredentialMigrationError(
            "legacy device credential envelope is invalid"
        ) from exc
    if not isinstance(secret_payload, Mapping):
        raise LegacyCredentialMigrationError("legacy device credential envelope is invalid")
    secret = str(secret_payload.get("secret") or "")
    secondary = str(secret_payload.get("secondary_secret") or "") or None
    username = str(legacy.get("username") or "").strip() or None
    login_path = str(legacy.get("login_path") or "").strip() or None
    if legacy_kind == "ssh_password":
        generic_kind, slot = "ssh_password", "ssh"
        capabilities = LEGACY_DEVICE_SSH_CAPABILITIES
    elif legacy_kind == "ssh_private_key":
        generic_kind = "ssh_private_key_with_passphrase" if secondary else "ssh_private_key"
        slot = "ssh"
        capabilities = LEGACY_DEVICE_SSH_CAPABILITIES
    elif legacy_kind == "web_authorization_header":
        generic_kind, slot = "authorization_header", "service"
        capabilities = LEGACY_DEVICE_WEB_CAPABILITIES
    elif legacy_kind == "web_cookie":
        generic_kind, slot = "cookie", "service"
        capabilities = LEGACY_DEVICE_WEB_CAPABILITIES
    elif legacy_kind == "web_form":
        generic_kind, slot = "form_login", "service"
        capabilities = LEGACY_DEVICE_WEB_CAPABILITIES
    else:
        raise LegacyCredentialMigrationError("legacy device credential kind is unsupported")
    try:
        envelope = build_credential_secret(
            generic_kind,
            secret=secret,
            username=username,
            secondary_secret=secondary if legacy_kind == "ssh_private_key" else None,
            endpoint_url=login_path,
        )
        configuration = public_credential_configuration(
            parse_credential_secret(generic_kind, envelope)
        )
    except Exception as exc:
        raise LegacyCredentialMigrationError(
            "legacy device credential cannot satisfy the generic credential contract"
        ) from exc
    return generic_kind, slot, envelope, configuration, capabilities


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

    if (
        existing.target_kind != "web"
        or existing.target_id != str(target_id)
        or existing.auth_kind != kind
    ):
        raise LegacyCredentialMigrationError(
            "legacy credential ID conflicts with a different generic profile"
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

    current = await conn.fetchrow(
        """SELECT encrypted_secret FROM credential_profile_versions
           WHERE profile_id=$1 AND version=$2 AND auth_kind=$3""",
        legacy_id,
        existing.current_version,
        kind,
    )
    if not current:
        raise LegacyCredentialMigrationError("generic credential version is unavailable")
    legacy_rotated_at = _utc(legacy.get("rotated_at"))
    secret_changed = (
        legacy_rotated_at > existing.rotated_at.astimezone(timezone.utc)
        if legacy_rotated_at is not None
        else str(current["encrypted_secret"] or "") != ciphertext
    )
    if secret_changed:
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


async def sync_legacy_device_credential(
    conn: Any,
    profile_id: Any,
    *,
    store: PostgresCredentialProfileStore | None = None,
    now: datetime | None = None,
) -> CredentialProfileMetadata | None:
    """Canonicalize one encrypted legacy device envelope into a generic profile."""
    try:
        legacy_id = uuid.UUID(str(profile_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise LegacyCredentialMigrationError("legacy device credential id is invalid") from exc
    row_value = await conn.fetchrow(
        "SELECT * FROM device_credential_profiles WHERE id=$1",
        legacy_id,
    )
    if not row_value:
        raise LegacyCredentialMigrationError("legacy device credential is unavailable")
    legacy = _row(row_value)
    try:
        target_id = uuid.UUID(str(legacy.get("device_target_id") or ""))
    except (TypeError, ValueError, AttributeError) as exc:
        raise LegacyCredentialMigrationError(
            "legacy device credential target is invalid"
        ) from exc
    name = str(legacy.get("name") or "").strip()
    if not name:
        raise LegacyCredentialMigrationError("legacy device credential name is invalid")
    generic_kind, slot, envelope, configuration, capabilities = _legacy_device_material(legacy)
    ciphertext = _encrypted(envelope)
    repository = store or PostgresCredentialProfileStore()
    raw_now = now or datetime.now(timezone.utc)
    if raw_now.tzinfo is None:
        raise LegacyCredentialMigrationError("legacy device migration time is invalid")
    timestamp = raw_now.astimezone(timezone.utc)
    expires_at = _utc(legacy.get("expires_at"))
    active = bool(legacy.get("is_active", True)) and (
        expires_at is None or expires_at > timestamp
    )
    existing = await _existing_profile(repository, conn, legacy_id)
    created_new = existing is None
    if existing is None:
        created_at = min(_utc(legacy.get("created_at")) or timestamp, timestamp)
        create_expiry = (
            expires_at if expires_at is not None and expires_at > created_at else None
        )
        existing = await repository.create_profile(
            conn,
            profile_id=legacy_id,
            target_kind="device",
            target_id=target_id,
            name=name,
            auth_kind=generic_kind,
            principal_slot=slot,
            principal_label=None,
            configuration=configuration,
            encrypted_secret=ciphertext,
            encrypted_metadata=_device_private_metadata(legacy),
            expires_at=create_expiry,
            allowed_capabilities=capabilities,
            created_by="migration:device_credential_profiles",
            now=created_at,
        )
    if (
        existing.target_kind != "device"
        or existing.target_id != str(target_id)
        or existing.auth_kind != generic_kind
    ):
        raise LegacyCredentialMigrationError(
            "legacy device credential ID or authentication kind conflicts with its generic profile"
        )
    if not active:
        if existing.is_active:
            return await repository.deactivate_profile(
                conn,
                profile_id=legacy_id,
                target_kind="device",
                target_id=target_id,
                now=timestamp,
            )
        return existing
    if created_new:
        return existing
    legacy_rotated_at = _utc(legacy.get("rotated_at"))
    if legacy_rotated_at is None or legacy_rotated_at > existing.rotated_at.astimezone(timezone.utc):
        existing = await repository.rotate_profile(
            conn,
            profile_id=legacy_id,
            target_kind="device",
            target_id=target_id,
            expected_record_version=existing.record_version,
            encrypted_secret=ciphertext,
            encrypted_metadata=_device_private_metadata(legacy),
            configuration=configuration,
            expires_at=expires_at,
            created_by="migration:device_credential_profiles",
            now=timestamp,
        )
    metadata_changed = (
        existing.name != name
        or existing.principal_slot != slot
        or existing.principal_label is not None
        or not existing.is_active
        or not _same_time(existing.expires_at, expires_at)
        or tuple(existing.allowed_capabilities) != capabilities
    )
    if metadata_changed:
        existing = await repository.update_profile_metadata(
            conn,
            profile_id=legacy_id,
            expected_record_version=existing.record_version,
            name=name,
            principal_label=None,
            principal_slot=slot,
            expires_at=expires_at,
            expires_at_changed=not _same_time(existing.expires_at, expires_at),
            is_active=True,
            allowed_capabilities=capabilities,
            now=timestamp,
        )
    return existing


async def migrate_legacy_device_credentials(
    conn: Any,
    *,
    store: PostgresCredentialProfileStore | None = None,
    now: datetime | None = None,
) -> int:
    marker = await conn.fetchval(
        "SELECT 1 FROM app_schema_migrations WHERE name=$1",
        LEGACY_DEVICE_MIGRATION,
    )
    if marker:
        return 0
    rows = await conn.fetch("SELECT id FROM device_credential_profiles ORDER BY created_at, id")
    migrated = 0
    for row in rows:
        profile = await sync_legacy_device_credential(
            conn, row["id"], store=store, now=now,
        )
        if profile is not None:
            migrated += 1
    await conn.execute(
        "INSERT INTO app_schema_migrations(name) VALUES ($1) ON CONFLICT DO NOTHING",
        LEGACY_DEVICE_MIGRATION,
    )
    return migrated


async def _sync_legacy_ai_credential(
    conn: Any,
    profile_id: Any,
    *,
    source: str,
    store: PostgresCredentialProfileStore | None = None,
    now: datetime | None = None,
) -> CredentialProfileMetadata | None:
    if source not in {"ai_target_credentials", "ai_target_principals"}:
        raise LegacyCredentialMigrationError("legacy AI credential source is invalid")
    try:
        legacy_id = uuid.UUID(str(profile_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise LegacyCredentialMigrationError("legacy AI credential id is invalid") from exc
    if source == "ai_target_credentials":
        query = """SELECT c.*, t.is_active AS target_is_active
                   FROM ai_target_credentials c
                   JOIN ai_targets t ON t.id=c.ai_target_id
                   WHERE c.id=$1"""
    else:
        query = """SELECT p.*, t.is_active AS target_is_active
                   FROM ai_target_principals p
                   JOIN ai_targets t ON t.id=p.ai_target_id
                   WHERE p.id=$1"""
    row_value = await conn.fetchrow(query, legacy_id)
    if not row_value:
        raise LegacyCredentialMigrationError("legacy AI credential is unavailable")
    legacy = _row(row_value)
    try:
        target_id = uuid.UUID(str(legacy.get("ai_target_id") or ""))
    except (TypeError, ValueError, AttributeError) as exc:
        raise LegacyCredentialMigrationError(
            "legacy AI credential target is invalid"
        ) from exc
    repository = store or PostgresCredentialProfileStore()
    raw_now = now or datetime.now(timezone.utc)
    if raw_now.tzinfo is None:
        raise LegacyCredentialMigrationError("legacy AI migration time is invalid")
    timestamp = raw_now.astimezone(timezone.utc)
    existing = await _existing_profile(repository, conn, legacy_id)
    material = _legacy_ai_material(legacy)
    active = bool(legacy.get("target_is_active", True)) and (
        source == "ai_target_credentials" or bool(legacy.get("is_active", True))
    )
    if material is None:
        if existing is not None and (
            existing.target_kind != "api" or existing.target_id != str(target_id)
        ):
            raise LegacyCredentialMigrationError(
                "legacy AI credential ID conflicts with a different generic profile"
            )
        if existing is not None and existing.is_active:
            return await repository.deactivate_profile(
                conn,
                profile_id=legacy_id,
                target_kind=existing.target_kind,
                target_id=existing.target_id,
                now=timestamp,
            )
        return existing

    generic_kind, envelope, configuration = material
    name, principal_label, slot = _ai_profile_identity(legacy, source=source)
    created_new = existing is None
    if existing is None:
        created_at = min(_utc(legacy.get("created_at")) or timestamp, timestamp)
        existing = await repository.create_profile(
            conn,
            profile_id=legacy_id,
            target_kind="api",
            target_id=target_id,
            name=name,
            auth_kind=generic_kind,
            principal_slot=slot,
            principal_label=principal_label,
            configuration=configuration,
            encrypted_secret=_encrypted(envelope),
            encrypted_metadata=_ai_private_metadata(legacy, source=source),
            expires_at=None,
            allowed_capabilities=LEGACY_AI_CAPABILITIES,
            created_by=f"migration:{source}",
            now=created_at,
        )
    if (
        existing.target_kind != "api"
        or existing.target_id != str(target_id)
        or existing.auth_kind != generic_kind
    ):
        raise LegacyCredentialMigrationError(
            "legacy AI credential ID or authentication kind conflicts with its generic profile"
        )
    if not active:
        if existing.is_active:
            return await repository.deactivate_profile(
                conn,
                profile_id=legacy_id,
                target_kind="api",
                target_id=target_id,
                now=timestamp,
            )
        return existing
    if created_new:
        return existing

    legacy_rotated_at = _utc(legacy.get("rotated_at"))
    if legacy_rotated_at is None or legacy_rotated_at > existing.rotated_at.astimezone(timezone.utc):
        existing = await repository.rotate_profile(
            conn,
            profile_id=legacy_id,
            target_kind="api",
            target_id=target_id,
            expected_record_version=existing.record_version,
            encrypted_secret=_encrypted(envelope),
            encrypted_metadata=_ai_private_metadata(legacy, source=source),
            configuration=configuration,
            expires_at=None,
            created_by=f"migration:{source}",
            now=timestamp,
        )
    metadata_changed = (
        existing.name != name
        or existing.principal_slot != slot
        or existing.principal_label != principal_label
        or not existing.is_active
        or existing.expires_at is not None
        or tuple(existing.allowed_capabilities) != LEGACY_AI_CAPABILITIES
    )
    if metadata_changed:
        existing = await repository.update_profile_metadata(
            conn,
            profile_id=legacy_id,
            expected_record_version=existing.record_version,
            name=name,
            principal_label=principal_label,
            principal_slot=slot,
            expires_at=None,
            expires_at_changed=existing.expires_at is not None,
            is_active=True,
            allowed_capabilities=LEGACY_AI_CAPABILITIES,
            now=timestamp,
        )
    return existing


async def sync_legacy_ai_target_credential(
    conn: Any,
    profile_id: Any,
    *,
    store: PostgresCredentialProfileStore | None = None,
    now: datetime | None = None,
) -> CredentialProfileMetadata | None:
    return await _sync_legacy_ai_credential(
        conn, profile_id, source="ai_target_credentials", store=store, now=now,
    )


async def sync_legacy_ai_principal_credential(
    conn: Any,
    profile_id: Any,
    *,
    store: PostgresCredentialProfileStore | None = None,
    now: datetime | None = None,
) -> CredentialProfileMetadata | None:
    return await _sync_legacy_ai_credential(
        conn, profile_id, source="ai_target_principals", store=store, now=now,
    )


async def migrate_legacy_ai_credentials(
    conn: Any,
    *,
    store: PostgresCredentialProfileStore | None = None,
    now: datetime | None = None,
) -> int:
    marker = await conn.fetchval(
        "SELECT 1 FROM app_schema_migrations WHERE name=$1",
        LEGACY_AI_MIGRATION,
    )
    if marker:
        return 0
    default_rows = await conn.fetch(
        "SELECT id FROM ai_target_credentials ORDER BY created_at, id"
    )
    principal_rows = await conn.fetch(
        "SELECT id FROM ai_target_principals ORDER BY created_at, id"
    )
    migrated = 0
    for row in default_rows:
        profile = await sync_legacy_ai_target_credential(
            conn, row["id"], store=store, now=now,
        )
        if profile is not None:
            migrated += 1
    for row in principal_rows:
        profile = await sync_legacy_ai_principal_credential(
            conn, row["id"], store=store, now=now,
        )
        if profile is not None:
            migrated += 1
    await conn.execute(
        "INSERT INTO app_schema_migrations(name) VALUES ($1) ON CONFLICT DO NOTHING",
        LEGACY_AI_MIGRATION,
    )
    return migrated
