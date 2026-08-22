"""Metadata-only HTTP API for canonical Scan/Hunt credential profiles."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from typing import Any, Literal, Mapping
import uuid

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr

try:
    from runtime.credential_store import (
        CredentialProfileMetadata,
        CredentialStoreConflict,
        CredentialStoreError,
        PostgresCredentialProfileStore,
    )
    from runtime.credentials import (
        CREDENTIAL_KINDS,
        CredentialContractError,
        build_credential_secret,
        parse_credential_secret,
        public_credential_configuration,
    )
except ModuleNotFoundError:
    from api.runtime.credential_store import (
        CredentialProfileMetadata,
        CredentialStoreConflict,
        CredentialStoreError,
        PostgresCredentialProfileStore,
    )
    from api.runtime.credentials import (
        CREDENTIAL_KINDS,
        CredentialContractError,
        build_credential_secret,
        parse_credential_secret,
        public_credential_configuration,
    )

try:
    from secret_store import SecretStoreUnavailable, encrypt_secret, encryption_enabled
except ModuleNotFoundError:
    from api.secret_store import SecretStoreUnavailable, encrypt_secret, encryption_enabled


router = APIRouter(prefix="/credential-profiles", tags=["credentials"])
_store = PostgresCredentialProfileStore()


def public_credential_validation_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Strip rejected input and validation context that may contain credential values."""
    return [
        {
            "type": str(error.get("type") or "value_error"),
            "loc": list(error.get("loc") or ()),
            "msg": str(error.get("msg") or "Invalid credential request"),
        }
        for error in errors
    ]


class CredentialProfileCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_kind: Literal["web", "api", "network", "device"]
    target_id: uuid.UUID
    name: str = Field(min_length=1, max_length=120)
    auth_kind: str
    principal_label: str | None = Field(default=None, max_length=120)
    principal_slot: Literal["primary", "secondary", "service", "ssh"] = "primary"
    secret: SecretStr | None = None
    username: SecretStr | None = None
    secondary_secret: SecretStr | None = None
    header_name: str | None = Field(default=None, max_length=200)
    endpoint_url: str | None = Field(default=None, max_length=2_000)
    client_id: SecretStr | None = None
    scopes: list[str] = Field(default_factory=list, max_length=32)
    custom_headers: dict[str, SecretStr] | None = None
    expires_at: datetime | None = None
    allowed_capabilities: list[str] = Field(default_factory=list, max_length=128)
    created_by: str = Field(default="api", max_length=120)


class CredentialProfilePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_record_version: int = Field(gt=0)
    name: str | None = Field(default=None, min_length=1, max_length=120)
    principal_label: str | None = Field(default=None, max_length=120)
    principal_slot: Literal["primary", "secondary", "service", "ssh"] | None = None
    expires_at: datetime | None = None
    clear_expiry: bool = False
    is_active: bool | None = None
    allowed_capabilities: list[str] | None = Field(default=None, max_length=128)


class CredentialProfileRotate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_record_version: int = Field(gt=0)
    secret: SecretStr | None = None
    username: SecretStr | None = None
    secondary_secret: SecretStr | None = None
    header_name: str | None = Field(default=None, max_length=200)
    endpoint_url: str | None = Field(default=None, max_length=2_000)
    client_id: SecretStr | None = None
    scopes: list[str] = Field(default_factory=list, max_length=32)
    custom_headers: dict[str, SecretStr] | None = None
    expires_at: datetime | None = None
    clear_expiry: bool = False
    created_by: str = Field(default="api", max_length=120)


def _secret(value: SecretStr | None) -> str | None:
    return value.get_secret_value() if value is not None else None


def _custom_headers(value: Mapping[str, SecretStr] | None) -> dict[str, str] | None:
    if value is None:
        return None
    return {str(name): secret.get_secret_value() for name, secret in value.items()}


def _material(auth_kind: str, value: Any) -> tuple[str, dict[str, Any]]:
    kind = str(auth_kind or "").strip().lower()
    if kind not in CREDENTIAL_KINDS:
        raise HTTPException(status_code=422, detail="auth_kind is not supported")
    try:
        envelope = build_credential_secret(
            kind,
            secret=_secret(value.secret),
            username=_secret(value.username),
            secondary_secret=_secret(value.secondary_secret),
            header_name=value.header_name,
            endpoint_url=value.endpoint_url,
            client_id=_secret(value.client_id),
            scopes=value.scopes,
            custom_headers=_custom_headers(value.custom_headers),
        )
        configuration = public_credential_configuration(
            parse_credential_secret(kind, envelope)
        )
    except CredentialContractError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return envelope, configuration


def _encrypt(value: str) -> str:
    try:
        encrypted = encrypt_secret(value)
    except SecretStoreUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="credential encryption is unavailable",
        ) from exc
    if not isinstance(encrypted, str) or not encrypted.startswith("enc:fernet:"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="credential encryption is unavailable",
        )
    return encrypted


def _private_metadata(*, created_by: str) -> str:
    return _encrypt(json.dumps({
        "schema_version": "credential-private-metadata/v1",
        "created_by": str(created_by or "api")[:120],
    }, sort_keys=True, separators=(",", ":")))


def _pool(request: Request) -> Any:
    pool = getattr(request.app.state, "db_pool", None)
    if pool is None:
        raise HTTPException(status_code=503, detail="credential database is unavailable")
    return pool


async def _require_target(conn: Any, *, target_kind: str, target_id: uuid.UUID) -> None:
    if target_kind == "device":
        row = await conn.fetchrow(
            "SELECT id FROM device_targets WHERE id=$1 AND is_active=true", target_id
        )
    else:
        row = await conn.fetchrow(
            "SELECT id FROM targets WHERE id=$1 AND is_active=true", target_id
        )
    if not row:
        raise HTTPException(status_code=404, detail="active credential target not found")


def _public(profile: CredentialProfileMetadata) -> dict[str, Any]:
    result = profile.public_dict()
    now = datetime.now(timezone.utc)
    expires_at = profile.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if not profile.is_active:
        profile_status, refresh_required = "inactive", False
    elif expires_at is not None and expires_at <= now:
        profile_status, refresh_required = "expired", True
    else:
        profile_status = "active"
        refresh_required = bool(expires_at and expires_at <= now + timedelta(days=7))
    result.update({
        "status": profile_status,
        "refresh_required": refresh_required,
        "execution_compatible": profile_status == "active",
        "storage_encrypted": True,
        "encryption_available": encryption_enabled(),
    })
    return result


def _store_error(exc: CredentialStoreError) -> HTTPException:
    if isinstance(exc, CredentialStoreConflict):
        return HTTPException(status_code=409, detail=str(exc))
    if "not found" in str(exc) or "unavailable for target" in str(exc):
        return HTTPException(status_code=404, detail=str(exc))
    return HTTPException(status_code=422, detail=str(exc))


async def _legacy_web_profile(
    conn: Any, profile: CredentialProfileMetadata,
) -> dict[str, Any] | None:
    """Return the compatibility row sharing this migrated profile identity."""
    if profile.target_kind != "web":
        return None
    row = await conn.fetchrow(
        """SELECT id, target_id, auth_kind, name
           FROM target_credential_profiles WHERE id=$1""",
        uuid.UUID(profile.profile_id),
    )
    if not row:
        return None
    item = dict(row)
    if (
        str(item.get("target_id") or "") != profile.target_id
        or str(item.get("auth_kind") or "") != profile.auth_kind
    ):
        raise CredentialStoreError(
            "migrated legacy credential identity no longer matches its generic profile"
        )
    return item


async def _sync_legacy_web_from_generic(
    conn: Any,
    profile: CredentialProfileMetadata,
    *,
    material: Mapping[str, Any] | None = None,
    rotated_at: datetime | None = None,
) -> None:
    legacy = await _legacy_web_profile(conn, profile)
    if legacy is None:
        return
    secret_value = None
    if material is not None:
        secret = str(material.get("secret") or "")
        if not secret:
            raise CredentialStoreError("migrated legacy credential secret is invalid")
        secret_value = _encrypt(secret)
    timestamp = rotated_at or datetime.now(timezone.utc)
    legacy_name = str(legacy.get("name") or "")
    try:
        await conn.execute(
            """UPDATE target_credential_profiles
               SET name=$2, expires_at=$3, is_active=$4,
                   secret_value=COALESCE($5, secret_value),
                   rotated_at=CASE WHEN $5 IS NULL THEN rotated_at ELSE $6 END,
                   updated_at=$6
               WHERE id=$1""",
            uuid.UUID(profile.profile_id),
            profile.name,
            profile.expires_at,
            profile.is_active,
            secret_value,
            timestamp,
        )
        if legacy_name and legacy_name.lower() != profile.name.lower():
            await conn.execute(
                """UPDATE target_principals
                   SET credential_profile=$3, updated_at=$4
                   WHERE target_id=$1 AND lower(credential_profile)=lower($2)""",
                uuid.UUID(profile.target_id),
                legacy_name,
                profile.name,
                timestamp,
            )
    except Exception as exc:
        raise CredentialStoreError("legacy Web credential compatibility write failed") from exc


_GENERIC_TO_LEGACY_DEVICE_KIND = {
    "ssh_password": "ssh_password",
    "ssh_private_key": "ssh_private_key",
    "ssh_private_key_with_passphrase": "ssh_private_key",
    "authorization_header": "web_authorization_header",
    "cookie": "web_cookie",
    "form_login": "web_form",
}


async def _legacy_device_profile(
    conn: Any, profile: CredentialProfileMetadata,
) -> dict[str, Any] | None:
    if profile.target_kind != "device":
        return None
    row = await conn.fetchrow(
        """SELECT id, device_target_id, auth_kind, name
           FROM device_credential_profiles WHERE id=$1""",
        uuid.UUID(profile.profile_id),
    )
    if not row:
        return None
    item = dict(row)
    expected_kind = _GENERIC_TO_LEGACY_DEVICE_KIND.get(profile.auth_kind)
    if (
        str(item.get("device_target_id") or "") != profile.target_id
        or str(item.get("auth_kind") or "") != expected_kind
    ):
        raise CredentialStoreError(
            "migrated device credential identity no longer matches its generic profile"
        )
    return item


async def _sync_legacy_device_from_generic(
    conn: Any,
    profile: CredentialProfileMetadata,
    *,
    material: Mapping[str, Any] | None = None,
    rotated_at: datetime | None = None,
) -> None:
    legacy = await _legacy_device_profile(conn, profile)
    if legacy is None:
        return
    secret_value = None
    username = None
    login_path = None
    if material is not None:
        secret = str(material.get("secret") or "")
        if not secret:
            raise CredentialStoreError("migrated device credential secret is invalid")
        secret_value = _encrypt(json.dumps({
            "secret": secret,
            "secondary_secret": str(material.get("secondary_secret") or "") or None,
        }, sort_keys=True, separators=(",", ":")))
        username = str(material.get("username") or "").strip() or None
        login_path = str(material.get("endpoint_url") or "").strip() or None
    timestamp = rotated_at or datetime.now(timezone.utc)
    try:
        await conn.execute(
            """UPDATE device_credential_profiles
               SET name=$2, expires_at=$3, is_active=$4,
                   secret_value=COALESCE($5, secret_value),
                   username=CASE WHEN $5 IS NULL THEN username ELSE $6 END,
                   login_path=CASE WHEN $5 IS NULL THEN login_path ELSE $7 END,
                   rotated_at=CASE WHEN $5 IS NULL THEN rotated_at ELSE $8 END,
                   updated_at=$8
               WHERE id=$1""",
            uuid.UUID(profile.profile_id),
            profile.name,
            profile.expires_at,
            profile.is_active,
            secret_value,
            username,
            login_path,
            timestamp,
        )
    except Exception as exc:
        raise CredentialStoreError("legacy device credential compatibility write failed") from exc


async def _sync_legacy_from_generic(
    conn: Any,
    profile: CredentialProfileMetadata,
    *,
    material: Mapping[str, Any] | None = None,
    rotated_at: datetime | None = None,
) -> None:
    await _sync_legacy_web_from_generic(
        conn, profile, material=material, rotated_at=rotated_at,
    )
    await _sync_legacy_device_from_generic(
        conn, profile, material=material, rotated_at=rotated_at,
    )


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_credential_profile(request: Request, payload: CredentialProfileCreate):
    envelope, configuration = _material(payload.auth_kind, payload)
    pool = _pool(request)
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                await _require_target(
                    conn, target_kind=payload.target_kind, target_id=payload.target_id
                )
                profile = await _store.create_profile(
                    conn,
                    target_kind=payload.target_kind,
                    target_id=payload.target_id,
                    name=payload.name,
                    auth_kind=payload.auth_kind,
                    principal_slot=payload.principal_slot,
                    principal_label=payload.principal_label,
                    configuration=configuration,
                    encrypted_secret=_encrypt(envelope),
                    encrypted_metadata=_private_metadata(created_by=payload.created_by),
                    expires_at=payload.expires_at,
                    allowed_capabilities=payload.allowed_capabilities,
                    created_by=payload.created_by,
                    now=datetime.now(timezone.utc),
                )
    except CredentialStoreError as exc:
        raise _store_error(exc) from exc
    return {"profile": _public(profile)}


@router.get("")
async def list_credential_profiles(
    request: Request,
    target_kind: Literal["web", "api", "network", "device"],
    target_id: uuid.UUID,
    include_inactive: bool = Query(default=False),
):
    pool = _pool(request)
    try:
        async with pool.acquire() as conn:
            await _require_target(conn, target_kind=target_kind, target_id=target_id)
            profiles = await _store.list_profiles(
                conn,
                target_kind=target_kind,
                target_id=target_id,
                include_inactive=include_inactive,
            )
    except CredentialStoreError as exc:
        raise _store_error(exc) from exc
    return {
        "target_kind": target_kind,
        "target_id": str(target_id),
        "profiles": [_public(profile) for profile in profiles],
        "count": len(profiles),
    }


@router.get("/{profile_id}")
async def get_credential_profile(request: Request, profile_id: uuid.UUID):
    pool = _pool(request)
    try:
        async with pool.acquire() as conn:
            profile = await _store.get_profile(conn, profile_id=profile_id)
    except CredentialStoreError as exc:
        raise _store_error(exc) from exc
    return {"profile": _public(profile)}


@router.patch("/{profile_id}")
async def patch_credential_profile(
    request: Request,
    profile_id: uuid.UUID,
    payload: CredentialProfilePatch,
):
    pool = _pool(request)
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                existing = await _store.get_profile(conn, profile_id=profile_id)
                expiry_changed = payload.clear_expiry or "expires_at" in payload.model_fields_set
                expires_at = None if payload.clear_expiry else (
                    payload.expires_at if "expires_at" in payload.model_fields_set
                    else existing.expires_at
                )
                profile = await _store.update_profile_metadata(
                    conn,
                    profile_id=profile_id,
                    expected_record_version=payload.expected_record_version,
                    name=payload.name or existing.name,
                    principal_label=(
                        payload.principal_label
                        if "principal_label" in payload.model_fields_set
                        else existing.principal_label
                    ),
                    principal_slot=payload.principal_slot or existing.principal_slot,
                    expires_at=expires_at,
                    expires_at_changed=expiry_changed,
                    is_active=(
                        payload.is_active
                        if payload.is_active is not None
                        else existing.is_active
                    ),
                    allowed_capabilities=payload.allowed_capabilities,
                    now=datetime.now(timezone.utc),
                )
                await _sync_legacy_from_generic(conn, profile)
    except CredentialStoreError as exc:
        raise _store_error(exc) from exc
    return {"profile": _public(profile)}


@router.post("/{profile_id}/rotate")
async def rotate_credential_profile(
    request: Request,
    profile_id: uuid.UUID,
    payload: CredentialProfileRotate,
):
    pool = _pool(request)
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                existing = await _store.get_profile(conn, profile_id=profile_id)
                envelope, configuration = _material(existing.auth_kind, payload)
                expires_at = None if payload.clear_expiry else (
                    payload.expires_at
                    if "expires_at" in payload.model_fields_set
                    else existing.expires_at
                )
                timestamp = datetime.now(timezone.utc)
                profile = await _store.rotate_profile(
                    conn,
                    profile_id=profile_id,
                    target_kind=existing.target_kind,
                    target_id=existing.target_id,
                    expected_record_version=payload.expected_record_version,
                    encrypted_secret=_encrypt(envelope),
                    encrypted_metadata=_private_metadata(created_by=payload.created_by),
                    configuration=configuration,
                    expires_at=expires_at,
                    created_by=payload.created_by,
                    now=timestamp,
                )
                await _sync_legacy_from_generic(
                    conn,
                    profile,
                    material=parse_credential_secret(existing.auth_kind, envelope),
                    rotated_at=timestamp,
                )
    except CredentialStoreError as exc:
        raise _store_error(exc) from exc
    return {"profile": _public(profile)}


@router.delete("/{profile_id}")
async def delete_credential_profile(request: Request, profile_id: uuid.UUID):
    pool = _pool(request)
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                existing = await _store.get_profile(conn, profile_id=profile_id)
                profile = await _store.deactivate_profile(
                    conn,
                    profile_id=profile_id,
                    target_kind=existing.target_kind,
                    target_id=existing.target_id,
                    now=datetime.now(timezone.utc),
                )
                await _sync_legacy_from_generic(conn, profile)
    except CredentialStoreError as exc:
        raise _store_error(exc) from exc
    return {"status": "deactivated", "profile": _public(profile)}
