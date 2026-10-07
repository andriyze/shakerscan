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
        HTTP_CREDENTIAL_KINDS,
        SSH_CREDENTIAL_KINDS,
        CredentialContractError,
        build_credential_secret,
        parse_credential_secret,
        public_credential_configuration,
    )
    from runtime.capability_registry import CAPABILITY_REGISTRY
except ModuleNotFoundError:
    from api.runtime.credential_store import (
        CredentialProfileMetadata,
        CredentialStoreConflict,
        CredentialStoreError,
        PostgresCredentialProfileStore,
    )
    from api.runtime.credentials import (
        CREDENTIAL_KINDS,
        HTTP_CREDENTIAL_KINDS,
        SSH_CREDENTIAL_KINDS,
        CredentialContractError,
        build_credential_secret,
        parse_credential_secret,
        public_credential_configuration,
    )
    from api.runtime.capability_registry import CAPABILITY_REGISTRY

try:
    from secret_store import SecretStoreUnavailable, encrypt_secret, encryption_enabled
except ModuleNotFoundError:
    from api.secret_store import SecretStoreUnavailable, encrypt_secret, encryption_enabled


router = APIRouter(prefix="/credential-profiles", tags=["credentials"])
_store = PostgresCredentialProfileStore()
_approval_validator: Any = None


def configure_credential_api(*, approval_validator: Any) -> None:
    global _approval_validator
    _approval_validator = approval_validator


async def _require_active_capability_approval(
    conn: Any,
    *,
    approval_receipt_id: str | None,
    target_id: uuid.UUID,
) -> None:
    if _approval_validator is None:
        raise HTTPException(status_code=503, detail="credential approval validation is unavailable")
    await _approval_validator(
        conn,
        approval_receipt_id,
        target_id=target_id,
        action_name="credential_profile.active_capabilities",
        command="credential_profile.active_capabilities",
        risk_tier="credential",
        always_require_receipt=True,
        require_target_binding=True,
        require_expiry=True,
    )


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


CredentialAuthKind = Literal[
    "authorization_header",
    "bearer_token",
    "api_key_header",
    "cookie",
    "basic_auth",
    "form_login",
    "oauth_client_credentials",
    "oauth_password",
    "json_login",
    "custom_headers",
    "query_parameter",
    "ssh_password",
    "ssh_private_key",
    "ssh_private_key_with_passphrase",
]


class CredentialProfileCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_kind: Literal["web", "api", "network", "device"]
    target_id: uuid.UUID
    name: str = Field(min_length=1, max_length=120)
    auth_kind: CredentialAuthKind
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
    parameter_name: str | None = Field(default=None, max_length=200)
    browser_storage_key: str | None = Field(default=None, max_length=200)
    browser_login: dict[str, Any] | None = None
    expires_at: datetime | None = None
    allowed_capabilities: list[str] = Field(default_factory=list, max_length=128)
    allow_active_capabilities: bool = False
    approval_receipt_id: str | None = None
    created_by: str = Field(default="api", max_length=120)


class CredentialGrantCreate(BaseModel):
    """Share a profile with another target of the same asset kind."""

    model_config = ConfigDict(extra="forbid")

    target_kind: Literal["web", "api", "network", "device"]
    target_id: uuid.UUID
    # Required when the profile allows active capabilities: the receiving target must approve
    # them itself, exactly as creating such a profile there would.
    approval_receipt_id: str | None = None
    granted_by: str = Field(default="api", max_length=120)


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
    allow_active_capabilities: bool = False
    approval_receipt_id: str | None = None


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
    parameter_name: str | None = Field(default=None, max_length=200)
    browser_storage_key: str | None = Field(default=None, max_length=200)
    browser_login: dict[str, Any] | None = None
    expires_at: datetime | None = None
    clear_expiry: bool = False
    created_by: str = Field(default="api", max_length=120)


def _secret(value: SecretStr | None) -> str | None:
    return value.get_secret_value() if value is not None else None


def _custom_headers(value: Mapping[str, SecretStr] | None) -> dict[str, str] | None:
    if value is None:
        return None
    return {str(name): secret.get_secret_value() for name, secret in value.items()}


def _safe_credential_capabilities(
    *, target_kind: str, auth_kind: str,
) -> tuple[str, ...]:
    if auth_kind in {"ssh_password", "ssh_private_key", "ssh_private_key_with_passphrase"}:
        # SSH capabilities all require explicit active authority or a separate
        # immutable-plan confirmation. A blank SSH allowlist therefore grants none.
        return ()
    if auth_kind == "query_parameter":
        return ("collections.replay_safe",)
    if auth_kind in {"form_login", "oauth_client_credentials", "oauth_password", "json_login"}:
        return (
            "auth.session.establish",
            "auth.session.refresh",
            "auth.session.revoke",
            "http.request",
        )
    return ("http.request",)


def _credential_capabilities(
    values: list[str] | tuple[str, ...],
    *,
    target_kind: str,
    auth_kind: str,
    allow_active: bool,
) -> list[str]:
    requested = list(dict.fromkeys(
        str(value or "").strip().lower() for value in values if str(value or "").strip()
    ))
    if not requested:
        requested = list(_safe_credential_capabilities(
            target_kind=target_kind, auth_kind=auth_kind,
        ))
    if not requested:
        raise HTTPException(
            status_code=422,
            detail=(
                "allowed_capabilities must contain at least one capability when "
                "this credential kind has no safe default"
            ),
        )
    validated: list[str] = []
    for name in requested:
        try:
            spec = CAPABILITY_REGISTRY.require(name)
        except KeyError as exc:
            raise HTTPException(
                status_code=422,
                detail=f"allowed_capabilities contains unknown capability: {name}",
            ) from exc
        if target_kind not in spec.target_kinds:
            raise HTTPException(
                status_code=422,
                detail=f"capability {name} does not support target kind {target_kind}",
            )
        ssh_capability = spec.placement_requirements.get('credential_binding') == 'ssh' or spec.name.startswith('device.ssh.')
        if auth_kind.startswith('ssh_') != ssh_capability:
            raise HTTPException(status_code=422,detail=f"capability {name} cannot consume {auth_kind} credentials")
        requires_active_elevation = (
            spec.risk_tier in {"active", "mutation"}
            or spec.required_approval in {"active_testing","network_discovery"}
        )
        if requires_active_elevation and not allow_active:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"capability {name} requires explicit active-capability elevation"
                ),
            )
        validated.append(spec.name)
    return validated


@router.get("/capabilities")
async def credential_capability_catalog(
    target_kind: Literal["web", "api", "network", "device"],
    auth_kind: CredentialAuthKind,
):
    defaults = set(_safe_credential_capabilities(
        target_kind=target_kind, auth_kind=auth_kind,
    ))
    capabilities = []
    for spec in CAPABILITY_REGISTRY.list(target_kind=target_kind):
        ssh_capability = spec.placement_requirements.get('credential_binding') == 'ssh' or spec.name.startswith('device.ssh.')
        if auth_kind.startswith('ssh_') != ssh_capability:
            continue
        if not spec.placement_requirements.get("credentials_resolved_server_side") and not (
            auth_kind.startswith("ssh_") and spec.name.startswith("device.ssh.")
        ):
            continue
        capabilities.append({
            "name": spec.name,
            "description": spec.description,
            "risk_tier": spec.risk_tier,
            "requires_active_approval": (
                spec.risk_tier in {"active", "mutation"}
                or spec.required_approval in {"active_testing","network_discovery"}
            ),
            "default": spec.name in defaults,
        })
    return {
        "blank_semantics": "safe_server_defaults",
        "safe_defaults": sorted(defaults),
        "capabilities": capabilities,
    }


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
            parameter_name=value.parameter_name,
            browser_storage_key=value.browser_storage_key,
            browser_login=value.browser_login,
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
            """SELECT id FROM targets WHERE id=$1 AND is_active=true
               UNION ALL
               SELECT id FROM device_targets WHERE id=$1 AND is_active=true
               LIMIT 1""", target_id,
        )
    else:
        row = await conn.fetchrow(
            "SELECT id FROM targets WHERE id=$1 AND is_active=true", target_id
        )
    if not row:
        raise HTTPException(status_code=404, detail="active credential target not found")


# What the receiving target actually is, read from the inventory rather than the caller's label.
_GRANT_TARGET_FACTS_SQL = """
SELECT t.url ~* '^https?://' AS http_origin,
       (t.url ~* '^https?://'
        OR EXISTS(SELECT 1 FROM targets member
                  WHERE member.asset_owner_id=t.id AND member.is_active AND member.url ~* '^https?://')
        OR EXISTS(SELECT 1 FROM device_services service
                  WHERE service.target_id=t.id AND service.state='open'
                    AND (service.web_origin IS NOT NULL OR service.service_name ~* 'http'))
       ) AS serves_http,
       EXISTS(SELECT 1 FROM device_services service
              WHERE service.target_id=t.id AND service.state='open') AS services_observed,
       EXISTS(SELECT 1 FROM target_device_profiles profile WHERE profile.target_id=t.id) AS device
FROM targets t WHERE t.id=$1 AND t.is_active=true
UNION ALL
SELECT false, false, false, true FROM device_targets d WHERE d.id=$1 AND d.is_active=true
LIMIT 1"""


def grant_target_kind_error(
    *, declared_kind: str, auth_kind: str, http_origin: bool, serves_http: bool,
    services_observed: bool, device: bool,
) -> str | None:
    """Why a profile cannot be shared with this target, or None when the kinds agree.

    Physical target views share explicitly granted inputs, but the label must name the target as
    it is and the credential's protocol must have something to authenticate to there: a web basic
    auth profile granted to an SSH-only device, or a web origin labelled as a network host, was
    accepted with 201 and could never be used correctly.

    A host or device is refused an HTTP credential only on evidence: its services were observed
    and none of them is HTTP. With no service observations yet, missing evidence does not show
    that it serves no HTTP, so the explicit share stands.
    """
    if declared_kind in {"web", "api"} and not http_origin:
        return f"a {declared_kind} grant needs a web or API origin; this target is a host or device"
    if declared_kind in {"network", "device"} and http_origin:
        return f"a {declared_kind} grant needs a host or device; this target is a web or API origin"
    if declared_kind == "device" and not device:
        return "a device grant needs a connected device; this host is not one"
    if auth_kind in HTTP_CREDENTIAL_KINDS and not serves_http and services_observed:
        return (
            f"a {auth_kind} credential authenticates HTTP; this target's observed services "
            "include no web or API service"
        )
    if auth_kind in SSH_CREDENTIAL_KINDS and http_origin:
        return "an SSH credential needs a host or device, not a web origin"
    return None


async def _require_grant_target(
    conn: Any, *, target_kind: str, target_id: uuid.UUID, auth_kind: str,
) -> None:
    facts = await conn.fetchrow(_GRANT_TARGET_FACTS_SQL, target_id)
    if not facts:
        raise HTTPException(status_code=404, detail="active credential target not found")
    reason = grant_target_kind_error(
        declared_kind=target_kind, auth_kind=auth_kind,
        http_origin=bool(facts["http_origin"]), serves_http=bool(facts["serves_http"]),
        services_observed=bool(facts["services_observed"]), device=bool(facts["device"]),
    )
    if reason:
        raise HTTPException(status_code=422, detail=reason)


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


def _has_active_capabilities(profile: CredentialProfileMetadata) -> bool:
    for name in profile.allowed_capabilities:
        try:
            spec = CAPABILITY_REGISTRY.require(name)
        except KeyError:
            return True  # unknown names are treated as the stricter case
        if spec.risk_tier in {"active", "mutation"} or spec.required_approval == "active_testing":
            return True
    return False


async def _target_labels(conn: Any, ids: set[str]) -> dict[str, dict[str, Any]]:
    """Display names for targets of any kind, so a shared credential can say where it is from."""
    uuids = [uuid.UUID(value) for value in ids if value]
    if not uuids:
        return {}
    rows = await conn.fetch(
        """SELECT id::text AS id, name, url AS locator, 'target' AS source FROM targets WHERE id=ANY($1::uuid[])
           UNION ALL
           SELECT id::text, name, primary_locator, 'device' FROM device_targets WHERE id=ANY($1::uuid[])""",
        uuids,
    )
    return {row["id"]: {"name": row["name"], "locator": row["locator"]} for row in rows}


def _with_home_label(item: dict[str, Any], labels: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    home = labels.get(str(item.get("home_target_id") or "")) or {}
    item["home_target_name"] = home.get("name")
    item["home_target_locator"] = home.get("locator")
    return item


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
    # After conversion this name is a read-only projection of the canonical
    # profile, so there is no legacy copy to synchronize.
    if await conn.fetchval(
        "SELECT 1 FROM app_schema_migrations WHERE name=$1",
        "unified_target_asset_inputs_v1",
    ):
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
    allowed_capabilities = _credential_capabilities(
        payload.allowed_capabilities,
        target_kind=payload.target_kind,
        auth_kind=payload.auth_kind,
        allow_active=payload.allow_active_capabilities,
    )
    pool = _pool(request)
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                await _require_target(
                    conn, target_kind=payload.target_kind, target_id=payload.target_id
                )
                if payload.allow_active_capabilities:
                    await _require_active_capability_approval(
                        conn,
                        approval_receipt_id=payload.approval_receipt_id,
                        target_id=payload.target_id,
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
                    allowed_capabilities=allowed_capabilities,
                    created_by=payload.created_by,
                    now=datetime.now(timezone.utc),
                )
    except CredentialStoreError as exc:
        raise _store_error(exc) from exc
    return {"profile": _public(profile)}


@router.get("")
async def list_credential_profiles(
    request: Request,
    target_kind: Literal["web", "api", "network", "device"] | None = None,
    target_id: uuid.UUID | None = None,
    include_inactive: bool = Query(default=False),
    search: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """With a target: every profile that target can use (its own and those shared with it).
    Without one: the library of all profiles, with how many other targets each is shared with."""
    if (target_kind is None) != (target_id is None):
        raise HTTPException(status_code=422, detail="target_kind and target_id go together")
    pool = _pool(request)
    try:
        async with pool.acquire() as conn:
            if target_id is not None:
                await _require_target(conn, target_kind=target_kind, target_id=target_id)
                profiles = await _store.list_profiles(
                    conn,
                    target_kind=target_kind,
                    target_id=target_id,
                    include_inactive=include_inactive,
                )
                labels = await _target_labels(conn, {p.target_id for p in profiles if p.shared})
                items = [_with_home_label(_public(profile), labels) for profile in profiles]
                return {
                    "target_kind": target_kind,
                    "target_id": str(target_id),
                    "profiles": items,
                    "count": len(items),
                }
            library, total = await _store.list_library(
                conn, include_inactive=include_inactive, search=search, limit=limit, offset=offset,
            )
            labels = await _target_labels(conn, {profile.target_id for profile, _ in library})
    except CredentialStoreError as exc:
        raise _store_error(exc) from exc
    items = []
    for profile, shared_count in library:
        item = _with_home_label(_public(profile), labels)
        item["shared_target_count"] = shared_count
        items.append(item)
    return {"profiles": items, "count": len(items), "total": total, "limit": limit, "offset": offset}


@router.get("/{profile_id}/grants")
async def list_credential_grants(
    request: Request,
    profile_id: uuid.UUID,
    include_revoked: bool = Query(default=False),
):
    """The targets a profile serves: its home target, then the targets it is shared with."""
    pool = _pool(request)
    try:
        async with pool.acquire() as conn:
            grants = await _store.list_grants(conn, profile_id=profile_id, include_revoked=include_revoked)
            labels = await _target_labels(conn, {grant["target_id"] for grant in grants})
    except CredentialStoreError as exc:
        raise _store_error(exc) from exc
    for grant in grants:
        label = labels.get(grant["target_id"]) or {}
        grant["target_name"] = label.get("name")
        grant["target_locator"] = label.get("locator")
    return {"profile_id": str(profile_id), "grants": grants, "count": len(grants)}


@router.post("/{profile_id}/grants", status_code=status.HTTP_201_CREATED)
async def grant_credential_profile(request: Request, profile_id: uuid.UUID, payload: CredentialGrantCreate):
    """Share a profile with another target. The grant makes it selectable there; testing that
    target still needs the target's own authorization, checked when a Scan or Hunt uses it."""
    pool = _pool(request)
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                profile = await _store.get_profile(conn, profile_id=profile_id)
                await _require_grant_target(
                    conn, target_kind=payload.target_kind, target_id=payload.target_id,
                    auth_kind=profile.auth_kind,
                )
                if _has_active_capabilities(profile):
                    await _require_active_capability_approval(
                        conn, approval_receipt_id=payload.approval_receipt_id, target_id=payload.target_id,
                    )
                grant = await _store.grant_profile(
                    conn,
                    profile_id=profile_id,
                    target_kind=payload.target_kind,
                    target_id=payload.target_id,
                    granted_by=payload.granted_by,
                    now=datetime.now(timezone.utc),
                )
                labels = await _target_labels(conn, {grant["target_id"]})
    except CredentialStoreError as exc:
        raise _store_error(exc) from exc
    label = labels.get(grant["target_id"]) or {}
    grant.update({"target_name": label.get("name"), "target_locator": label.get("locator")})
    return {"profile_id": str(profile_id), "grant": grant}


@router.delete("/{profile_id}/grants/{target_id}")
async def revoke_credential_grant(request: Request, profile_id: uuid.UUID, target_id: uuid.UUID):
    """Stop sharing a profile with a target. Runs already admitted with it fail their next
    credential check; the home target is removed only by deactivating the profile."""
    pool = _pool(request)
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                grant = await _store.revoke_grant(
                    conn, profile_id=profile_id, target_id=target_id, now=datetime.now(timezone.utc),
                )
    except CredentialStoreError as exc:
        raise _store_error(exc) from exc
    return {"profile_id": str(profile_id), "grant": grant}


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
                if payload.allowed_capabilities is not None and payload.allow_active_capabilities:
                    await _require_active_capability_approval(
                        conn,
                        approval_receipt_id=payload.approval_receipt_id,
                        target_id=uuid.UUID(existing.target_id),
                    )
                allowed_capabilities = (
                    _credential_capabilities(
                        payload.allowed_capabilities,
                        target_kind=existing.target_kind,
                        auth_kind=existing.auth_kind,
                        allow_active=payload.allow_active_capabilities,
                    )
                    if payload.allowed_capabilities is not None else None
                )
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
                    allowed_capabilities=allowed_capabilities,
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
                if (existing.configuration.get("browser_login_configured")
                        and "browser_login" not in payload.model_fields_set):
                    raise HTTPException(
                        status_code=422,
                        detail="Resubmit browser_login when rotating this profile, or explicitly set it to null to remove the saved workflow.",
                    )
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
