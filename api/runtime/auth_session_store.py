"""Durable encrypted authentication sessions for canonical Hunt execution.

Only opaque references and content-free metadata cross the control-plane boundary.
Workers decrypt session headers after acquiring a target-bound action lease and clear
the in-memory values after use.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
from typing import Any, Mapping
import uuid

try:
    from secret_store import SecretStoreUnavailable, decrypt_secret, encrypt_secret
except ModuleNotFoundError:
    from api.secret_store import SecretStoreUnavailable, decrypt_secret, encrypt_secret

from .models import TargetBinding


AUTH_SESSION_SCHEMA_VERSION = "auth-session/v1"
AUTH_SESSION_MIGRATION = "v2_auth_sessions_v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9_.-]{0,119}$")
_HEADER = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,120}$")


AUTH_SESSION_SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS auth_sessions (
    id UUID PRIMARY KEY,
    owner_kind TEXT NOT NULL CHECK (owner_kind IN ('scan','hunt')),
    owner_id UUID NOT NULL,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('web','api')),
    target_id UUID NOT NULL,
    target_binding_digest TEXT NOT NULL CHECK (
        target_binding_digest ~ '^[0-9a-f]{64}$'
    ),
    profile_id UUID NOT NULL REFERENCES credential_profiles(id) ON DELETE CASCADE,
    profile_version INTEGER NOT NULL CHECK (profile_version > 0),
    principal_slot TEXT NOT NULL CHECK (
        principal_slot IN ('primary','secondary','service')
    ),
    principal_label TEXT,
    auth_kind TEXT NOT NULL CHECK (
        auth_kind IN ('form_login','oauth_client_credentials','oauth_password')
    ),
    compatible_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(compatible_capabilities) = 'array'
    ),
    encrypted_headers TEXT NOT NULL CHECK (
        encrypted_headers LIKE 'enc:fernet:%'
    ),
    status TEXT NOT NULL DEFAULT 'active' CHECK (
        status IN ('active','revoked','expired')
    ),
    established_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    refresh_after TIMESTAMPTZ NOT NULL,
    last_refreshed_at TIMESTAMPTZ,
    refresh_count INTEGER NOT NULL DEFAULT 0 CHECK (refresh_count >= 0),
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    evidence_receipt_digest TEXT NOT NULL CHECK (
        evidence_receipt_digest ~ '^[0-9a-f]{64}$'
    ),
    evidence_receipt_id UUID,
    source_action_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT auth_sessions_expiry_check CHECK (
        established_at < expires_at
        AND refresh_after >= established_at
        AND refresh_after < expires_at
    )
);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_owner_active
    ON auth_sessions(owner_kind, owner_id, principal_slot, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_profile_active
    ON auth_sessions(profile_id, profile_version, status, expires_at);

CREATE TABLE IF NOT EXISTS app_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO app_schema_migrations(name)
VALUES ('v2_auth_sessions_v1')
ON CONFLICT (name) DO NOTHING;
"""


class AuthSessionStoreError(ValueError):
    """A session is missing, expired, revoked, rotated, or authority-detached."""


def _row(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    try:
        return dict(value)
    except (TypeError, ValueError) as exc:
        raise AuthSessionStoreError("authentication session row is invalid") from exc


def _utc(value: Any, *, name: str) -> datetime:
    if not isinstance(value, datetime):
        raise AuthSessionStoreError(f"{name} is invalid")
    if value.tzinfo is None:
        raise AuthSessionStoreError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _capabilities(values: Any) -> tuple[str, ...]:
    if isinstance(values, str):
        try:
            values = json.loads(values)
        except json.JSONDecodeError as exc:
            raise AuthSessionStoreError(
                "authentication session capabilities are invalid"
            ) from exc
    if not isinstance(values, (list, tuple)):
        raise AuthSessionStoreError("authentication session capabilities are invalid")
    result = tuple(sorted({str(item).strip() for item in values if str(item).strip()}))
    if len(result) > 128 or any(not _CAPABILITY.fullmatch(item) for item in result):
        raise AuthSessionStoreError("authentication session capabilities are invalid")
    return result


def _headers(values: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    lowered: set[str] = set()
    for raw_name, raw_value in dict(values or {}).items():
        name, value = str(raw_name).strip(), str(raw_value)
        normalized = name.lower()
        if (
            not _HEADER.fullmatch(name)
            or normalized in lowered
            or normalized in {
                "host", "content-length", "connection", "transfer-encoding",
            }
            or not value
            or not value.isascii()
            or len(value.encode("ascii")) > 8_192
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise AuthSessionStoreError("authentication session headers are invalid")
        lowered.add(normalized)
        result[name] = value
    if not result:
        raise AuthSessionStoreError("authentication session has no identity headers")
    return result


@dataclass(frozen=True)
class AuthSessionMetadata:
    session_ref: str
    owner_kind: str
    owner_id: str
    target_kind: str
    target_id: str
    target_binding_digest: str
    profile_id: str
    profile_version: int
    principal_slot: str
    principal_label: str | None
    auth_kind: str
    compatible_capabilities: tuple[str, ...]
    status: str
    established_at: datetime
    expires_at: datetime
    refresh_after: datetime
    last_refreshed_at: datetime | None
    refresh_count: int
    revoked_at: datetime | None
    evidence_receipt_digest: str
    evidence_receipt_id: str | None
    source_action_id: str

    @classmethod
    def from_row(cls, value: Any) -> "AuthSessionMetadata":
        item = _row(value)
        digest = str(item.get("target_binding_digest") or "").lower()
        evidence = str(item.get("evidence_receipt_digest") or "").lower()
        if not _DIGEST.fullmatch(digest) or not _DIGEST.fullmatch(evidence):
            raise AuthSessionStoreError("authentication session digest is invalid")
        return cls(
            session_ref=str(uuid.UUID(str(item["id"]))),
            owner_kind=str(item["owner_kind"]),
            owner_id=str(uuid.UUID(str(item["owner_id"]))),
            target_kind=str(item["target_kind"]),
            target_id=str(uuid.UUID(str(item["target_id"]))),
            target_binding_digest=digest,
            profile_id=str(uuid.UUID(str(item["profile_id"]))),
            profile_version=int(item["profile_version"]),
            principal_slot=str(item["principal_slot"]),
            principal_label=(
                str(item["principal_label"]) if item.get("principal_label") else None
            ),
            auth_kind=str(item["auth_kind"]),
            compatible_capabilities=_capabilities(
                item.get("compatible_capabilities") or []
            ),
            status=str(item["status"]),
            established_at=_utc(item["established_at"], name="established_at"),
            expires_at=_utc(item["expires_at"], name="expires_at"),
            refresh_after=_utc(item["refresh_after"], name="refresh_after"),
            last_refreshed_at=(
                _utc(item["last_refreshed_at"], name="last_refreshed_at")
                if item.get("last_refreshed_at") else None
            ),
            refresh_count=int(item.get("refresh_count") or 0),
            revoked_at=(
                _utc(item["revoked_at"], name="revoked_at")
                if item.get("revoked_at") else None
            ),
            evidence_receipt_digest=evidence,
            evidence_receipt_id=(
                str(uuid.UUID(str(item["evidence_receipt_id"])))
                if item.get("evidence_receipt_id") else None
            ),
            source_action_id=str(uuid.UUID(str(item["source_action_id"]))),
        )

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema_version": AUTH_SESSION_SCHEMA_VERSION,
            "session_ref": self.session_ref,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "target_binding_digest": self.target_binding_digest,
            "principal_slot": self.principal_slot,
            "principal_label": self.principal_label,
            "auth_kind": self.auth_kind,
            "compatible_capabilities": list(self.compatible_capabilities),
            "status": self.status,
            "established_at": self.established_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "refresh_after": self.refresh_after.isoformat(),
            "last_refreshed_at": (
                self.last_refreshed_at.isoformat()
                if self.last_refreshed_at else None
            ),
            "refresh_count": self.refresh_count,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "evidence_receipt_digest": self.evidence_receipt_digest,
            "evidence_receipt_id": self.evidence_receipt_id,
            "source_action_id": self.source_action_id,
            "secret_values_visible": False,
        }


@dataclass(repr=False)
class WorkerAuthSession:
    metadata: AuthSessionMetadata
    _headers: dict[str, str] = field(repr=False)
    _closed: bool = field(default=False, repr=False)

    def __repr__(self) -> str:
        return (
            "WorkerAuthSession("
            f"session_ref={self.metadata.session_ref!r}, "
            f"principal_slot={self.metadata.principal_slot!r}, "
            f"header_names={sorted(self._headers)}, values_visible=False)"
        )

    def headers(self) -> dict[str, str]:
        if self._closed:
            raise AuthSessionStoreError("authentication session is closed")
        return dict(self._headers)

    def close(self) -> None:
        for name in list(self._headers):
            self._headers[name] = ""
        self._headers.clear()
        self._closed = True


class PostgresAuthSessionStore:
    async def ensure_schema(self, conn: Any) -> None:
        await conn.execute(AUTH_SESSION_SCHEMA_SQL)

    async def create(
        self,
        conn: Any,
        *,
        owner_kind: str,
        owner_id: Any,
        target: TargetBinding,
        profile_id: Any,
        profile_version: int,
        principal_slot: str,
        principal_label: str | None,
        auth_kind: str,
        compatible_capabilities: tuple[str, ...] | list[str],
        headers: Mapping[str, Any],
        established_at: datetime,
        expires_at: datetime,
        refresh_after: datetime,
        evidence_receipt_digest: str,
        source_action_id: Any,
        session_ref: Any | None = None,
    ) -> AuthSessionMetadata:
        owner = str(owner_kind or "").strip().lower()
        if owner not in {"scan", "hunt"}:
            raise AuthSessionStoreError("authentication session owner is invalid")
        if target.target_kind not in {"web", "api"}:
            raise AuthSessionStoreError("authentication session target is invalid")
        slot = str(principal_slot or "").strip().lower()
        if slot not in {"primary", "secondary", "service"}:
            raise AuthSessionStoreError("authentication session principal is invalid")
        kind = str(auth_kind or "").strip().lower()
        if kind not in {"form_login", "oauth_client_credentials", "oauth_password"}:
            raise AuthSessionStoreError("authentication session kind is invalid")
        capabilities = _capabilities(compatible_capabilities)
        if "http.request" not in capabilities:
            raise AuthSessionStoreError(
                "authentication session does not allow HTTP use"
            )
        normalized_headers = _headers(headers)
        encrypted = encrypt_secret(json.dumps(
            normalized_headers, sort_keys=True, separators=(",", ":"),
        ))
        if not isinstance(encrypted, str) or not encrypted.startswith("enc:fernet:"):
            raise AuthSessionStoreError("authentication session encryption is unavailable")
        session_id = uuid.UUID(str(session_ref)) if session_ref else uuid.uuid4()
        row = await conn.fetchrow(
            """INSERT INTO auth_sessions (
                   id, owner_kind, owner_id, target_kind, target_id,
                   target_binding_digest, profile_id, profile_version,
                   principal_slot, principal_label, auth_kind,
                   compatible_capabilities, encrypted_headers, status,
                   established_at, expires_at, refresh_after,
                   evidence_receipt_digest, source_action_id
               ) VALUES (
                   $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,
                   'active',$14,$15,$16,$17,$18
               ) RETURNING *""",
            session_id,
            owner,
            uuid.UUID(str(owner_id)),
            target.target_kind,
            uuid.UUID(str(target.target_id)),
            target.digest,
            uuid.UUID(str(profile_id)),
            int(profile_version),
            slot,
            str(principal_label or "").strip()[:120] or None,
            kind,
            json.dumps(capabilities),
            encrypted,
            _utc(established_at, name="established_at"),
            _utc(expires_at, name="expires_at"),
            _utc(refresh_after, name="refresh_after"),
            str(evidence_receipt_digest or "").lower(),
            uuid.UUID(str(source_action_id)),
        )
        if not row:
            raise AuthSessionStoreError("authentication session was not persisted")
        return AuthSessionMetadata.from_row(row)

    async def _load_row(
        self,
        conn: Any,
        *,
        session_ref: Any,
        owner_kind: str,
        owner_id: Any,
        target: TargetBinding,
        for_update: bool,
        now: datetime | None = None,
    ) -> Any:
        query = """SELECT s.*, p.current_version AS live_profile_version,
                          p.is_active AS live_profile_active,
                          p.expires_at AS live_profile_expires_at,
                          b.allowed_capabilities AS live_allowed_capabilities
                   FROM auth_sessions s
                   JOIN credential_profiles p ON p.id=s.profile_id
                   JOIN credential_profile_bindings b
                     ON b.profile_id=s.profile_id
                    AND b.binding_kind='target'
                    AND b.binding_id=s.target_id::text
                    AND b.is_active=true
                   WHERE s.id=$1 AND s.owner_kind=$2 AND s.owner_id=$3
                     AND s.target_kind=$4 AND s.target_id=$5"""
        if for_update:
            query += " FOR UPDATE OF s"
        row = await conn.fetchrow(
            query,
            uuid.UUID(str(session_ref)),
            str(owner_kind),
            uuid.UUID(str(owner_id)),
            target.target_kind,
            uuid.UUID(str(target.target_id)),
        )
        if not row:
            raise AuthSessionStoreError(
                "authentication session is unavailable for this authority"
            )
        metadata = AuthSessionMetadata.from_row(row)
        current = (
            _utc(now, name="operation time")
            if now is not None
            else datetime.now(timezone.utc)
        )
        profile_expires = row.get("live_profile_expires_at")
        if (
            metadata.target_binding_digest != target.digest
            or not bool(row.get("live_profile_active"))
            or int(row.get("live_profile_version") or 0) != metadata.profile_version
            or (
                profile_expires is not None
                and _utc(profile_expires, name="profile expiry") <= current
            )
        ):
            raise AuthSessionStoreError(
                "authentication session credential was rotated, revoked, or expired"
            )
        return row

    async def load_for_worker(
        self,
        conn: Any,
        *,
        session_ref: Any,
        owner_kind: str,
        owner_id: Any,
        target: TargetBinding,
        capability: str,
        now: datetime | None = None,
    ) -> WorkerAuthSession:
        current = (
            _utc(now, name="operation time")
            if now is not None
            else datetime.now(timezone.utc)
        )
        row = await self._load_row(
            conn,
            session_ref=session_ref,
            owner_kind=owner_kind,
            owner_id=owner_id,
            target=target,
            for_update=False,
            now=current,
        )
        metadata = AuthSessionMetadata.from_row(row)
        if metadata.status != "active" or metadata.expires_at <= current:
            raise AuthSessionStoreError("authentication session is expired or revoked")
        capability_name = str(capability or "").strip()
        if capability_name not in metadata.compatible_capabilities:
            raise AuthSessionStoreError(
                "authentication session is incompatible with the capability"
            )
        live_capabilities = _capabilities(row.get("live_allowed_capabilities") or [])
        if capability_name not in live_capabilities:
            raise AuthSessionStoreError(
                "authentication session profile no longer allows the capability"
            )
        try:
            decoded = decrypt_secret(row["encrypted_headers"])
            headers = json.loads(str(decoded or ""))
        except (SecretStoreUnavailable, json.JSONDecodeError, TypeError) as exc:
            raise AuthSessionStoreError(
                "authentication session could not be decrypted"
            ) from exc
        if not isinstance(headers, Mapping):
            raise AuthSessionStoreError("authentication session headers are invalid")
        return WorkerAuthSession(metadata=metadata, _headers=_headers(headers))

    async def load_for_refresh(
        self,
        conn: Any,
        *,
        session_ref: Any,
        owner_kind: str,
        owner_id: Any,
        target: TargetBinding,
        now: datetime | None = None,
    ) -> AuthSessionMetadata:
        current = (
            _utc(now, name="operation time")
            if now is not None
            else datetime.now(timezone.utc)
        )
        row = await self._load_row(
            conn,
            session_ref=session_ref,
            owner_kind=owner_kind,
            owner_id=owner_id,
            target=target,
            for_update=False,
            now=current,
        )
        metadata = AuthSessionMetadata.from_row(row)
        if metadata.status != "active" or metadata.expires_at <= current:
            raise AuthSessionStoreError("authentication session is expired or revoked")
        return metadata

    async def refresh(
        self,
        conn: Any,
        *,
        session_ref: Any,
        owner_kind: str,
        owner_id: Any,
        target: TargetBinding,
        expected_profile_version: int,
        headers: Mapping[str, Any],
        established_at: datetime,
        expires_at: datetime,
        refresh_after: datetime,
        evidence_receipt_digest: str,
        source_action_id: Any,
        now: datetime | None = None,
    ) -> AuthSessionMetadata:
        operation_time = (
            _utc(now, name="operation time")
            if now is not None
            else datetime.now(timezone.utc)
        )
        row = await self._load_row(
            conn,
            session_ref=session_ref,
            owner_kind=owner_kind,
            owner_id=owner_id,
            target=target,
            for_update=True,
            now=operation_time,
        )
        current = AuthSessionMetadata.from_row(row)
        if (
            current.status != "active"
            or current.expires_at <= operation_time
            or current.profile_version != int(expected_profile_version)
        ):
            raise AuthSessionStoreError("authentication session cannot be refreshed")
        encrypted = encrypt_secret(json.dumps(
            _headers(headers), sort_keys=True, separators=(",", ":"),
        ))
        updated = await conn.fetchrow(
            """UPDATE auth_sessions
               SET encrypted_headers=$1, established_at=$2, expires_at=$3,
                   refresh_after=$4, last_refreshed_at=$2,
                   refresh_count=refresh_count+1,
                   evidence_receipt_digest=$5, evidence_receipt_id=NULL,
                   source_action_id=$6, updated_at=$2
               WHERE id=$7 AND status='active' RETURNING *""",
            encrypted,
            _utc(established_at, name="established_at"),
            _utc(expires_at, name="expires_at"),
            _utc(refresh_after, name="refresh_after"),
            str(evidence_receipt_digest or "").lower(),
            uuid.UUID(str(source_action_id)),
            uuid.UUID(current.session_ref),
        )
        if not updated:
            raise AuthSessionStoreError("authentication session changed before refresh")
        return AuthSessionMetadata.from_row(updated)

    async def revoke(
        self,
        conn: Any,
        *,
        session_ref: Any,
        owner_kind: str,
        owner_id: Any,
        target: TargetBinding,
        reason: str,
        now: datetime | None = None,
    ) -> AuthSessionMetadata:
        timestamp = (
            _utc(now, name="operation time")
            if now is not None
            else datetime.now(timezone.utc)
        )
        row = await self._load_row(
            conn,
            session_ref=session_ref,
            owner_kind=owner_kind,
            owner_id=owner_id,
            target=target,
            for_update=True,
            now=timestamp,
        )
        current = AuthSessionMetadata.from_row(row)
        if current.status != "active":
            return current
        destroyed = encrypt_secret("{}")
        updated = await conn.fetchrow(
            """UPDATE auth_sessions
               SET status='revoked', encrypted_headers=$1, revoked_at=$2,
                   revocation_reason=$3, updated_at=$2
               WHERE id=$4 AND status='active' RETURNING *""",
            destroyed,
            timestamp,
            str(reason or "operator_revoked")[:240],
            uuid.UUID(current.session_ref),
        )
        if not updated:
            raise AuthSessionStoreError("authentication session changed before revocation")
        return AuthSessionMetadata.from_row(updated)

    async def expire_stale(
        self,
        conn: Any,
        *,
        now: datetime | None = None,
        limit: int = 500,
    ) -> int:
        """Destroy ciphertext for a bounded batch of expired active sessions."""

        timestamp = (
            _utc(now, name="operation time")
            if now is not None
            else datetime.now(timezone.utc)
        )
        bounded_limit = max(1, min(int(limit), 5_000))
        destroyed = encrypt_secret("{}")
        rows = await conn.fetch(
            """WITH claimed AS (
                   SELECT id FROM auth_sessions
                   WHERE status='active' AND expires_at <= $1
                   ORDER BY expires_at, id
                   LIMIT $3
                   FOR UPDATE SKIP LOCKED
               )
               UPDATE auth_sessions AS session
               SET status='expired', encrypted_headers=$2, revoked_at=$1,
                   revocation_reason='expired_cleanup', updated_at=$1
               FROM claimed
               WHERE session.id=claimed.id
               RETURNING session.id""",
            timestamp,
            destroyed,
            bounded_limit,
        )
        return len(rows)

    async def bind_evidence_receipt(
        self,
        conn: Any,
        *,
        session_ref: Any,
        receipt_id: Any,
        evidence_receipt_digest: str,
    ) -> None:
        updated = await conn.execute(
            """UPDATE auth_sessions SET evidence_receipt_id=$1, updated_at=NOW()
               WHERE id=$2 AND evidence_receipt_digest=$3""",
            uuid.UUID(str(receipt_id)),
            uuid.UUID(str(session_ref)),
            str(evidence_receipt_digest or "").lower(),
        )
        if not str(updated).endswith(" 1"):
            raise AuthSessionStoreError(
                "authentication session evidence receipt did not bind"
            )


__all__ = [
    "AUTH_SESSION_MIGRATION",
    "AUTH_SESSION_SCHEMA_SQL",
    "AUTH_SESSION_SCHEMA_VERSION",
    "AuthSessionMetadata",
    "AuthSessionStoreError",
    "PostgresAuthSessionStore",
    "WorkerAuthSession",
]
