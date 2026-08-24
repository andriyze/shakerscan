from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import uuid

import pytest

from api.runtime import auth_session_store as sessions
from api.runtime.models import TargetBinding


NOW = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
SESSION_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
OWNER_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")
TARGET_ID = uuid.UUID("33333333-3333-4333-8333-333333333333")
PROFILE_ID = uuid.UUID("44444444-4444-4444-8444-444444444444")
ACTION_ID = uuid.UUID("55555555-5555-4555-8555-555555555555")
RECEIPT_ID = uuid.UUID("66666666-6666-4666-8666-666666666666")
EVIDENCE_DIGEST = "a" * 64
SECRET = "Bearer session-canary-value"


def target() -> TargetBinding:
    return TargetBinding(
        target_id=str(TARGET_ID),
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
        environment="test",
        scope_receipt_id="scope-1",
    )


class SessionConn:
    def __init__(self):
        self.row = None
        self.executed = []

    async def execute(self, query, *args):
        self.executed.append((query, args))
        normalized = " ".join(query.split())
        if query == sessions.AUTH_SESSION_SCHEMA_SQL:
            return "OK"
        if normalized.startswith("UPDATE auth_sessions SET evidence_receipt_id"):
            receipt_id, session_id, digest = args
            if (
                self.row
                and self.row["id"] == session_id
                and self.row["evidence_receipt_digest"] == digest
            ):
                self.row["evidence_receipt_id"] = receipt_id
                return "UPDATE 1"
            return "UPDATE 0"
        raise AssertionError(normalized)

    async def fetchrow(self, query, *args):
        normalized = " ".join(query.split())
        if normalized.startswith("INSERT INTO auth_sessions"):
            (
                session_id, owner_kind, owner_id, target_kind, target_id,
                binding_digest, profile_id, profile_version, principal_slot,
                principal_label, auth_kind, capabilities, encrypted_headers,
                established_at, expires_at, refresh_after, evidence_digest,
                source_action_id,
            ) = args
            self.row = {
                "id": session_id,
                "owner_kind": owner_kind,
                "owner_id": owner_id,
                "target_kind": target_kind,
                "target_id": target_id,
                "target_binding_digest": binding_digest,
                "profile_id": profile_id,
                "profile_version": profile_version,
                "principal_slot": principal_slot,
                "principal_label": principal_label,
                "auth_kind": auth_kind,
                "compatible_capabilities": json.loads(capabilities),
                "encrypted_headers": encrypted_headers,
                "status": "active",
                "established_at": established_at,
                "expires_at": expires_at,
                "refresh_after": refresh_after,
                "last_refreshed_at": None,
                "refresh_count": 0,
                "revoked_at": None,
                "revocation_reason": None,
                "evidence_receipt_digest": evidence_digest,
                "evidence_receipt_id": None,
                "source_action_id": source_action_id,
            }
            return dict(self.row)
        if normalized.startswith("SELECT s.*, p.current_version"):
            session_id, owner_kind, owner_id, target_kind, target_id = args
            if not self.row or (
                self.row["id"], self.row["owner_kind"], self.row["owner_id"],
                self.row["target_kind"], self.row["target_id"],
            ) != (session_id, owner_kind, owner_id, target_kind, target_id):
                return None
            return {
                **self.row,
                "live_profile_version": self.row["profile_version"],
                "live_profile_active": True,
                "live_profile_expires_at": NOW + timedelta(days=1),
                "live_allowed_capabilities": [
                    "auth.session.establish", "auth.session.refresh",
                    "auth.session.revoke", "http.request",
                ],
            }
        if normalized.startswith("UPDATE auth_sessions SET status='revoked'"):
            encrypted, timestamp, reason, session_id = args
            if not self.row or self.row["id"] != session_id:
                return None
            self.row.update({
                "status": "revoked",
                "encrypted_headers": encrypted,
                "revoked_at": timestamp,
                "revocation_reason": reason,
            })
            return dict(self.row)
        raise AssertionError(normalized)


def install_fake_crypto(monkeypatch):
    monkeypatch.setattr(
        sessions, "encrypt_secret", lambda value: "enc:fernet:" + value,
    )
    monkeypatch.setattr(
        sessions,
        "decrypt_secret",
        lambda value: str(value).removeprefix("enc:fernet:"),
    )


async def created(conn: SessionConn):
    return await sessions.PostgresAuthSessionStore().create(
        conn,
        owner_kind="hunt",
        owner_id=OWNER_ID,
        target=target(),
        profile_id=PROFILE_ID,
        profile_version=3,
        principal_slot="primary",
        principal_label="Owner",
        auth_kind="oauth_client_credentials",
        compatible_capabilities=("http.request",),
        headers={"Authorization": SECRET},
        established_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        refresh_after=NOW + timedelta(minutes=50),
        evidence_receipt_digest=EVIDENCE_DIGEST,
        source_action_id=ACTION_ID,
        session_ref=SESSION_ID,
    )


def test_runtime_schema_matches_repair_and_init_has_marker():
    repair = Path(
        "db/repairs/2026-08-24_v2_auth_sessions.sql"
    ).read_text()
    body = repair.split("BEGIN;", 1)[1].rsplit("COMMIT;", 1)[0]
    squash = lambda value: " ".join(value.split())
    assert squash(body) == squash(sessions.AUTH_SESSION_SCHEMA_SQL)
    init = Path("db/init.sql").read_text()
    assert "CREATE TABLE auth_sessions" in init
    assert sessions.AUTH_SESSION_MIGRATION in init


def test_session_is_encrypted_opaque_worker_only_and_clearable(monkeypatch):
    install_fake_crypto(monkeypatch)
    conn = SessionConn()
    metadata = asyncio.run(created(conn))
    assert metadata.session_ref == str(SESSION_ID)
    assert SECRET not in json.dumps(metadata.public_dict())

    worker = asyncio.run(sessions.PostgresAuthSessionStore().load_for_worker(
        conn,
        session_ref=SESSION_ID,
        owner_kind="hunt",
        owner_id=OWNER_ID,
        target=target(),
        capability="http.request",
        now=NOW + timedelta(minutes=1),
    ))
    assert worker.headers() == {"Authorization": SECRET}
    assert SECRET not in repr(worker)
    worker.close()
    with pytest.raises(sessions.AuthSessionStoreError, match="closed"):
        worker.headers()


def test_expiry_rotation_and_live_capability_changes_fail_closed(monkeypatch):
    install_fake_crypto(monkeypatch)
    conn = SessionConn()
    asyncio.run(created(conn))
    store = sessions.PostgresAuthSessionStore()

    with pytest.raises(sessions.AuthSessionStoreError, match="expired"):
        asyncio.run(store.load_for_worker(
            conn,
            session_ref=SESSION_ID,
            owner_kind="hunt",
            owner_id=OWNER_ID,
            target=target(),
            capability="http.request",
            now=NOW + timedelta(hours=2),
        ))

    original = conn.fetchrow

    async def rotated(query, *args):
        row = await original(query, *args)
        if row and "SELECT s.*, p.current_version" in query:
            row["live_profile_version"] = 4
        return row

    conn.fetchrow = rotated
    with pytest.raises(sessions.AuthSessionStoreError, match="rotated"):
        asyncio.run(store.load_for_refresh(
            conn,
            session_ref=SESSION_ID,
            owner_kind="hunt",
            owner_id=OWNER_ID,
            target=target(),
        ))

    conn.fetchrow = original

    async def narrowed(query, *args):
        row = await original(query, *args)
        if row and "SELECT s.*, p.current_version" in query:
            row["live_allowed_capabilities"] = ["auth.session.revoke"]
        return row

    conn.fetchrow = narrowed
    with pytest.raises(sessions.AuthSessionStoreError, match="no longer allows"):
        asyncio.run(store.load_for_worker(
            conn,
            session_ref=SESSION_ID,
            owner_kind="hunt",
            owner_id=OWNER_ID,
            target=target(),
            capability="http.request",
            now=NOW + timedelta(minutes=1),
        ))


def test_revocation_destroys_ciphertext_and_binds_evidence(monkeypatch):
    install_fake_crypto(monkeypatch)
    conn = SessionConn()
    asyncio.run(created(conn))
    store = sessions.PostgresAuthSessionStore()
    revoked = asyncio.run(store.revoke(
        conn,
        session_ref=SESSION_ID,
        owner_kind="hunt",
        owner_id=OWNER_ID,
        target=target(),
        reason="operator_revoked",
        now=NOW + timedelta(minutes=2),
    ))
    assert revoked.status == "revoked"
    assert SECRET not in conn.row["encrypted_headers"]
    with pytest.raises(sessions.AuthSessionStoreError, match="revoked"):
        asyncio.run(store.load_for_worker(
            conn,
            session_ref=SESSION_ID,
            owner_kind="hunt",
            owner_id=OWNER_ID,
            target=target(),
            capability="http.request",
            now=NOW + timedelta(minutes=3),
        ))

    asyncio.run(store.bind_evidence_receipt(
        conn,
        session_ref=SESSION_ID,
        receipt_id=RECEIPT_ID,
        evidence_receipt_digest=EVIDENCE_DIGEST,
    ))
    assert conn.row["evidence_receipt_id"] == RECEIPT_ID
