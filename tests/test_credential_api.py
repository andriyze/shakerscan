from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import uuid

import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

import api.credential_api as credential_api
from tests.test_credential_store import MemoryCredentialConn, TARGET_ID


class ApiCredentialConn(MemoryCredentialConn):
    def __init__(self):
        super().__init__()
        self.legacy_web = None
        self.legacy_device = None

    def transaction(self):
        @asynccontextmanager
        async def transaction_context():
            yield

        return transaction_context()

    async def fetchrow(self, query, *args):
        if query.lstrip().startswith("SELECT id FROM targets"):
            return {"id": args[0]} if args[0] == TARGET_ID else None
        if query.lstrip().startswith("SELECT id FROM device_targets"):
            return {"id": args[0]} if args[0] == TARGET_ID else None
        if "FROM target_credential_profiles WHERE id" in query:
            if self.legacy_web and self.legacy_web["id"] == args[0]:
                return dict(self.legacy_web)
            return None
        if "FROM device_credential_profiles WHERE id" in query:
            if self.legacy_device and self.legacy_device["id"] == args[0]:
                return dict(self.legacy_device)
            return None
        return await super().fetchrow(query, *args)

    async def execute(self, query, *args):
        if "UPDATE device_credential_profiles" in query:
            assert self.legacy_device and self.legacy_device["id"] == args[0]
            self.legacy_device.update({
                "name": args[1],
                "expires_at": args[2],
                "is_active": args[3],
                "secret_value": args[4] or self.legacy_device["secret_value"],
                "username": args[5] if args[4] else self.legacy_device["username"],
                "login_path": args[6] if args[4] else self.legacy_device["login_path"],
                "rotated_at": args[7] if args[4] else self.legacy_device["rotated_at"],
                "updated_at": args[7],
            })
            return "UPDATE 1"
        if "UPDATE target_principals" in query:
            assert self.legacy_web and self.legacy_web["target_id"] == args[0]
            self.legacy_web["principal_profile_name"] = args[2]
            return "UPDATE 1"
        if "UPDATE target_credential_profiles" in query:
            assert self.legacy_web and self.legacy_web["id"] == args[0]
            self.legacy_web.update({
                "name": args[1],
                "expires_at": args[2],
                "is_active": args[3],
                "secret_value": args[4] or self.legacy_web["secret_value"],
                "rotated_at": args[5] if args[4] else self.legacy_web["rotated_at"],
                "updated_at": args[5],
            })
            return "UPDATE 1"
        return await super().execute(query, *args)


class ApiCredentialPool:
    def __init__(self):
        self.conn = ApiCredentialConn()

    def acquire(self):
        conn = self.conn

        @asynccontextmanager
        async def acquire_context():
            yield conn

        return acquire_context()


@pytest.fixture
def client(monkeypatch):
    # API tests prove the boundary and public shape; real Fernet and PostgreSQL are
    # covered separately. Never make test ciphertext include its plaintext input.
    monkeypatch.setattr(
        credential_api, "encrypt_secret", lambda _value: "enc:fernet:opaque-ciphertext"
    )
    monkeypatch.setattr(credential_api, "encryption_enabled", lambda: True)
    async def validate_approval(_conn, receipt_id, **kwargs):
        if receipt_id != "11111111-1111-4111-8111-111111111111":
            raise HTTPException(status_code=400, detail="Approval receipt is required")
        assert kwargs["require_target_binding"] is True
        assert kwargs["risk_tier"] == "credential"

    credential_api.configure_credential_api(approval_validator=validate_approval)
    app = FastAPI()
    app.state.db_pool = ApiCredentialPool()
    app.include_router(credential_api.router)

    @app.exception_handler(RequestValidationError)
    async def safe_credential_validation(_request, exc):
        return JSONResponse(
            status_code=422,
            content={
                "detail": credential_api.public_credential_validation_errors(exc.errors())
            },
        )

    return TestClient(app), app.state.db_pool


def _create_payload(**updates):
    payload = {
        "target_kind": "api",
        "target_id": str(TARGET_ID),
        "name": "Primary API",
        "auth_kind": "bearer_token",
        "principal_label": "primary-user",
        "principal_slot": "primary",
        "secret": "never-return-this-secret",
        "expires_at": "2027-08-22T12:00:00Z",
        "allowed_capabilities": ["http.request"],
    }
    payload.update(updates)
    return payload


def test_metadata_only_crud_and_rotation_never_return_secret_material(client):
    http, pool = client

    created = http.post("/credential-profiles", json=_create_payload())
    assert created.status_code == 201, created.text
    profile = created.json()["profile"]
    profile_id = profile["id"]
    assert profile["auth_kind"] == "bearer_token"
    assert profile["configuration"]["username_configured"] is False
    assert profile["allowed_capabilities"] == ["http.request"]
    assert profile["secret_values_visible"] is False
    assert profile["storage_encrypted"] is True
    assert "never-return-this-secret" not in created.text
    assert "opaque-ciphertext" not in created.text

    listed = http.get(
        "/credential-profiles",
        params={"target_kind": "api", "target_id": str(TARGET_ID)},
    )
    assert listed.status_code == 200
    assert listed.json()["count"] == 1
    assert listed.json()["profiles"][0]["id"] == profile_id
    assert "opaque-ciphertext" not in listed.text

    fetched = http.get(f"/credential-profiles/{profile_id}")
    assert fetched.status_code == 200
    assert fetched.json()["profile"]["id"] == profile_id

    patched = http.patch(
        f"/credential-profiles/{profile_id}",
        json={
            "expected_record_version": 1,
            "name": "Primary API renamed",
            "allowed_capabilities": ["http.request", "web.probe"],
        },
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["profile"]["record_version"] == 2
    assert patched.json()["profile"]["allowed_capabilities"] == [
        "http.request", "web.probe"
    ]

    stale = http.patch(
        f"/credential-profiles/{profile_id}",
        json={"expected_record_version": 1, "name": "stale"},
    )
    assert stale.status_code == 409

    rotated = http.post(
        f"/credential-profiles/{profile_id}/rotate",
        json={
            "expected_record_version": 2,
            "secret": "new-secret-must-not-return",
            "clear_expiry": True,
        },
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["profile"]["current_version"] == 2
    assert rotated.json()["profile"]["record_version"] == 3
    assert "new-secret-must-not-return" not in rotated.text
    assert len(pool.conn.versions) == 2

    deleted = http.delete(f"/credential-profiles/{profile_id}")
    assert deleted.status_code == 200
    assert deleted.json()["profile"]["status"] == "inactive"
    assert pool.conn.binding["is_active"] is False


def test_capability_registry_defaults_validate_names_and_require_active_elevation(client):
    http, _ = client

    catalog = http.get(
        "/credential-profiles/capabilities",
        params={"target_kind": "api", "auth_kind": "bearer_token"},
    )
    assert catalog.status_code == 200, catalog.text
    assert catalog.json()["blank_semantics"] == "safe_server_defaults"
    assert catalog.json()["safe_defaults"] == ["http.request"]

    defaulted = http.post(
        "/credential-profiles",
        json=_create_payload(name="Defaulted", allowed_capabilities=[]),
    )
    assert defaulted.status_code == 201, defaulted.text
    assert defaulted.json()["profile"]["allowed_capabilities"] == ["http.request"]

    unknown = http.post(
        "/credential-profiles",
        json=_create_payload(name="Unknown", allowed_capabilities=["made.up.capability"]),
    )
    assert unknown.status_code == 422
    assert "unknown capability" in unknown.text

    active = http.post(
        "/credential-profiles",
        json=_create_payload(name="Active", allowed_capabilities=["authz.verify"]),
    )
    assert active.status_code == 422
    assert "explicit active-capability elevation" in active.text

    self_asserted = http.post(
        "/credential-profiles",
        json=_create_payload(
            name="Self asserted",
            allowed_capabilities=["authz.verify"],
            allow_active_capabilities=True,
        ),
    )
    assert self_asserted.status_code == 400
    assert "Approval receipt is required" in self_asserted.text

    elevated = http.post(
        "/credential-profiles",
        json=_create_payload(
            name="Elevated",
            allowed_capabilities=["authz.verify"],
            allow_active_capabilities=True,
            approval_receipt_id="11111111-1111-4111-8111-111111111111",
        ),
    )
    assert elevated.status_code == 201, elevated.text

def test_creation_is_fail_closed_for_unknown_target_and_unsafe_material(client):
    http, pool = client

    missing = http.post(
        "/credential-profiles",
        json=_create_payload(target_id="99999999-9999-4999-8999-999999999999"),
    )
    assert missing.status_code == 404
    assert pool.conn.profile is None

    split = http.post(
        "/credential-profiles",
        json=_create_payload(
            auth_kind="api_key_header",
            header_name="X-API-Key",
            secret="token\r\nX-Escape: yes",
        ),
    )
    assert split.status_code == 422
    assert "line breaks" in split.text
    assert pool.conn.profile is None


def test_request_and_response_models_do_not_serialize_secret_values(client):
    http, _pool = client
    body = _create_payload(
        auth_kind="basic_auth",
        username="private-user",
        secret="private-password",
    )
    response = http.post("/credential-profiles", json=body)
    assert response.status_code == 201, response.text
    serialized = json.dumps(response.json())
    assert "private-user" not in serialized
    assert "private-password" not in serialized
    assert response.json()["profile"]["configuration"]["username_configured"] is True


def test_query_parameter_profile_exposes_name_but_never_value(client):
    http, _pool = client
    response = http.post(
        "/credential-profiles",
        json=_create_payload(
            auth_kind="query_parameter",
            parameter_name="access_key",
            secret="private-query-value",
        ),
    )
    assert response.status_code == 201, response.text
    profile = response.json()["profile"]
    assert profile["configuration"]["parameter_name"] == "access_key"
    assert "private-query-value" not in response.text


def test_unknown_fields_are_rejected_before_secret_storage(client):
    http, pool = client
    response = http.post(
        "/credential-profiles",
        json={**_create_payload(), "raw_headers": {"Authorization": "leak"}},
    )
    assert response.status_code == 422
    assert "leak" not in response.text
    assert pool.conn.profile is None


def test_migrated_web_profile_changes_stay_synchronized_with_legacy_execution(client):
    http, pool = client
    created = http.post(
        "/credential-profiles",
        json=_create_payload(
            target_kind="web",
            name="Legacy primary",
            auth_kind="authorization_header",
            secret="Bearer original",
        ),
    )
    assert created.status_code == 201, created.text
    profile = created.json()["profile"]
    pool.conn.legacy_web = {
        "id": uuid.UUID(profile["id"]),
        "target_id": TARGET_ID,
        "auth_kind": "authorization_header",
        "name": "Legacy primary",
        "secret_value": "enc:fernet:legacy-original",
        "is_active": True,
        "expires_at": None,
        "rotated_at": datetime.now(timezone.utc),
    }

    patched = http.patch(
        f"/credential-profiles/{profile['id']}",
        json={
            "expected_record_version": profile["record_version"],
            "name": "Canonical primary",
            "clear_expiry": True,
        },
    )
    assert patched.status_code == 200, patched.text
    assert pool.conn.legacy_web["name"] == "Canonical primary"
    assert pool.conn.legacy_web["principal_profile_name"] == "Canonical primary"

    rotated = http.post(
        f"/credential-profiles/{profile['id']}/rotate",
        json={
            "expected_record_version": patched.json()["profile"]["record_version"],
            "secret": "Bearer canonical-rotation",
            "clear_expiry": True,
        },
    )
    assert rotated.status_code == 200, rotated.text
    assert pool.conn.legacy_web["secret_value"] == "enc:fernet:opaque-ciphertext"

    deleted = http.delete(f"/credential-profiles/{profile['id']}")
    assert deleted.status_code == 200, deleted.text
    assert pool.conn.legacy_web["is_active"] is False


def test_migrated_device_profile_rotation_stays_synchronized_with_legacy_execution(client):
    http, pool = client
    created = http.post(
        "/credential-profiles",
        json=_create_payload(
            target_kind="device",
            name="Device SSH",
            auth_kind="ssh_password",
            principal_slot="ssh",
            username="root",
            secret="original-password",
            allowed_capabilities=[],
        ),
    )
    assert created.status_code == 201, created.text
    profile = created.json()["profile"]
    pool.conn.legacy_device = {
        "id": uuid.UUID(profile["id"]),
        "device_target_id": TARGET_ID,
        "auth_kind": "ssh_password",
        "name": "Device SSH",
        "username": "root",
        "login_path": None,
        "secret_value": "enc:fernet:legacy-original",
        "is_active": True,
        "expires_at": None,
        "rotated_at": datetime.now(timezone.utc),
    }

    rotated = http.post(
        f"/credential-profiles/{profile['id']}/rotate",
        json={
            "expected_record_version": profile["record_version"],
            "username": "root",
            "secret": "canonical-password",
            "clear_expiry": True,
        },
    )
    assert rotated.status_code == 200, rotated.text
    assert pool.conn.legacy_device["secret_value"] == "enc:fernet:opaque-ciphertext"
    assert pool.conn.legacy_device["username"] == "root"

    deleted = http.delete(f"/credential-profiles/{profile['id']}")
    assert deleted.status_code == 200, deleted.text
    assert pool.conn.legacy_device["is_active"] is False
