from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import stat
import uuid

import pytest

from api.runtime.credential_resolver import (
    CredentialResolutionAuthority,
    CredentialResolutionError,
    WorkerCredentialResolver,
    validate_worker_credential_authority,
)
from api.runtime.credential_store import (
    CredentialProfileMetadata,
    CredentialStoreError,
    WorkerCredentialCiphertext,
)
from api.runtime.credentials import (
    build_credential_secret,
    parse_credential_secret,
    public_credential_configuration,
)
from api.runtime.models import TargetBinding


NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
TARGET_ID = "22222222-2222-4222-8222-222222222222"
PROFILE_ID = "11111111-1111-4111-8111-111111111111"


def _target(kind="api"):
    return TargetBinding(
        target_id=TARGET_ID,
        target_kind=kind,
        canonical_host="example.test",
        allowed_origins=("https://example.test",),
        allowed_addresses=("192.0.2.20",),
        allowed_root_domains=("example.test",),
        scope_receipt_id="scope-1",
    )


def _authority(**updates):
    values = {
        "owner_kind": "hunt",
        "owner_id": "hunt-1",
        "credential_access_allowed": True,
        "approval_validated": True,
        "approval_receipt_id": "approval-1",
        "scope_receipt_id": "scope-1",
    }
    values.update(updates)
    return CredentialResolutionAuthority(**values)


def _metadata(kind, target_kind="api", principal_slot="primary"):
    kwargs = {"secret": "placeholder"}
    if kind.startswith("ssh_"):
        kwargs["username"] = "operator"
    if kind == "basic_auth":
        kwargs["username"] = "operator"
    if kind == "form_login":
        kwargs.update({"username": "operator", "endpoint_url": "/login"})
    if kind == "query_parameter":
        kwargs["parameter_name"] = "access_key"
    if kind == "ssh_private_key_with_passphrase":
        kwargs["secondary_secret"] = "placeholder-passphrase"
    configuration = public_credential_configuration(
        parse_credential_secret(kind, build_credential_secret(kind, **kwargs))
    )
    return CredentialProfileMetadata(
        profile_id=PROFILE_ID,
        target_kind=target_kind,
        target_id=TARGET_ID,
        name="fixture",
        auth_kind=kind,
        principal_label="fixture-principal",
        principal_slot=principal_slot,
        configuration=configuration,
        current_version=3,
        record_version=5,
        is_active=True,
        expires_at=None,
        rotated_at=NOW,
        created_at=NOW,
        updated_at=NOW,
        allowed_capabilities=("request.replay",),
    )


class FakeStore:
    def __init__(self, *, metadata, encrypted_secret="cipher-secret", encrypted_metadata="cipher-metadata"):
        self.metadata = metadata
        self.encrypted_secret = encrypted_secret
        self.encrypted_metadata = encrypted_metadata
        self.calls = []

    async def load_for_worker(self, conn, **kwargs):
        self.calls.append((conn, kwargs))
        if str(kwargs["target_id"]) != self.metadata.target_id:
            raise CredentialStoreError("credential profile is unavailable for target")
        return WorkerCredentialCiphertext(
            metadata=self.metadata,
            encrypted_secret=self.encrypted_secret,
            encrypted_metadata=self.encrypted_metadata,
            allowed_capabilities=("request.replay",),
        )


def _decryptor(envelope, private_metadata=None):
    values = {
        "cipher-secret": envelope,
        "cipher-metadata": private_metadata or json.dumps({
            "schema_version": "credential-private-metadata/v1",
            "created_by": "test",
        }),
    }
    return lambda ciphertext: values[ciphertext]


def test_authority_fails_before_profile_lookup_or_decryption():
    envelope = build_credential_secret("bearer_token", secret="top-secret")
    store = FakeStore(metadata=_metadata("bearer_token"))
    decrypted = []
    resolver = WorkerCredentialResolver(
        store=store,
        decryptor=lambda value: decrypted.append(value) or value,
    )

    async def exercise():
        with pytest.raises(CredentialResolutionError, match="validated target-bound approval"):
            async with resolver.resolve(
                object(),
                profile_id=PROFILE_ID,
                target=_target(),
                capability="request.replay",
                authority=_authority(approval_validated=False),
            ):
                pass

    asyncio.run(exercise())
    assert store.calls == []
    assert decrypted == []
    assert "top-secret" in envelope


def test_scope_mismatch_fails_before_profile_lookup():
    store = FakeStore(metadata=_metadata("bearer_token"))
    resolver = WorkerCredentialResolver(store=store, decryptor=lambda value: value)

    async def exercise():
        with pytest.raises(CredentialResolutionError, match="scope does not match"):
            async with resolver.resolve(
                object(),
                profile_id=PROFILE_ID,
                target=_target(),
                capability="request.replay",
                authority=_authority(scope_receipt_id="another-scope"),
            ):
                pass

    asyncio.run(exercise())
    assert store.calls == []


def test_http_resolution_is_exact_content_free_and_scrubbed_after_context():
    envelope = build_credential_secret("bearer_token", secret="top-secret")
    store = FakeStore(metadata=_metadata("bearer_token"))
    resolver = WorkerCredentialResolver(
        store=store,
        decryptor=_decryptor(envelope),
    )
    retained = None

    async def exercise():
        nonlocal retained
        async with resolver.resolve(
            "db-connection",
            profile_id=PROFILE_ID,
            target=_target(),
            capability="request.replay",
            authority=_authority(),
        ) as credential:
            retained = credential
            headers = credential.http_headers()
            assert headers.as_dict() == {"Authorization": "Bearer top-secret"}
            assert "top-secret" not in repr(headers)
            assert "top-secret" not in repr(credential)
            receipt = json.dumps(credential.receipt_metadata())
            assert "top-secret" not in receipt
            assert credential.receipt_metadata()["principal_profile_version"] == 3

    asyncio.run(exercise())
    assert store.calls[0][1] == {
        "profile_id": PROFILE_ID,
        "target_kind": "api",
        "target_id": TARGET_ID,
        "capability": "request.replay",
    }
    assert retained is not None and retained._closed is True
    assert retained._material == {}
    with pytest.raises(CredentialResolutionError, match="closed"):
        retained.http_headers()


def test_immediate_http_material_is_worker_private_and_hides_values_in_repr():
    envelope = build_credential_secret(
        "basic_auth", username="private-user", secret="private-password"
    )
    store = FakeStore(metadata=_metadata("basic_auth"))
    resolver = WorkerCredentialResolver(store=store, decryptor=_decryptor(envelope))

    async def exercise():
        async with resolver.resolve(
            object(),
            profile_id=PROFILE_ID,
            target=_target(),
            capability="request.replay",
            authority=_authority(),
        ) as credential:
            material = credential.immediate_http()
            assert material.username == "private-user"
            assert material.secret == "private-password"
            assert "private-user" not in repr(material)
            assert "private-password" not in repr(material)

    asyncio.run(exercise())


def test_interactive_http_material_hides_values_in_repr():
    envelope = build_credential_secret(
        "form_login",
        username="private-user",
        secret="private-password",
        endpoint_url="/login",
    )
    store = FakeStore(metadata=_metadata("form_login"))
    resolver = WorkerCredentialResolver(store=store, decryptor=_decryptor(envelope))

    async def exercise():
        async with resolver.resolve(
            object(), profile_id=PROFILE_ID, target=_target(), capability="request.replay",
            authority=_authority(),
        ) as credential:
            material = credential.interactive_http()
            assert material.username == "private-user"
            assert material.secret == "private-password"
            assert "private-user" not in repr(material)
            assert "private-password" not in repr(material)

    asyncio.run(exercise())


def test_query_parameter_material_hides_value_in_repr_and_is_scrubbed():
    envelope = build_credential_secret(
        "query_parameter", secret="top-secret-query", parameter_name="access_key"
    )
    store = FakeStore(metadata=_metadata("query_parameter"))
    resolver = WorkerCredentialResolver(store=store, decryptor=_decryptor(envelope))
    retained = None

    async def exercise():
        nonlocal retained
        async with resolver.resolve(
            object(), profile_id=PROFILE_ID, target=_target(),
            capability="request.replay", authority=_authority(),
        ) as credential:
            retained = credential
            material = credential.query_parameter()
            assert material.name == "access_key"
            assert material.value == "top-secret-query"
            assert "top-secret-query" not in repr(material)

    asyncio.run(exercise())
    assert retained is not None and retained._material == {}


def test_private_key_file_is_mode_0600_then_zeroed_and_deleted(tmp_path, monkeypatch):
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-key-value\n"
    envelope = build_credential_secret(
        "ssh_private_key_with_passphrase",
        username="operator",
        secret=key,
        secondary_secret="private-passphrase",
    )
    store = FakeStore(
        metadata=_metadata(
            "ssh_private_key_with_passphrase", target_kind="device", principal_slot="ssh"
        )
    )
    resolver = WorkerCredentialResolver(
        store=store,
        decryptor=_decryptor(envelope),
        temporary_root=str(tmp_path),
    )
    target = TargetBinding(
        target_id=TARGET_ID,
        target_kind="device",
        canonical_host="device.example.test",
        allowed_addresses=("192.0.2.44",),
        scope_receipt_id="scope-1",
    )
    removed = []
    real_unlink = os.unlink

    def inspect_then_unlink(path):
        removed.append(Path(path).read_bytes())
        real_unlink(path)

    monkeypatch.setattr(os, "unlink", inspect_then_unlink)

    async def exercise():
        async with resolver.resolve(
            object(), profile_id=PROFILE_ID, target=target, capability="request.replay",
            authority=_authority(),
        ) as credential:
            with credential.ssh_private_key() as material:
                path = Path(material.private_key_path)
                assert stat.S_IMODE(path.stat().st_mode) == 0o600
                assert path.read_text() == key
                assert material.username == "operator"
                assert material.passphrase == "private-passphrase"
                assert "private-passphrase" not in repr(material)
            assert not path.exists()

    asyncio.run(exercise())
    assert removed == [b"\0" * len(key.encode())]


def test_invalid_ciphertext_and_metadata_fail_without_leaking_values():
    envelope = build_credential_secret("bearer_token", secret="top-secret")
    store = FakeStore(metadata=_metadata("bearer_token"))
    resolver = WorkerCredentialResolver(
        store=store,
        decryptor=_decryptor(envelope, private_metadata='{"wrong":"schema"}'),
    )

    async def exercise():
        with pytest.raises(CredentialResolutionError, match="metadata is invalid") as error:
            async with resolver.resolve(
                object(), profile_id=PROFILE_ID, target=_target(),
                capability="request.replay", authority=_authority(),
            ):
                pass
        assert "top-secret" not in str(error.value)

    asyncio.run(exercise())


class ApprovalConn:
    def __init__(self, row):
        self.row = row
        self.calls = []

    async def fetchrow(self, query, *args):
        self.calls.append((query, args))
        return self.row


def test_worker_reloads_bounded_credential_approval_before_resolution():
    approval_id = uuid.UUID("44444444-4444-4444-8444-444444444444")
    conn = ApprovalConn({
        "scope_receipt_id": "scope-1",
        "risk_tier": "credential",
        "confirmations": ["confirm_authorized", "confirm_scope_reviewed"],
        "approved_by": "operator",
        "denial_reason": None,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
        "target_id": TARGET_ID,
        "verdict": "needs_approval",
        "action_name": "hunt.capability:collections.replay_safe",
    })

    authority = asyncio.run(validate_worker_credential_authority(
        conn,
        owner_kind="hunt",
        owner_id="hunt-1",
        target=_target(),
        approval_receipt_id=approval_id,
        scope_receipt_id="scope-1",
        action_name="hunt.capability:collections.replay_safe",
    ))
    assert authority.approval_validated is True
    assert authority.approval_receipt_id == str(approval_id)
    assert conn.calls[0][1] == (approval_id,)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"risk_tier": "active"}, "does not authorize"),
        ({"approved_by": None}, "does not authorize"),
        ({"denial_reason": "denied"}, "does not authorize"),
        ({"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)}, "expired"),
        ({"confirmations": []}, "confirm_authorized"),
        ({"target_id": "another-target"}, "target changed"),
        ({"verdict": "blocked"}, "scope is blocked"),
        ({"action_name": "hunt.capability:http.request"}, "action changed"),
    ],
)
def test_worker_approval_revalidation_fails_closed(changes, message):
    row = {
        "scope_receipt_id": "scope-1",
        "risk_tier": "credential",
        "confirmations": ["confirm_authorized"],
        "approved_by": "operator",
        "denial_reason": None,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
        "target_id": TARGET_ID,
        "verdict": "allowed",
        "action_name": "hunt.capability:collections.replay_safe",
    }
    row.update(changes)
    with pytest.raises(CredentialResolutionError, match=message):
        asyncio.run(validate_worker_credential_authority(
            ApprovalConn(row),
            owner_kind="hunt",
            owner_id="hunt-1",
            target=_target(),
            approval_receipt_id="44444444-4444-4444-8444-444444444444",
            scope_receipt_id="scope-1",
            action_name="hunt.capability:collections.replay_safe",
        ))
