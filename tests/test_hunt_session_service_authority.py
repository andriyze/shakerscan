"""Approved service reuse succeeds; stale authority never decrypts a session."""
from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
import json

import pytest

from api.runtime import auth_session_store as sessions
from api.runtime.credential_resolver import CredentialResolutionError
from api.runtime.session_service_authority import normalize_session_origin, service_origin
from tests import test_auth_session_store as fixture


class PolicyConn(fixture.SessionConn):
    def __init__(self, target):
        super().__init__()
        self.reads = []
        self.run = {
            "id": fixture.OWNER_ID, "target_kind": target.target_kind,
            "target_id": None if target.target_kind == "device" else target.target_id,
            "device_target_id": target.target_id if target.target_kind == "device" else None,
            "status": "active",
            "context_pack": {
                "target": {"url": target.allowed_origins[0], "origins": list(target.allowed_origins),
                           "root_domain": target.allowed_root_domains[0], "environment": target.environment},
                "authorized_target_addresses": list(target.allowed_addresses),
            },
            "policy_json": {"active_testing": True, "network_discovery": False,
                            "approval_receipt_id": str(fixture.RECEIPT_ID),
                            "scope_receipt_id": target.scope_receipt_id},
        }
        self.approval = {
            "scope_receipt_id": target.scope_receipt_id, "target_id": target.target_id,
            "risk_tier": "active", "action_name": "target.authorization", "status": "active",
            "revoked_at": None, "approved_by": "operator", "denial_reason": None,
            "confirmations": ["confirm_authorized"], "expires_at": None, "verdict": "allowed",
        }

    async def fetchrow(self, query, *args):
        if "FROM hunt_runs WHERE id=$1" in query:
            assert args == (fixture.OWNER_ID,)
            self.reads.append("hunt")
            return self.run
        if "FROM approval_receipts a" in query:
            assert args == (fixture.RECEIPT_ID,)
            self.reads.append("approval")
            return self.approval
        return await super().fetchrow(query, *args)


async def create(conn, target, *, source=None):
    return await sessions.PostgresAuthSessionStore().create(
        conn, owner_kind="hunt", owner_id=fixture.OWNER_ID, target=target,
        profile_id=fixture.PROFILE_ID, profile_version=3, principal_slot="primary",
        principal_label="Owner", auth_kind="oauth_client_credentials",
        compatible_capabilities=("http.request",), headers={"Authorization": fixture.SECRET},
        established_at=fixture.NOW, expires_at=fixture.NOW + timedelta(hours=1),
        refresh_after=fixture.NOW + timedelta(minutes=50),
        evidence_receipt_digest=fixture.EVIDENCE_DIGEST, source_action_id=fixture.ACTION_ID,
        session_ref=fixture.SESSION_ID, service_origin=source,
    )


async def load(conn, target, *, selected_origins=None):
    return await sessions.PostgresAuthSessionStore().load_for_worker(
        conn, session_ref=fixture.SESSION_ID, owner_kind="hunt", owner_id=fixture.OWNER_ID,
        target=target, capability="http.request", selected_origins=selected_origins,
        now=fixture.NOW,
    )


@pytest.mark.parametrize("kind", ["web", "api", "network", "device"])
@pytest.mark.parametrize("destination", ["https://app.example.test:9443", "https://app.example.test"])
def test_one_standing_authorization_allows_selected_session_on_other_services(monkeypatch, kind, destination):
    fixture.install_fake_crypto(monkeypatch)
    original = replace(fixture.target(), target_kind=kind, allowed_origins=("https://app.example.test:8443",))
    conn = PolicyConn(original)
    established = asyncio.run(create(conn, original))
    selected = replace(original, allowed_origins=(destination,))
    worker = asyncio.run(load(conn, selected))
    assert worker.headers() == {"Authorization": fixture.SECRET}
    assert worker.metadata.service_origin == established.service_origin == original.allowed_origins[0]
    assert conn.reads == ["hunt", "approval"]
    assert conn.run["policy_json"]["network_discovery"] is False
    assert not conn.executed  # Consume existing authority; never create an approval.
    worker.close()


@pytest.mark.parametrize("kind", ["web", "api", "network", "device"])
@pytest.mark.parametrize("destination", ["http://app.example.test:8080", "http://app.example.test"])
def test_https_session_reuses_selected_http_service_under_standing_authority(monkeypatch, kind, destination):
    fixture.install_fake_crypto(monkeypatch)
    original = replace(fixture.target(), target_kind=kind, allowed_origins=("https://app.example.test:8443",))
    conn = PolicyConn(original)
    asyncio.run(create(conn, original))
    worker = asyncio.run(load(conn, replace(original, allowed_origins=(destination,))))
    assert worker.headers() == {"Authorization": fixture.SECRET}
    assert worker.metadata.service_origin == original.allowed_origins[0]
    assert conn.reads == ["hunt", "approval"]
    assert not conn.executed  # No per-port or per-scheme approval was created.
    worker.close()


def test_http_session_can_reuse_another_http_port_with_existing_authority(monkeypatch):
    fixture.install_fake_crypto(monkeypatch)
    original = replace(fixture.target(), allowed_origins=("http://app.example.test:8008",))
    conn = PolicyConn(original)
    asyncio.run(create(conn, original))
    worker = asyncio.run(load(conn, replace(original, allowed_origins=("http://app.example.test:8060",))))
    assert worker.headers() == {"Authorization": fixture.SECRET}
    assert conn.reads == ["hunt", "approval"]
    worker.close()


def test_only_selected_service_in_multi_origin_binding_controls_authority(monkeypatch):
    fixture.install_fake_crypto(monkeypatch)
    original = replace(fixture.target(), allowed_origins=("https://app.example.test:8443",))
    conn = PolicyConn(original)
    asyncio.run(create(conn, original))
    selected = replace(original, allowed_origins=(
        "http://app.example.test", "https://app.example.test:8443",
    ))

    worker = asyncio.run(load(conn, selected, selected_origins=("https://app.example.test:8443",)))
    assert worker.headers() == {"Authorization": fixture.SECRET}
    worker.close()
    assert conn.reads == []
    worker = asyncio.run(load(conn, selected, selected_origins=("http://app.example.test",)))
    assert worker.headers() == {"Authorization": fixture.SECRET}
    assert conn.reads == ["hunt", "approval"]
    worker.close()
    with pytest.raises(sessions.AuthSessionStoreError, match="outside the target binding"):
        asyncio.run(load(conn, selected, selected_origins=("https://other.example.test",)))


def test_equivalent_default_port_is_not_an_extra_service_or_approval(monkeypatch):
    fixture.install_fake_crypto(monkeypatch)
    original = fixture.target()
    conn = PolicyConn(original)
    result = asyncio.run(create(conn, original, source="https://APP.example.test:443/"))
    assert result.service_origin == "https://app.example.test"
    worker = asyncio.run(load(conn, replace(original, allowed_origins=("https://app.example.test:443",))))
    assert worker.headers()["Authorization"] == fixture.SECRET
    assert conn.reads == []
    worker.close()


@pytest.mark.parametrize("change", ["passive", "cancelled", "addresses", "scope", "revoked", "target"])
def test_changed_service_authority_is_rejected_before_decryption(monkeypatch, change):
    fixture.install_fake_crypto(monkeypatch)
    original = fixture.target()
    conn = PolicyConn(original)
    asyncio.run(create(conn, original))
    if change == "passive":
        conn.run["policy_json"]["active_testing"] = False
    elif change == "cancelled":
        conn.run["status"] = "cancelled"
    elif change == "addresses":
        conn.run["context_pack"]["authorized_target_addresses"] = ["192.0.2.99"]
    elif change == "scope":
        conn.run["policy_json"]["scope_receipt_id"] = "new-scope"
    elif change == "revoked":
        conn.approval["status"] = "revoked"
    else:
        conn.run["target_id"] = str(fixture.PROFILE_ID)
    def no_decrypt(_):
        pytest.fail("a detached authorization reached session decryption")
    monkeypatch.setattr(sessions, "decrypt_secret", no_decrypt)
    with pytest.raises((sessions.AuthSessionStoreError, CredentialResolutionError)):
        asyncio.run(load(conn, replace(original, allowed_origins=("http://app.example.test:8080",))))


def test_legacy_asset_bound_session_uses_live_authority_without_inventing_login_origin(monkeypatch):
    fixture.install_fake_crypto(monkeypatch)
    original = fixture.target()
    conn = PolicyConn(original)
    asyncio.run(create(conn, original))
    conn.row["service_origin"] = None
    worker = asyncio.run(load(conn, replace(original, allowed_origins=("http://app.example.test:8080",))))
    assert worker.headers() == {"Authorization": fixture.SECRET}
    assert worker.metadata.service_origin is None
    assert conn.reads == ["hunt", "approval"]
    worker.close()


def test_exact_bound_legacy_session_keeps_its_original_binding(monkeypatch):
    fixture.install_fake_crypto(monkeypatch)
    original = fixture.target()
    conn = PolicyConn(original)
    asyncio.run(create(conn, original))
    conn.row["service_origin"] = None
    conn.row["target_binding_digest"] = original.digest
    worker = asyncio.run(load(conn, original))
    assert conn.reads == []
    worker.close()
    with pytest.raises(sessions.AuthSessionStoreError):
        asyncio.run(load(conn, replace(original, allowed_origins=("https://app.example.test:9443",))))


@pytest.mark.parametrize("origin", ["https://app.example.test:0", "https://app.example.test:65536", "https://u:p@app.example.test", "https://app.example.test/login", "https://app.example.test?", "https://app.example.test#", "https://other.example.test", "https://app.example.test\\evil", "https://app.example.test\n"])
def test_session_origin_validation_rejects_ambiguous_or_other_asset_destinations(origin):
    with pytest.raises(ValueError):
        normalize_session_origin(fixture.target(), origin)


@pytest.mark.parametrize("value,expected", [("https://[2001:db8::1]:443/", "https://[2001:db8::1]"), ("http://APP.example.test:80", "http://app.example.test"), ("https://app.example.test:8443", "https://app.example.test:8443")])
def test_service_origin_normalizes_without_erasing_real_port_or_transport(value, expected):
    assert service_origin(value) == expected
