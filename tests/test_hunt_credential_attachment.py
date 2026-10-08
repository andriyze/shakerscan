"""A Hunt uses one credential list: everything attached to its target, and records each use.

Unit tests with in-memory doubles. Fixture labels: ``FixtureStore`` stands in for the credential
profile store (``list_profiles`` = the attached list, ``load_for_worker`` = the target-bound
ciphertext query), ``FixtureConn`` for the registered-principal query and the use ledger, and
``fixture_decrypt`` for the secret store. The real SQL is exercised against PostgreSQL in
``tests/test_hunt_credential_uses_postgres.py``.
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import uuid

import pytest
from fastapi import HTTPException

from hunt.credential_uses import (
    CREDENTIAL_REFUSAL_CODES,
    HuntCredentialRefusal,
    action_credential_references,
    admit_action_credentials,
    unattached_reference_refusal,
)
from hunt.verification_credentials import (
    HuntCredentialScope,
    HuntVerificationCredentialRefused,
    hunt_credential_scope,
    resolve_hunt_workflow_principal_contexts,
)
from runtime.credential_store import CredentialProfileMetadata, CredentialStoreError, WorkerCredentialCiphertext
from workflow_experiment import WorkflowContractError, validate_principal_contexts
from workflow_principals import resolve_target_principal_contexts

from api import api as api_module

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
HUNT = uuid.UUID("a0000000-0000-4000-8000-000000000001")
ACTION = uuid.UUID("a0000000-0000-4000-8000-000000000002")
TARGET = uuid.UUID("b0000000-0000-4000-8000-000000000001")
OTHER = uuid.UUID("b0000000-0000-4000-8000-000000000002")
OWN_ALICE = "c0000000-0000-4000-8000-000000000001"
OWN_BOB = "c0000000-0000-4000-8000-000000000002"
SHARED_CAROL = "c0000000-0000-4000-8000-000000000003"
SHARED_DAVE = "c0000000-0000-4000-8000-000000000004"
UNATTACHED_EVE = "c0000000-0000-4000-8000-000000000005"


def _jwt(subject: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"sub": subject}).encode()).decode().rstrip("=")
    return f"Bearer h.{payload}.s"


SECRETS = {  # fixture ciphertext -> fixture plaintext
    f"enc:fernet:{OWN_ALICE}": _jwt("alice"),
    f"enc:fernet:{OWN_BOB}": "session=bob-session; theme=dark",
    f"enc:fernet:{SHARED_CAROL}": _jwt("carol"),
    f"enc:fernet:{SHARED_DAVE}": _jwt("dave"),
    f"enc:fernet:{UNATTACHED_EVE}": _jwt("eve"),
}


def _profile(profile_id, *, home=TARGET, slot="primary", kind="authorization_header",
             version=1, capabilities=("authz.verify", "http.request")):
    return CredentialProfileMetadata(
        profile_id=profile_id, target_kind="web", target_id=str(home), name=f"p-{profile_id[-4:]}",
        auth_kind=kind, principal_label=None, principal_slot=slot,
        configuration={"auth_kind": kind}, current_version=version, record_version=1,
        is_active=True, expires_at=NOW + timedelta(days=30), rotated_at=NOW, created_at=NOW,
        updated_at=NOW, allowed_capabilities=tuple(capabilities), granted_target_id=str(TARGET),
    )


class FixtureStore:
    """The attached list of TARGET; anything else is unavailable, exactly like the store."""

    def __init__(self, profiles, *, stored_versions=None):
        self.profiles = {profile.profile_id: profile for profile in profiles}
        self.stored_versions = dict(stored_versions or {})
        self.loaded = []

    async def list_profiles(self, conn, *, target_kind, target_id):
        assert (target_kind, str(target_id)) == ("web", str(TARGET))
        return list(self.profiles.values())

    async def load_for_worker(self, conn, *, profile_id, target_kind, target_id, capability):
        self.loaded.append(profile_id)
        profile = self.profiles.get(profile_id)
        if profile is None or str(target_id) != str(TARGET) or capability not in profile.allowed_capabilities:
            raise CredentialStoreError("credential profile is unavailable for target")
        version = self.stored_versions.get(profile_id, profile.current_version)
        return WorkerCredentialCiphertext(
            metadata=replace(profile, current_version=version),
            encrypted_secret=f"enc:fernet:{profile_id}",
            encrypted_metadata="enc:fernet:metadata",
            allowed_capabilities=profile.allowed_capabilities,
        )


class FixtureConn:
    """Registered principals of TARGET (legacy shape) and an in-memory use ledger."""

    def __init__(self, principals=()):
        self.principals = [dict(row) for row in principals]
        self.uses = []

    async def fetch(self, query, *args):
        if "FROM target_principals p" in query:
            assert args[0] == TARGET
            if "secret_value" in query:  # the registered-principal resolver outside Hunt
                return [dict(row) for row in self.principals]
            return [{k: v for k, v in row.items() if k not in {"secret_value", "auth_kind"}}
                    for row in self.principals]
        raise AssertionError(query)

    async def execute(self, query, *args):
        assert "INSERT INTO hunt_credential_uses" in query, query
        assert "ON CONFLICT ON CONSTRAINT hunt_credential_uses_action_slot_unique DO NOTHING" in query
        row = dict(zip(("hunt_run_id", "action_id", "profile_id", "profile_version", "source", "slot"), args))
        if not any((u["action_id"], u["profile_id"], u["slot"]) == (row["action_id"], row["profile_id"], row["slot"])
                   for u in self.uses):
            self.uses.append(row)
        return "INSERT 0 1"


def _principal(profile_id, state, *, refs=None, label=None):
    return {
        "principal_id": uuid.uuid5(TARGET, f"principal:{state}"), "label": label or state,
        "role": "user", "tenant_id": None, "auth_state": state,
        "principal_metadata": json.dumps({"captured_refs": refs or {}}),
        "profile_id": uuid.UUID(profile_id), "profile_metadata": "{}",
        "auth_kind": "authorization_header" if profile_id != OWN_BOB else "cookie",
        "secret_value": f"enc:fernet:{profile_id}",
    }


class Decryptions:
    """Spy on the secret store: records every ciphertext decrypted."""

    def __init__(self):
        self.calls = []

    def __call__(self, value):
        self.calls.append(value)
        return SECRETS[value]


def _scope(refs=()):
    return HuntCredentialScope(hunt_id=HUNT, action_id=ACTION, target_kind="web",
                               target_id=TARGET, credential_refs=tuple(refs))


def _ref(profile_id, slot, *, version=1):
    return {"source": "credential_profiles", "role": f"{slot}_credential_profile_id",
            "profile_id": profile_id, "principal_slot": slot, "profile_version": version,
            "auth_kind": "authorization_header", "allowed_capabilities": ["authz.verify", "http.request"]}


def _resolve(conn, store, decrypt, slots, *, refs=(), select_only=False):
    return asyncio.run(resolve_hunt_workflow_principal_contexts(
        conn, _scope(refs), TARGET, set(slots), select_only=select_only,
        store=store, decryptor=decrypt,
    ))


def _refusal(conn, store, decrypt, slots, **kwargs):
    with pytest.raises(HuntVerificationCredentialRefused) as exc:
        _resolve(conn, store, decrypt, slots, **kwargs)
    assert isinstance(exc.value, WorkflowContractError)  # existing workflow guards still apply
    assert exc.value.code in CREDENTIAL_REFUSAL_CODES
    return exc.value


# --- the rule: own plus shared, nothing unattached -----------------------------------------

def test_credentials_shared_from_other_targets_become_usable_and_are_recorded():
    store = FixtureStore([
        _profile(SHARED_CAROL, home=OTHER, slot="primary"),
        _profile(SHARED_DAVE, home=OTHER, slot="secondary"),
    ])
    conn, decrypt = FixtureConn(), Decryptions()
    contexts = _resolve(conn, store, decrypt, {"user1", "user2", "anonymous"})

    assert contexts["user1"]["headers"] == {"Authorization": _jwt("carol")}
    assert contexts["user2"]["headers"] == {"Authorization": _jwt("dave")}
    assert {c["credential_source"] for c in contexts.values()} == {f"shared_from:{OTHER}"}
    # Two attached principals with distinct identities satisfy the cross-principal contract.
    receipts = validate_principal_contexts(contexts, {"user1", "user2"})
    assert [r["identity_verified"] for r in receipts] == [True, True]
    assert sorted((u["slot"], str(u["profile_id"]), u["source"]) for u in conn.uses) == [
        ("primary", SHARED_CAROL, f"shared_from:{OTHER}"),
        ("secondary", SHARED_DAVE, f"shared_from:{OTHER}"),
    ]
    assert all(u["hunt_run_id"] == HUNT and u["action_id"] == ACTION for u in conn.uses)


def test_an_unattached_selected_credential_is_refused_with_a_reason_code_and_never_decrypted():
    store = FixtureStore([_profile(OWN_ALICE)])
    conn, decrypt = FixtureConn([_principal(OWN_ALICE, "user1")]), Decryptions()
    refusal = _refusal(conn, store, decrypt, {"user1"}, refs=[_ref(UNATTACHED_EVE, "primary")])

    assert refusal.code == "credential_not_attached" and refusal.slot == "user1"
    detail = refusal.public_detail()
    assert detail["reason_code"] == "credential_not_attached"
    assert detail["profile_id"] == UNATTACHED_EVE and "grants" in detail["attach"]
    assert decrypt.calls == [] and store.loaded == [] and conn.uses == []


def test_hunt_start_refuses_an_unattached_credential_reference_with_the_reason_code(monkeypatch):
    attached = [_profile(OWN_ALICE), _profile(SHARED_CAROL, home=OTHER)]

    class Store:
        async def list_profiles(self, conn, **kwargs):
            return attached

    monkeypatch.setattr(api_module, "_generic_credential_store", Store())
    contract = type("Contract", (), {"target_kind": "web", "credential_refs": {
        "primary_credential_profile_id": SHARED_CAROL,
        "secondary_credential_profile_id": UNATTACHED_EVE,
    }})()
    with pytest.raises(HTTPException) as exc:
        asyncio.run(api_module._validate_hunt_credential_references(None, contract, TARGET))
    assert exc.value.status_code == 422
    assert exc.value.detail["reason_code"] == "credential_not_attached"
    assert exc.value.detail["slot"] == "secondary"
    assert exc.value.detail["profile_id"] == UNATTACHED_EVE
    # A shared (attached) credential alone is accepted.
    assert unattached_reference_refusal({"primary_credential_profile_id": SHARED_CAROL}, attached) is None


def test_a_start_selection_narrows_the_attached_list():
    store = FixtureStore([
        _profile(OWN_ALICE, slot="primary"),
        _profile(SHARED_CAROL, home=OTHER, slot="primary"),
    ])
    # Without a selection two attached primaries are ambiguous: the agent must name one.
    refusal = _refusal(FixtureConn(), store, Decryptions(), {"user1"})
    assert refusal.code == "credential_ambiguous_for_slot"
    assert "primary_credential_profile_id" in refusal.message

    conn, decrypt = FixtureConn(), Decryptions()
    contexts = _resolve(conn, store, decrypt, {"user1"}, refs=[_ref(SHARED_CAROL, "primary")])
    assert contexts["user1"]["profile_id"] == SHARED_CAROL
    assert store.loaded == [SHARED_CAROL] and decrypt.calls == [f"enc:fernet:{SHARED_CAROL}"]
    # D38: the selection keeps the credential's origin target.
    assert [(u["slot"], u["source"]) for u in conn.uses] == [("primary", f"selected_shared_from:{OTHER}")]


def test_a_selection_also_overrides_the_registered_principal_for_its_slot():
    store = FixtureStore([_profile(OWN_ALICE), _profile(SHARED_CAROL, home=OTHER)])
    conn = FixtureConn([_principal(OWN_ALICE, "user1")])
    decrypt = Decryptions()
    contexts = _resolve(conn, store, decrypt, {"user1"}, refs=[_ref(SHARED_CAROL, "primary")])
    assert contexts["user1"]["profile_id"] == SHARED_CAROL
    assert f"enc:fernet:{OWN_ALICE}" not in decrypt.calls


def test_every_use_is_recorded_once_with_its_source():
    store = FixtureStore([
        _profile(OWN_ALICE, slot="primary"),
        _profile(SHARED_DAVE, home=OTHER, slot="secondary", version=4),
    ])
    conn, decrypt = FixtureConn([_principal(OWN_ALICE, "user1")]), Decryptions()
    for _ in range(2):  # the create-surface probe and the dispatch resolve the same action twice
        _resolve(conn, store, decrypt, {"user1", "user2"})
    assert sorted((u["slot"], str(u["profile_id"]), u["profile_version"], u["source"]) for u in conn.uses) == [
        ("primary", OWN_ALICE, 1, "target_own"),
        ("secondary", SHARED_DAVE, 4, f"shared_from:{OTHER}"),
    ]
    # Selecting only (building the proof before approval) decrypts and records nothing.
    quiet, quiet_decrypt = FixtureConn([_principal(OWN_ALICE, "user1")]), Decryptions()
    selected = _resolve(quiet, store, quiet_decrypt, {"user1", "user2"}, select_only=True)
    assert set(selected) == {"user1", "user2"} and selected["user1"]["headers"] == {}
    assert quiet.uses == [] and quiet_decrypt.calls == [] and store.loaded.count(OWN_ALICE) == 2


# --- BOLA -----------------------------------------------------------------------------------

def _bola(conn, store):
    async def run():
        with hunt_credential_scope(_scope()):
            return await api_module._agent_verification_workflow_for(
                conn, TARGET, "bola", "/api/orders/{id}", "GET")
    return asyncio.run(run())


def test_bola_with_two_attached_principals_builds_the_proof(monkeypatch):
    store = FixtureStore([_profile(OWN_ALICE), _profile(OWN_BOB, slot="secondary", kind="cookie")])
    monkeypatch.setattr("hunt.verification_credentials.PostgresCredentialProfileStore", lambda: store)
    conn = FixtureConn([
        _principal(OWN_ALICE, "user1", refs={"order_id": "1001"}),
        _principal(OWN_ALICE, "user2", refs={"order_id": "2002"}, label="second"),
    ])
    # Both registered principals share one credential: refused, a proof needs two.
    with pytest.raises(HTTPException) as exc:
        _bola(conn, store)
    assert exc.value.detail["reason_code"] == "credentials_not_distinct"

    conn.principals[1]["profile_id"] = uuid.UUID(OWN_BOB)
    workflow, route, method, _ = _bola(conn, store)
    assert (route, method) == ("/api/orders/{id}", "GET") and workflow["steps"]
    assert conn.uses == [] and store.loaded == []  # the proof is built before approval


def test_bola_with_one_attached_principal_refuses_naming_what_to_attach(monkeypatch):
    store = FixtureStore([_profile(OWN_ALICE)])
    monkeypatch.setattr("hunt.verification_credentials.PostgresCredentialProfileStore", lambda: store)
    conn = FixtureConn([_principal(OWN_ALICE, "user1", refs={"order_id": "1001"})])
    with pytest.raises(HTTPException) as exc:
        _bola(conn, store)
    assert exc.value.status_code == 422
    detail = exc.value.detail
    assert (detail["reason_code"], detail["slot"]) == ("credential_missing_for_slot", "user2")
    assert "secondary principal" in detail["message"] and "grants" in detail["attach"]


# --- no capability lost, and outside a Hunt nothing changes ---------------------------------

def test_the_targets_own_principals_resolve_exactly_as_before(monkeypatch):
    principals = [
        _principal(OWN_ALICE, "user1", refs={"order_id": "1001", "password": "never"}),
        _principal(OWN_BOB, "user2", refs={"order_id": "2002"}),
    ]
    monkeypatch.setattr("workflow_principals.decrypt_secret", lambda value: SECRETS[value])
    legacy = asyncio.run(resolve_target_principal_contexts(FixtureConn(principals), TARGET, {"user1", "user2"}))

    store = FixtureStore([_profile(OWN_ALICE), _profile(OWN_BOB, slot="secondary", kind="cookie")])
    conn = FixtureConn(principals)
    hunt = _resolve(conn, store, Decryptions(), {"user1", "user2"})
    for slot in ("user1", "user2"):
        for key in ("principal_id", "profile_id", "identity_fingerprint", "role", "tenant_id",
                    "captured_refs", "headers", "cookies"):
            assert hunt[slot][key] == legacy[slot][key], (slot, key)
    assert hunt["user2"]["cookies"] == {"session": "bob-session", "theme": "dark"}
    assert {u["source"] for u in conn.uses} == {"target_own"}


def test_outside_a_hunt_the_verifier_keeps_the_registered_principals(monkeypatch):
    calls = []

    async def legacy(conn, target_uuid, used_slots):
        calls.append(used_slots)
        return {}

    async def hunt(*args, **kwargs):
        raise AssertionError("a non-Hunt verification must not resolve the Hunt list")

    monkeypatch.setattr(api_module, "resolve_target_principal_contexts", legacy)
    monkeypatch.setattr(api_module, "resolve_hunt_workflow_principal_contexts", hunt)
    asyncio.run(api_module._resolve_workflow_principal_contexts(None, TARGET, {"user1"}))
    assert calls == [{"user1"}]


# --- version, kind and target checks --------------------------------------------------------

def test_a_rotated_selected_profile_is_refused_before_decryption():
    store = FixtureStore([_profile(SHARED_CAROL, home=OTHER, version=2)])
    decrypt = Decryptions()
    refusal = _refusal(FixtureConn(), store, decrypt, {"user1"}, refs=[_ref(SHARED_CAROL, "primary", version=1)])
    assert refusal.code == "credential_version_changed" and decrypt.calls == []

    # A rotation between selection and the ciphertext read is refused too.
    racing = FixtureStore([_profile(SHARED_CAROL, home=OTHER)], stored_versions={SHARED_CAROL: 2})
    refusal = _refusal(FixtureConn(), racing, decrypt, {"user1"})
    assert refusal.code == "credential_version_changed" and decrypt.calls == []


def test_kind_capability_and_target_are_checked_before_decryption():
    decrypt = Decryptions()
    login = FixtureStore([_profile(SHARED_CAROL, home=OTHER, kind="form_login")])
    assert _refusal(FixtureConn(), login, decrypt, {"user1"},
                    refs=[_ref(SHARED_CAROL, "primary")]).code == "credential_kind_unsupported"
    scoped = FixtureStore([_profile(SHARED_CAROL, home=OTHER, capabilities=("http.request",))])
    assert _refusal(FixtureConn(), scoped, decrypt, {"user1"},
                    refs=[_ref(SHARED_CAROL, "primary")]).code == "credential_capability_not_granted"
    with pytest.raises(HuntVerificationCredentialRefused) as exc:
        asyncio.run(resolve_hunt_workflow_principal_contexts(
            FixtureConn(), _scope(), OTHER, {"user1"}, store=scoped, decryptor=decrypt))
    assert exc.value.code == "credential_target_mismatch"
    assert decrypt.calls == []


# --- Hunt actions ---------------------------------------------------------------------------

class AttachmentConn:
    """Fixture for the admission attachment query: profile id -> current version."""

    def __init__(self, attached):
        self.attached = dict(attached)

    async def fetch(self, query, *args):
        assert "JOIN credential_profile_bindings b" in query and args[1] == str(TARGET)
        return [{"id": value, "current_version": self.attached[str(value)]}
                for value in args[0] if str(value) in self.attached]


def test_an_action_records_its_selected_credentials_and_refuses_a_revoked_grant():
    context = {"credential_refs": [_ref(SHARED_CAROL, "primary"), _ref(OWN_ALICE, "secondary")]}
    run = {"id": HUNT, "target_id": TARGET, "device_target_id": None}
    authz = {"routes": ["/api/orders"], "primary_principal": "primary", "secondary_principal": "secondary"}
    assert [slot for slot, _ in action_credential_references("authz.verify", authz, context)] == [
        "primary", "secondary"]
    assert action_credential_references("http.request", {"method": "GET"}, context) == []

    uses = asyncio.run(admit_action_credentials(
        AttachmentConn({SHARED_CAROL: 1, OWN_ALICE: 1}), run=run, capability="http.request",
        capability_input={"as_principal": "primary"}, context=context))
    assert [(u.slot, u.profile_id, u.profile_version, u.source) for u in uses] == [
        ("primary", SHARED_CAROL, 1, "selected")]

    with pytest.raises(HuntCredentialRefusal) as exc:  # the grant was revoked after start
        asyncio.run(admit_action_credentials(
            AttachmentConn({OWN_ALICE: 1}), run=run, capability="authz.verify",
            capability_input=authz, context=context))
    assert exc.value.code == "credential_not_attached" and exc.value.profile_id == SHARED_CAROL
    assert exc.value.http_exception().status_code == 403

    with pytest.raises(HuntCredentialRefusal) as exc:  # rotated after start
        asyncio.run(admit_action_credentials(
            AttachmentConn({SHARED_CAROL: 2}), run=run, capability="http.request",
            capability_input={"as_principal": "primary"}, context=context))
    assert exc.value.code == "credential_version_changed"
