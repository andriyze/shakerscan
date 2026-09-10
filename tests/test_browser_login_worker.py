"""Exercise real credential/approval validators with an in-memory SQL boundary.

Crypto is a tracked test double; owner, scope, approval, version, capability and
principal checks use production code. No credentials or requests leave the test.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import json
import uuid

import pytest

from capabilities import browser_login_worker as worker
from runtime.credential_resolver import WorkerCredentialResolver
from runtime.credential_store import PostgresCredentialProfileStore
from runtime.credentials import build_credential_secret, parse_credential_secret, public_credential_configuration
from tests.test_browser_login_action import (
    CAP, CONFIG, CONTEXT, POLICY, REF, PROFILE_ID, TARGET_ID, SCOPE_ID,
    APPROVAL_ID, OWNER_ID, ORIGIN, SECRET, prepared,
)
from tests.test_credential_store import MemoryCredentialConn


class Conn(MemoryCredentialConn):
    def __init__(self, owner_kind):
        super().__init__()
        self.owner_kind = owner_kind
        self.owner_status = "running" if owner_kind == "scan" else "active"
        self.target = {"url": ORIGIN, "is_active": True}
        self.scope = {"id": SCOPE_ID, "target_id": TARGET_ID, "status": "active",
                      "verdict": "allowed", "allowed_hosts": ["login-fixture.test"]}
        self.approval = {
            "id": APPROVAL_ID, "scope_receipt_id": SCOPE_ID, "status": "active",
            "approved_by": "synthetic-operator", "confirmations": ["confirm_authorized"],
            "risk_tier": "credential", "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
            "action_name": "scan.submit" if owner_kind == "scan" else f"hunt.capability:{CAP}",
        }
        self.policy = {"active_testing": True, "allow_state_changing_http": True,
                       "allowed_capabilities": [CAP], "approval_receipt_id": APPROVAL_ID,
                       "scope_receipt_id": SCOPE_ID}
        self.context = json.loads(json.dumps(CONTEXT))

    async def fetchrow(self, query, *args):
        if "FROM scans WHERE" in query:
            assert args == (uuid.UUID(OWNER_ID), uuid.UUID(TARGET_ID))
            return {"status": self.owner_status}
        if "FROM hunt_runs WHERE" in query:
            assert args == (uuid.UUID(OWNER_ID), uuid.UUID(TARGET_ID))
            return {"status": self.owner_status, "policy_json": json.dumps(self.policy),
                    "context_pack": json.dumps(self.context)}
        if "SELECT url, is_active FROM targets" in query:
            return self.target
        if "SELECT * FROM scope_receipts" in query:
            assert args == (SCOPE_ID,)
            return self.scope
        if "SELECT * FROM approval_receipts" in query:
            assert args == (uuid.UUID(APPROVAL_ID),)
            return self.approval
        if "FROM approval_receipts a" in query:
            return {**self.approval, "target_id": self.scope["target_id"], "verdict": self.scope["verdict"]}
        if query.lstrip().startswith("SELECT p.*, v.encrypted_secret"):
            if self.profile["expires_at"] <= datetime.now(timezone.utc):
                return None
        return await super().fetchrow(query, *args)


class Pool:
    def __init__(self, conn):
        self.conn, self.acquired = conn, 0

    @asynccontextmanager
    async def acquire(self):
        self.acquired += 1
        try:
            yield self.conn
        finally:
            self.acquired -= 1


async def setup(monkeypatch, owner_kind):
    conn = Conn(owner_kind)
    envelope = build_credential_secret("form_login", username="synthetic-user", secret=SECRET,
                                       endpoint_url=ORIGIN + "/login", browser_login=CONFIG)
    now = datetime.now(timezone.utc)
    await PostgresCredentialProfileStore().create_profile(
        conn, profile_id=PROFILE_ID, target_kind="web", target_id=TARGET_ID,
        name="Saved browser QA", auth_kind="form_login", principal_slot="primary", principal_label="synthetic-user",
        configuration=public_credential_configuration(parse_credential_secret("form_login", envelope)),
        encrypted_secret="enc:fernet:synthetic-secret", encrypted_metadata="enc:fernet:synthetic-metadata",
        expires_at=now + timedelta(hours=1), allowed_capabilities=[CAP], now=now,
    )
    decrypted = []
    resolvers = []
    def decrypt(value):
        decrypted.append(value)
        return envelope if value.endswith("synthetic-secret") else json.dumps({"schema_version": "credential-private-metadata/v1"})
    def resolver():
        value = WorkerCredentialResolver(decryptor=decrypt)
        resolvers.append(value)
        return value
    monkeypatch.setattr(worker, "WorkerCredentialResolver", resolver)
    return conn, Pool(conn), decrypted


@pytest.mark.parametrize("owner_kind", ["scan", "hunt"])
def test_real_worker_resolution_revalidates_without_holding_a_database_connection(monkeypatch, owner_kind):
    async def scenario():
        conn, pool, decrypted = await setup(monkeypatch, owner_kind)
        async with worker.browser_login_material(pool, prepared=prepared(), owner_kind=owner_kind,
                                                 owner_id=OWNER_ID, policy=POLICY) as material:
            assert pool.acquired == 0
            assert len(decrypted) == 2
            assert material.values.password == SECRET
            assert SECRET not in repr(material)
            await material.revalidate()
            assert len(decrypted) == 2  # revalidation does not decrypt again
            config = material.configuration
        assert pool.acquired == 0
        assert config == {}
    asyncio.run(scenario())


def change(conn, case):
    if case == "revoked": conn.approval["status"] = "revoked"
    elif case == "expired": conn.approval["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=1)
    elif case == "owner_stopped": conn.owner_status = "cancelled"
    elif case == "target_disabled": conn.target["is_active"] = False
    elif case == "target_changed": conn.target["url"] = "https://other.test"
    elif case == "scope_changed": conn.scope["allowed_hosts"] = ["other.test"]
    elif case == "approval_action_changed": conn.approval["action_name"] = "different.action"
    elif case == "profile_expired": conn.profile["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=1)
    elif case == "profile_inactive": conn.profile["is_active"] = False
    elif case == "capability_removed": conn.binding["allowed_capabilities"] = ["http.request"]
    elif case == "principal_changed": conn.profile["principal_slot"] = "secondary"
    elif case == "rotated":
        conn.profile["current_version"] = 2
        conn.versions[(uuid.UUID(PROFILE_ID), 2)] = conn.versions[(uuid.UUID(PROFILE_ID), 1)]
    else: raise AssertionError(case)


CASES = ["revoked", "expired", "owner_stopped", "target_disabled", "target_changed", "scope_changed",
         "approval_action_changed", "profile_expired", "profile_inactive", "capability_removed",
         "principal_changed", "rotated"]


@pytest.mark.parametrize("owner_kind", ["scan", "hunt"])
@pytest.mark.parametrize("case", CASES)
def test_changed_authority_never_decrypts_before_login(monkeypatch, owner_kind, case):
    async def scenario():
        conn, pool, decrypted = await setup(monkeypatch, owner_kind)
        change(conn, case)
        with pytest.raises((ValueError, RuntimeError)):
            async with worker.browser_login_material(pool, prepared=prepared(), owner_kind=owner_kind,
                                                     owner_id=OWNER_ID, policy=POLICY):
                pytest.fail("changed authority admitted")
        assert decrypted == []
        assert pool.acquired == 0
    asyncio.run(scenario())


@pytest.mark.parametrize("owner_kind", ["scan", "hunt"])
@pytest.mark.parametrize("case", CASES)
def test_changed_authority_is_detected_before_the_next_request(monkeypatch, owner_kind, case):
    async def scenario():
        conn, pool, decrypted = await setup(monkeypatch, owner_kind)
        async with worker.browser_login_material(pool, prepared=prepared(), owner_kind=owner_kind,
                                                 owner_id=OWNER_ID, policy=POLICY) as material:
            change(conn, case)
            with pytest.raises((ValueError, RuntimeError)):
                await material.revalidate()
            assert len(decrypted) == 2
    asyncio.run(scenario())


@pytest.mark.parametrize("field", ["active_testing", "allow_state_changing_http", "allowed_capabilities"])
def test_hunt_policy_narrowing_is_reloaded_before_next_request(monkeypatch, field):
    async def scenario():
        conn, pool, _ = await setup(monkeypatch, "hunt")
        async with worker.browser_login_material(pool, prepared=prepared(), owner_kind="hunt",
                                                 owner_id=OWNER_ID, policy=POLICY) as material:
            conn.policy[field] = [] if field == "allowed_capabilities" else False
            with pytest.raises(ValueError):
                await material.revalidate()
    asyncio.run(scenario())
