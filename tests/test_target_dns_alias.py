"""An existing authorized target keeps one identity when its www twin answers DNS."""

import asyncio
import json
import socket
import uuid

from api import target_authorization
from api import target_dns_alias
from tests.test_target_authorization import _Conn, TARGET_ID


class AliasConn(_Conn):
    def __init__(self, url="https://example.com"):
        super().__init__(url=url)

    def transaction(self):
        class Transaction:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        return Transaction()

    async def fetchrow(self, query, *args):
        if query == "SELECT id FROM targets WHERE canonical_key = $1":
            return {"id": TARGET_ID} if args[0] == "web:example.com" else None
        if query == "SELECT metadata_json FROM targets WHERE canonical_key = $1":
            return {"metadata_json": {"environment": "production"}}
        if query.startswith("SELECT id, status, approved_by, risk_tier, action_name, action_context FROM approval_receipts"):
            return next((row for row in self.approvals if row["id"] == args[0]), None)
        if query == "SELECT allowed_hosts FROM scope_receipts WHERE id=$1":
            scope = next((value for key, value in self.scopes.items() if str(key) == str(args[0])), None)
            return {"allowed_hosts": scope["allowed_hosts"]} if scope else None
        return await super().fetchrow(query, *args)

    async def execute(self, query, *args):
        if "derived_from_approval_receipt_id" in query:
            source_id = str(args[4])
            count = 0
            for row in self.approvals:
                context = json.loads(row["action_context"])
                if (str(row["id"]) == source_id
                        or context.get("derived_from_approval_receipt_id") == source_id):
                    if row["status"] == "active":
                        row["status"] = "revoked"
                        count += 1
            return f"UPDATE {count}"
        return await super().execute(query, *args)


class AliasPool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        class Acquisition:
            async def __aenter__(inner):
                return self.conn

            async def __aexit__(inner, *_args):
                return False

        return Acquisition()


def test_existing_target_keeps_id_and_derives_one_revocable_alias_receipt():
    conn = AliasConn()
    pool = AliasPool(conn)
    original = asyncio.run(target_authorization.authorize_target(conn, TARGET_ID, approved_by="alice"))
    target_id = asyncio.run(target_dns_alias.registered_alias_target_id(
        pool, "https://example.com", "https://www.example.com",
    ))
    assert target_id == TARGET_ID

    derived_id = asyncio.run(target_dns_alias.standing_receipt_for_dns_alias(
        pool, target_id=target_id, requested_url="https://example.com",
        effective_url="https://www.example.com", supplied_receipt_id=original["approval_receipt_id"],
    ))
    assert derived_id and derived_id != original["approval_receipt_id"]
    derived = next(row for row in conn.approvals if str(row["id"]) == derived_id)
    assert json.loads(derived["action_context"])["derived_from_approval_receipt_id"] == original["approval_receipt_id"]
    scope = conn.scopes[derived["scope_receipt_id"]]
    assert scope["target_id"] == TARGET_ID
    assert scope["allowed_hosts"] == ["example.com", "www.example.com"]
    assert conn.url == "https://example.com"

    again = asyncio.run(target_dns_alias.standing_receipt_for_dns_alias(
        pool, target_id=target_id, requested_url="https://example.com",
        effective_url="https://www.example.com",
    ))
    assert again == derived_id and len(conn.approvals) == 2
    with_old_receipt = asyncio.run(target_dns_alias.standing_receipt_for_dns_alias(
        pool, target_id=target_id, requested_url="https://example.com",
        effective_url="https://www.example.com", supplied_receipt_id=original["approval_receipt_id"],
    ))
    assert with_old_receipt == derived_id and len(conn.approvals) == 2
    assert asyncio.run(target_authorization.revoke_target_authorization(
        conn, TARGET_ID, revoked_by="alice", reason="offboarded",
    )) == 2
    assert asyncio.run(target_authorization.current_target_authorization(conn, TARGET_ID)) is None


def test_alias_derivation_requires_current_standing_authorization_and_exact_pair():
    conn = AliasConn()
    pool = AliasPool(conn)
    assert asyncio.run(target_dns_alias.standing_receipt_for_dns_alias(
        pool, target_id=TARGET_ID, requested_url="https://example.com",
        effective_url="https://www.example.com",
    )) is None
    original = asyncio.run(target_authorization.authorize_target(conn, TARGET_ID, approved_by="alice"))
    for other in ("https://api.example.com", "http://www.example.com", "https://www.other.com"):
        assert asyncio.run(target_dns_alias.registered_alias_target_id(
            pool, "https://example.com", other,
        )) is None
    assert asyncio.run(target_dns_alias.standing_receipt_for_dns_alias(
        pool, target_id=TARGET_ID, requested_url="https://example.com",
        effective_url="https://www.example.com", supplied_receipt_id=str(uuid.uuid4()),
    )) is None
    assert len(conn.approvals) == 1
    assert original["approval_receipt_id"]


def test_scan_preparation_reuses_authorized_target_without_creating_a_twin(monkeypatch):
    conn = AliasConn()
    pool = AliasPool(conn)
    original = asyncio.run(target_authorization.authorize_target(conn, TARGET_ID, approved_by="alice"))

    async def lookup(host):
        if host == "www.example.com":
            return ["93.184.215.14"]
        raise socket.gaierror(socket.EAI_NONAME, "no address")

    monkeypatch.setattr(target_dns_alias.target_resolution, "system_lookup", lookup)
    effective, fallback, target_id, receipt_id = asyncio.run(target_dns_alias.prepare_scan_dns_alias(
        pool, "https://example.com", active=True,
        supplied_receipt_id=original["approval_receipt_id"],
    ))
    assert effective == "https://www.example.com"
    assert fallback["requested_host"] == "example.com"
    assert target_id == TARGET_ID
    assert receipt_id != original["approval_receipt_id"]
    assert conn.url == "https://example.com"
    assert len(conn.approvals) == 2

    passive = asyncio.run(target_dns_alias.prepare_scan_dns_alias(
        pool, "https://example.com", active=False, supplied_receipt_id=None,
    ))
    assert passive[2] == TARGET_ID and passive[3] is None
    assert len(conn.approvals) == 2


def test_revoking_original_or_derived_receipt_ends_both_authorities():
    for revoke_derived in (False, True):
        conn = AliasConn()
        pool = AliasPool(conn)
        original = asyncio.run(target_authorization.authorize_target(conn, TARGET_ID, approved_by="alice"))
        derived_id = asyncio.run(target_dns_alias.standing_receipt_for_dns_alias(
            pool, target_id=TARGET_ID, requested_url="https://example.com",
            effective_url="https://www.example.com",
        ))
        selected_id = derived_id if revoke_derived else original["approval_receipt_id"]
        selected = next(row for row in conn.approvals if str(row["id"]) == selected_id)
        selected["status"] = "revoked"  # the Arsenal route's first UPDATE
        asyncio.run(target_dns_alias.revoke_dns_alias_lineage(
            conn, selected, revoked_by="alice", reason="offboarded",
        ))
        assert all(row["status"] == "revoked" for row in conn.approvals)
        assert asyncio.run(target_authorization.current_target_authorization(conn, TARGET_ID)) is None
