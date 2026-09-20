"""Standing target authorization: once per target, reused, revocable, scope-bound."""

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from api import target_authorization as ta
from api.scan.authorization import (
    ActionAuthorityDecision,
    revalidate_action_authority,
)

TARGET_ID = uuid.uuid4()


class _Conn:
    """Fake connection: a targets row, scope receipts and approval receipts in memory."""

    def __init__(self, url="https://app.example.com/", approvals=None, scopes=None):
        self.url = url
        self.approvals = list(approvals or [])
        self.scopes = dict(scopes or {})
        self.executed = []

    async def fetchrow(self, query, *args):
        if "FROM targets" in query:
            if args and str(args[0]) != str(TARGET_ID):
                return None
            return {"id": TARGET_ID, "url": self.url, "metadata_json": json.dumps({"environment": "production"})}
        if "INSERT INTO approval_receipts" in query:
            row = {
                "id": uuid.uuid4(), "scope_receipt_id": args[0], "risk_tier": args[1],
                "confirmations": args[2], "action_name": args[3], "action_context": args[4],
                "approved_by": args[5], "expires_at": None, "status": "active",
                "created_at": datetime.now(timezone.utc),
            }
            self.approvals.append(row)
            return row
        raise AssertionError(query)

    async def fetch(self, query, *args):
        assert "FROM approval_receipts a" in query
        rows = []
        for approval in self.approvals:
            if approval.get("status") != "active" or not approval.get("approved_by"):
                continue
            if approval.get("risk_tier") not in args[1]:
                continue
            if approval.get("action_name") != args[2]:
                continue
            expires = approval.get("expires_at")
            if expires is not None and expires <= datetime.now(timezone.utc):
                continue
            scope = self.scopes.get(approval["scope_receipt_id"])
            if not scope or str(scope.get("target_id")) != str(args[0]):
                continue
            rows.append({
                **approval, "scope_id": approval["scope_receipt_id"],
                "scope_allowed_hosts": json.dumps(scope["allowed_hosts"]),
                "scope_normalized": json.dumps({"host": scope["host"]}),
                "scope_verdict": scope.get("verdict", "allowed"),
            })
        rows.sort(key=lambda r: (r["expires_at"] is None, r["created_at"]), reverse=True)
        return rows

    async def execute(self, query, *args):
        self.executed.append((query, args))
        if "INSERT INTO scope_receipts" in query:
            self.scopes[args[0]] = {
                "target_id": args[1], "allowed_hosts": json.loads(args[9]),
                "host": json.loads(args[3]).get("host"), "verdict": args[4],
            }
            return "INSERT 0 1"
        if "UPDATE approval_receipts" in query:
            count = 0
            for approval in self.approvals:
                scope = self.scopes.get(approval["scope_receipt_id"]) or {}
                if (approval["status"] == "active" and str(scope.get("target_id")) == str(args[0])
                        and approval.get("action_name") == args[3]):
                    approval["status"] = "revoked"; count += 1
            return f"UPDATE {count}"
        raise AssertionError(query)

    async def fetchval(self, query, *args):
        raise AssertionError(query)


def test_authorize_once_then_reuse_without_expiry():
    conn = _Conn()
    first = asyncio.run(ta.authorize_target(conn, TARGET_ID, approved_by="alice"))
    assert first["standing"] is True and first["expires_at"] is None
    assert first["approved_by"] == "alice" and first["risk_tier"] == "active"
    scope = conn.scopes[first["scope_receipt_id"]]
    assert scope["allowed_hosts"] == ["app.example.com"] and scope["host"] == "app.example.com"
    # Idempotent while it stands: no second receipt.
    again = asyncio.run(ta.authorize_target(conn, TARGET_ID, approved_by="bob"))
    assert again["approval_receipt_id"] == first["approval_receipt_id"]
    assert len(conn.approvals) == 1
    current = asyncio.run(ta.current_target_authorization(conn, TARGET_ID))
    assert current["approval_receipt_id"] == first["approval_receipt_id"]


def test_authorization_does_not_follow_a_target_whose_host_changed():
    conn = _Conn()
    asyncio.run(ta.authorize_target(conn, TARGET_ID, approved_by="alice"))
    conn.url = "https://other.example.com/"
    assert asyncio.run(ta.current_target_authorization(conn, TARGET_ID)) is None
    renewed = asyncio.run(ta.authorize_target(conn, TARGET_ID, approved_by="alice"))
    assert conn.scopes[renewed["scope_receipt_id"]]["host"] == "other.example.com"
    assert len(conn.approvals) == 2


def test_revocation_ends_the_standing_authorization():
    conn = _Conn()
    asyncio.run(ta.authorize_target(conn, TARGET_ID, approved_by="alice"))
    assert asyncio.run(ta.revoke_target_authorization(conn, TARGET_ID, revoked_by="carol", reason="offboarded")) == 1
    assert asyncio.run(ta.current_target_authorization(conn, TARGET_ID)) is None
    with pytest.raises(ta.TargetAuthorizationError, match="required"):
        asyncio.run(ta.revoke_target_authorization(conn, TARGET_ID, revoked_by="", reason="x"))


def test_blocked_scope_and_unknown_target_are_refused():
    with pytest.raises(ta.TargetAuthorizationError, match="blocked"):
        asyncio.run(ta.authorize_target(_Conn(url="http://169.254.169.254/"), TARGET_ID, approved_by="alice"))
    with pytest.raises(ta.TargetAuthorizationError, match="not found"):
        asyncio.run(ta.authorize_target(_Conn(), uuid.uuid4(), approved_by="alice"))
    with pytest.raises(ta.TargetAuthorizationError, match="approved_by"):
        asyncio.run(ta.authorize_target(_Conn(), TARGET_ID, approved_by="  "))


def test_dangerous_tier_receipts_are_never_standing_authorizations():
    with pytest.raises(ta.TargetAuthorizationError, match="active or intrusive"):
        asyncio.run(ta.authorize_target(_Conn(), TARGET_ID, approved_by="alice", risk_tier="dangerous"))


def _decision(approval, *, action_name="web.crawl"):
    scope = {"id": "scope-1", "target_id": str(TARGET_ID), "verdict": "allowed",
             "allowed_hosts": ["app.example.com"], "normalized_scope": {"host": "app.example.com"}}
    return revalidate_action_authority(
        action={"capability_name": "xss.verify", "action_id": action_name},
        target_binding={"target_id": str(TARGET_ID), "status": "active", "scope_receipt_id": "scope-1",
                        "canonical_host": "app.example.com"},
        scope_receipt=scope,
        approval_receipt=approval,
        scope_receipt_id="scope-1",
        approval_receipt_id=str(approval["id"]),
    )


def test_runtime_revalidation_accepts_a_standing_receipt_and_still_expires_bounded_ones():
    standing = {"id": uuid.uuid4(), "scope_receipt_id": "scope-1", "risk_tier": "active",
                "action_name": ta.STANDING_ACTION_NAME, "approved_by": "alice", "expires_at": None,
                "confirmations": ["confirm_authorized"], "status": "active"}
    assert _decision(standing) is ActionAuthorityDecision.ALLOWED
    ordinary = {**standing, "id": uuid.uuid4(), "action_name": None}
    assert _decision(ordinary) is ActionAuthorityDecision.REJECTED_MISSING, "no expiry, not standing"
    expired = {**standing, "id": uuid.uuid4(), "expires_at": datetime.now(timezone.utc) - timedelta(minutes=1)}
    assert _decision(expired) is ActionAuthorityDecision.REJECTED_EXPIRED
    dangerous = {**standing, "id": uuid.uuid4(), "risk_tier": "dangerous"}
    assert _decision(dangerous) is ActionAuthorityDecision.REJECTED_MISSING, "dangerous needs a bounded receipt"


def test_a_receipt_without_the_standing_action_name_is_not_a_standing_authorization():
    """One definition of standing, or a target deadlocks.

    Receipts recorded before the standing-authorization contract carry no
    action_name. The resolver counted them as standing, so the target reported
    itself authorized -- while the submission gate, which compares the exact
    action_name, refused every active scan of it, and revoke, which matches the
    same name, could never clear it. Because authorization is recorded once per
    target, re-authorizing returned the same unusable receipt: the target could
    not be scanned and could not be fixed.
    """
    scope_id = "scope-legacy"
    legacy = {
        "id": uuid.uuid4(), "scope_receipt_id": scope_id, "risk_tier": "active",
        "action_name": None, "approved_by": "benchmark", "expires_at": None,
        "confirmations": ["confirm_authorized"], "status": "active",
        "created_at": datetime.now(timezone.utc),
    }
    conn = _Conn(
        url="https://app.example.com/",
        approvals=[legacy],
        scopes={scope_id: {"target_id": TARGET_ID, "allowed_hosts": ["app.example.com"],
                           "normalized_scope": {"host": "app.example.com"}, "verdict": "allowed"}},
    )

    assert asyncio.run(ta.current_target_authorization(conn, TARGET_ID)) is None

    # The runtime gate already agreed: a receipt with no action_name and no
    # expiry is not standing, which is exactly why the two disagreeing deadlocked.
    assert _decision(legacy) is not ActionAuthorityDecision.ALLOWED
