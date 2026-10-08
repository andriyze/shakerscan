"""A finding materialized by a Hunt's candidate.verify is attributed to that Hunt.

Live: Hunt 7dfe2b92 verified BOLA candidate cd383366 into finding 54a489bc, whose hunt_run_id was
NULL, so the Hunt's outcome_summary.finding_ids was [] although GET /findings?hunt_id found it.
Attribution follows E2E H-19 (authz.verify): the finding row names the Hunt whose proof made it.
"""
from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager

from api.hunt import interaction_router as router
from api.hunt.run_service import _action_reference_ids

HUNT, TARGET, CANDIDATE, FINDING = (uuid.uuid4() for _ in range(4))
RUN = {"id": HUNT, "target_id": TARGET, "device_target_id": None}
ACTION = uuid.uuid4()


class _Conn:
    """Unit double for the finding row: answers the owner read and records every statement."""

    def __init__(self, result=None, owner=None):
        self.calls = []
        self.result = result
        self.owner = owner

    def _record(self, sql, args):
        self.calls.append((" ".join(sql.split()), args))
        if isinstance(self.result, Exception):
            raise self.result

    @asynccontextmanager
    async def transaction(self):
        yield self

    async def fetchrow(self, sql, *args):
        self._record(sql, args)
        return {"id": args[0], "hunt_run_id": self.owner}

    async def fetchval(self, sql, *args):
        self._record(sql, args)
        self.owner = args[1]
        return self.owner

    async def execute(self, sql, *args):
        self._record(sql, args)
        return "INSERT 0 1"


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self.conn


def _verify(monkeypatch, verification, conn):
    async def verifier(candidate_uuid, approval, *, created_by, autonomous):
        assert candidate_uuid == CANDIDATE and created_by == f"hunt_v2:{HUNT}"
        assert autonomous is False  # a Hunt verifies under its own authority
        return dict(verification)

    monkeypatch.setattr(router, "_verify_suspected_finding_workflow", verifier)
    monkeypatch.setattr(router, "_pool", lambda: _Pool(conn))
    return asyncio.run(router._execute_hunt_candidate_verification(
        run=RUN, context={}, policy={"approval_receipt_id": "approval"}, candidate_uuid=CANDIDATE,
        action_id=ACTION,
    ))


def test_a_verified_candidate_finding_is_attributed_to_the_hunt(monkeypatch):
    conn = _Conn()
    result = _verify(monkeypatch, {
        "finding_id": str(CANDIDATE), "candidate_id": str(CANDIDATE), "verified": True,
        "verified_finding_id": str(FINDING),
    }, conn)
    assert result["hunt_attributed"] is True
    assert result["hunt_attribution"]["role"] == "owner"
    assert result["hunt_attribution"]["owner_hunt_id"] == str(HUNT)
    (read, read_args), (claim, claim_args), (record, record_args) = conn.calls
    assert read.startswith("SELECT id, hunt_run_id FROM findings") and read.endswith("FOR UPDATE")
    assert "last_verified_at IS NOT NULL" in read and read_args == (FINDING, TARGET)
    # Only an unowned finding is claimed, so a concurrent claim cannot overwrite an owner.
    assert claim.startswith("UPDATE findings SET hunt_run_id=$2") and "hunt_run_id IS NULL" in claim
    assert claim_args == (FINDING, HUNT)
    assert record.startswith("INSERT INTO finding_hunt_verifications")
    assert record_args == (FINDING, HUNT, ACTION)


def test_a_finding_another_hunt_owns_is_not_taken_over(monkeypatch):
    """D21: a later Hunt's re-verification is recorded beside the owner, never instead of it."""
    first_hunt = uuid.uuid4()
    conn = _Conn(owner=first_hunt)
    result = _verify(monkeypatch, {"verified": True, "verified_finding_id": str(FINDING)}, conn)
    assert result["hunt_attributed"] is True
    assert result["hunt_attribution"] == {
        "schema_version": "finding-hunt-verification/v1", "finding_id": str(FINDING),
        "owner_hunt_id": str(first_hunt), "role": "additional",
    }
    assert not any(sql.startswith("UPDATE findings") for sql, _ in conn.calls)
    ((record, record_args),) = [call for call in conn.calls if call[0].startswith("INSERT")]
    assert record_args == (FINDING, HUNT, ACTION)


def test_an_unverified_result_attributes_nothing(monkeypatch):
    conn = _Conn()
    result = _verify(monkeypatch, {"candidate_id": str(CANDIDATE), "verified": False,
                                   "verified_finding_id": None}, conn)
    assert "hunt_attributed" not in result and conn.calls == []


def test_attribution_failure_never_fails_the_verification(monkeypatch):
    result = _verify(monkeypatch, {"verified": True, "verified_finding_id": str(FINDING)},
                     _Conn(RuntimeError("database unavailable")))
    assert result["verified"] is True and result["hunt_attributed"] is False
    assert "hunt_attribution" not in result


def test_the_action_references_name_the_verified_finding_not_the_candidate(monkeypatch):
    verification = _verify(monkeypatch, {
        "finding_id": str(CANDIDATE), "candidate_id": str(CANDIDATE), "verified": True,
        "verified_finding_id": str(FINDING),
    }, _Conn())
    action_result = router._candidate_verification_action_result(CANDIDATE, verification)
    assert "finding_id" not in action_result["verification"]
    references = _action_reference_ids(action_result)
    assert references["finding_ids"] == [str(FINDING)]
    assert references["candidate_ids"] == [str(CANDIDATE)]
