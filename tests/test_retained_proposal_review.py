"""The rolling retained-checks proposal: what it leaves out and what accepting it requires.

The database is a labelled fixture that answers the module's own queries; the recipe validation,
merge and review text are production code.
"""
from __future__ import annotations

import asyncio
import json
from uuid import uuid4

import pytest
from fastapi import HTTPException

from hunt.saved_actions import RETAINED_ACTION_NAME, RETAINED_INSTRUCTIONS, merge_retained_steps
from targets import instruction_proposals as proposals

TARGET = uuid4()


def _step(path):
    return {"capability": "javascript.analyze", "input": {"path": path}}


class Conn:
    """Labelled fixture: a target with no saved actions, an optional pending and rejected retained
    proposal, and a captured insert or update."""

    def __init__(self, *, pending=None, rejected=None):
        self.pending, self.rejected, self.written = pending, rejected, None

    def transaction(self):
        class _Transaction:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False
        return _Transaction()

    async def execute(self, query, *args):
        assert "pg_advisory_xact_lock" in query

    async def fetchrow(self, query, *args):
        if "status='pending'" in query and "proposed_by=$2" in query:
            return self.pending
        if "status='rejected'" in query:
            return self.rejected
        if query.lstrip().startswith(("INSERT INTO target_instruction_proposals", "UPDATE target_instruction_proposals")):
            self.written = args
            return {"id": uuid4()}
        if "FROM target_instruction_proposals" in query and "FOR UPDATE" in query:
            return self.pending
        raise AssertionError(query)


@pytest.fixture(autouse=True)
def _target(monkeypatch):
    async def target(conn, target_id, lock=False):
        return {"id": TARGET}

    async def actions(conn, target_id):
        return {"revision": 3, "actions": []}

    async def unknown(conn, target_id, refs):
        return []
    monkeypatch.setattr(proposals, "_target", target)
    monkeypatch.setattr(proposals, "read_target_actions", actions)
    monkeypatch.setattr(proposals, "_unknown_evidence", unknown)


def _refresh(conn, steps):
    return asyncio.run(proposals.refresh_retained_proposal(
        conn, TARGET, steps=steps, evidence_refs=[], hunt_run_id=uuid4(), name=RETAINED_ACTION_NAME,
        instructions=RETAINED_INSTRUCTIONS, merge=merge_retained_steps))


def test_a_step_rejected_in_the_latest_retained_proposal_is_not_proposed_again():
    rejected = {"action_body": json.dumps({"name": RETAINED_ACTION_NAME, "instructions": "", "parameters": {},
                                           "steps": [_step("/static/rejected.js")]})}
    conn = Conn(rejected=rejected)
    result = _refresh(conn, [_step("/static/rejected.js"), _step("/static/kept.js")])
    assert result["status"] == "proposed" and result["step_count"] == 1
    body = json.loads(conn.written[-1])
    assert [step["input"]["path"] for step in body["steps"]] == ["/static/kept.js"]
    # Only rejected steps: nothing is proposed.
    conn = Conn(rejected=rejected)
    assert _refresh(conn, [_step("/static/rejected.js")])["status"] == "skipped" and conn.written is None


def _pending(sha="a" * 64):
    return {"id": uuid4(), "status": "pending", "kind": "saved_action", "proposed_by": proposals.RETAINED_PROPOSER,
            "methodology_sha256": sha, "base_revision": 3, "action_operation": "create", "action_id": None,
            "action_body": json.dumps({"name": RETAINED_ACTION_NAME, "instructions": "", "parameters": {},
                                       "steps": [_step("/static/app.js")]})}


def test_accepting_the_retained_proposal_requires_the_reviewed_text_digest(monkeypatch):
    written = []

    async def accept(conn, row, proposal, **kwargs):
        written.append(proposal["id"])
        return {"accepted": True}
    monkeypatch.setattr(proposals, "_accept_action", accept)
    pending = _pending()
    with pytest.raises(HTTPException) as refused:
        asyncio.run(proposals.accept_proposal(Conn(pending=pending), TARGET, str(pending["id"]), actor="operator:a"))
    assert refused.value.status_code == 422
    assert refused.value.detail["error"] == "proposal_review_required"
    assert "methodology_sha256" in refused.value.detail["message"]
    # A later finish changed the text after the review: refused as before.
    with pytest.raises(HTTPException) as changed:
        asyncio.run(proposals.accept_proposal(Conn(pending=pending), TARGET, str(pending["id"]), actor="operator:a",
                                              reviewed_sha256="b" * 64))
    assert changed.value.detail["error"] == "proposal_text_mismatch"
    assert written == []
    asyncio.run(proposals.accept_proposal(Conn(pending=pending), TARGET, str(pending["id"]), actor="operator:a",
                                          reviewed_sha256="a" * 64))
    assert written == [pending["id"]]


def test_other_proposals_may_still_be_accepted_without_a_digest(monkeypatch):
    written = []

    async def accept(conn, row, proposal, **kwargs):
        written.append(proposal["id"])
        return {"accepted": True}
    monkeypatch.setattr(proposals, "_accept_action", accept)
    planner = {**_pending(), "proposed_by": f"hunt:{uuid4()}"}
    asyncio.run(proposals.accept_proposal(Conn(pending=planner), TARGET, str(planner["id"]), actor="operator:a"))
    assert written == [planner["id"]]
