from __future__ import annotations

import asyncio
import json
import uuid

import pytest

from api.hunt.finding_actions import (
    HuntFindingActionError,
    create_hunt_finding,
)
from api.runtime.capability_registry import (
    CAPABILITY_REGISTRY,
    CapabilityInputContractError,
)


class _Transaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class _Acquire:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *_args):
        return False


class _Pool:
    def __init__(self, connection):
        self.connection = connection

    def acquire(self):
        return _Acquire(self.connection)


class _Connection:
    def __init__(self, *, expose_evidence: bool = True):
        self.hunt_id = uuid.uuid4()
        self.target_id = uuid.uuid4()
        self.finding_id = uuid.uuid4()
        self.expose_evidence = expose_evidence
        self.insert_args = None

    def transaction(self):
        return _Transaction()

    async def fetchrow(self, query, *args):
        if "FROM hunt_runs" in query:
            return {
                "id": self.hunt_id,
                "status": "active",
                "target_kind": "web",
                "target_id": self.target_id,
                "device_target_id": None,
                "context_pack": {"target": {"url": "https://example.test/app"}},
            }
        if "INSERT INTO findings" in query:
            self.insert_args = args
            return {"id": self.finding_id, "status": "active", "created_at": None}
        raise AssertionError(query)

    async def fetch(self, query, *args):
        if "FROM hunt_actions" in query:
            return [{"id": action_id} for action_id in args[1]] if self.expose_evidence else []
        raise AssertionError(query)

    async def execute(self, query, *args):
        if query.lstrip().startswith("UPDATE targets"):
            return "UPDATE 1"
        raise AssertionError(query)


def _create(connection: _Connection, *, evidence_action_id: uuid.UUID):
    return asyncio.run(create_hunt_finding(
        _Pool(connection),
        hunt_id=connection.hunt_id,
        action_id=uuid.uuid4(),
        values={
            "title": "Exposed token",
            "description": "Authorization: Bearer secret-value",
            "severity": "high",
            "path": "/admin",
            "evidence_summary": "token=super-secret-value",
            "evidence_action_ids": [str(evidence_action_id)],
        },
    ))


def test_hunt_create_persists_an_unverified_evidence_linked_finding():
    connection = _Connection()
    result = _create(connection, evidence_action_id=uuid.uuid4())

    assert result["finding_id"] == str(connection.finding_id)
    assert result["proof_state"] == "unverified"
    assert result["authoritative"] is False
    assert connection.insert_args is not None
    evidence = json.loads(connection.insert_args[8])
    assert evidence["proof_state"] == "unverified"
    assert evidence["authoritative"] is False
    assert evidence["source_action_ids"]
    assert "super-secret-value" not in repr(connection.insert_args)
    assert connection.insert_args[7] == "https://example.test/admin"


def test_hunt_create_rejects_evidence_not_owned_by_the_same_hunt():
    connection = _Connection(expose_evidence=False)
    with pytest.raises(HuntFindingActionError, match="from this Hunt"):
        _create(connection, evidence_action_id=uuid.uuid4())
    assert connection.insert_args is None


def test_finding_capabilities_cannot_accept_verification_or_proof_fields():
    for capability in ("findings.create", "findings.update", "findings.delete"):
        specification = CAPABILITY_REGISTRY.require(capability)
        assert specification.risk_tier == "active"
        assert specification.required_approval == "active_testing"
        assert specification.placement_requirements["runtime_target_binding"] is True

    with pytest.raises(CapabilityInputContractError, match="unsupported fields"):
        CAPABILITY_REGISTRY.validate_input("findings.create", {
            "title": "Candidate",
            "description": "Observed behavior",
            "severity": "medium",
            "evidence_summary": "Action observed a response difference",
            "evidence_action_ids": [str(uuid.uuid4())],
            "verified": True,
            "proof_state": "verified",
        })
