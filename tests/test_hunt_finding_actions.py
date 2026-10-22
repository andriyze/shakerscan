from __future__ import annotations

import asyncio
import json
import uuid

import pytest

from api.hunt.finding_actions import (
    HuntFindingActionError,
    create_hunt_finding,
    _finding_url,
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
    def __init__(self, *, expose_evidence: bool = True, target_url="https://example.test/app",
                 observed_urls=(), status="active", completed_at=None, admitted_origins=()):
        self.hunt_id = uuid.uuid4()
        self.target_id = uuid.uuid4()
        self.finding_id = uuid.uuid4()
        self.expose_evidence = expose_evidence
        self.insert_args = None
        self.target_url, self.observed_urls = target_url, observed_urls
        self.status, self.completed_at = status, completed_at
        self.admitted_origins = admitted_origins
        self.fingerprints = set()

    def transaction(self):
        return _Transaction()

    async def fetchrow(self, query, *args):
        if "FROM hunt_runs" in query:
            return {
                "id": self.hunt_id,
                "status": self.status,
                "completed_at": self.completed_at,
                "target_kind": "web",
                "target_id": self.target_id,
                "device_target_id": None,
                "context_pack": {"target": {"url": self.target_url, "origins": self.admitted_origins}},
            }
        if "INSERT INTO findings" in query:
            self.insert_args = args
            if args[3] in self.fingerprints:
                return None
            self.fingerprints.add(args[3])
            return {"id": self.finding_id, "status": "active", "created_at": None}
        if "FROM findings" in query:
            return {"id": self.finding_id, "status": "active", "created_at": None,
                    "last_verified_at": None, "verification_count": 0}
        raise AssertionError(query)

    async def fetch(self, query, *args):
        if "FROM http_transactions" in query:
            return [{"url": url} for url in self.observed_urls]
        if "FROM hunt_actions" in query:
            return [{"id": action_id} for action_id in args[1]] if self.expose_evidence else []
        raise AssertionError(query)

    async def execute(self, query, *args):
        if query.lstrip().startswith("UPDATE targets"):
            return "UPDATE 1"
        raise AssertionError(query)


def _create(connection: _Connection, *, evidence_action_id: uuid.UUID, path="/admin"):
    return asyncio.run(create_hunt_finding(
        _Pool(connection),
        hunt_id=connection.hunt_id,
        action_id=uuid.uuid4(),
        values={
            "title": "Exposed token",
            "description": "Authorization: Bearer secret-value",
            "severity": "high",
            "path": path,
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


@pytest.mark.parametrize("target,observed,path,expected", [
    ("https://example.test:8443", (), "/admin", "https://example.test:8443/admin"),
    ("http://example.test:8080", (), "/admin", "http://example.test:8080/admin"),
    ("host://example.test", ("http://example.test:8081/admin",), "/admin", "http://example.test:8081/admin"),
    ("host://example.test", ("https://example.test:8443/admin",), "https://example.test:8443/admin", "https://example.test:8443/admin"),
    ("https://example.test", ("https://example.test:8443/admin",), "/admin", "https://example.test:8443/admin"),
])
def test_the_cited_service_port_reaches_the_findings_insert(target, observed, path, expected):
    connection = _Connection(target_url=target, observed_urls=observed)
    _create(connection, evidence_action_id=uuid.uuid4(), path=path)
    assert connection.insert_args[7] == expected


def test_frozen_service_origin_does_not_depend_on_complete_http_archive_capture():
    connection = _Connection(target_url="https://example.test", admitted_origins=("https://example.test:8443",))
    _create(connection, evidence_action_id=uuid.uuid4(), path="https://example.test:8443/admin")
    assert connection.insert_args[7] == "https://example.test:8443/admin"
    with pytest.raises(HuntFindingActionError):
        _create(connection, evidence_action_id=uuid.uuid4(), path="https://other.test:8443/admin")


def test_two_services_with_the_same_path_need_an_explicit_origin():
    with pytest.raises(HuntFindingActionError, match="absolute URL"):
        _finding_url("https://example.test", "/admin", ["http://example.test:8081/admin", "https://example.test:8443/admin"])


def test_duplicate_creation_returns_the_existing_finding_without_overwriting_it():
    connection = _Connection()
    first = _create(connection, evidence_action_id=uuid.uuid4())
    second = _create(connection, evidence_action_id=uuid.uuid4())
    assert first["finding_id"] == second["finding_id"]
    assert first["created"] is True and second["created"] is False
    assert second["observation"]["operation"] == "existing"


def test_unfinished_exhausted_hunt_can_persist_evidence_but_finished_hunt_cannot():
    connection = _Connection(status="budget_exhausted")
    assert _create(connection, evidence_action_id=uuid.uuid4())["created"]
    connection.completed_at = "finished"
    with pytest.raises(HuntFindingActionError, match="budget_exhausted"):
        _create(connection, evidence_action_id=uuid.uuid4())


def test_hunt_create_rejects_evidence_not_owned_by_the_same_hunt():
    connection = _Connection(expose_evidence=False)
    with pytest.raises(HuntFindingActionError, match="from this Hunt"):
        _create(connection, evidence_action_id=uuid.uuid4())
    assert connection.insert_args is None


@pytest.mark.parametrize("path", ["/api/status", "http://tv.test:8081/api/status"])
def test_network_finding_accepts_an_evidenced_same_asset_service(path):
    assert _finding_url("host://tv.test", path, ["http://tv.test:8081/login"]) == "http://tv.test:8081/api/status"


def test_relative_network_finding_requires_an_unambiguous_evidenced_service():
    with pytest.raises(HuntFindingActionError, match="absolute URL"):
        _finding_url("host://tv.test", "/status", ["http://tv.test:8081/", "https://tv.test:8443/"])
    assert _finding_url("https://tv.test", "https://tv.test:443/status") == "https://tv.test:443/status"


@pytest.mark.parametrize("path", ["http://other.test:8081/a", "http://tv.test:8082/a", "http://user:secret@tv.test:8081/a", "//other.test/a"])
def test_network_finding_rejects_unevidenced_or_cross_asset_service(path):
    with pytest.raises(HuntFindingActionError):
        _finding_url("host://tv.test", path, ["http://tv.test:8081/"])


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
