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
                 observed_urls=(), status="active", completed_at=None, admitted_origins=(),
                 device=False, device_results=(), verification_count=0):
        self.hunt_id = uuid.uuid4()
        self.target_id = uuid.uuid4()
        self.finding_id = uuid.uuid4()
        self.device = device
        # Labelled fixture: result summaries of cited device.http.probe actions.
        self.device_results = device_results
        self.verification_count = verification_count
        self.stored_evidence = None
        self.expose_evidence = expose_evidence
        self.insert_args = None
        self.target_url, self.observed_urls = target_url, observed_urls
        self.status, self.completed_at = status, completed_at
        self.admitted_origins = admitted_origins
        self.fingerprints = set()
        self.locks = []

    def transaction(self):
        return _Transaction()

    async def fetchrow(self, query, *args):
        if "FROM hunt_runs" in query:
            self.locks.append("hunt")
            target = ({"kind": "device", "locator": self.target_url} if self.device
                      else {"url": self.target_url, "origins": self.admitted_origins})
            return {
                "id": self.hunt_id,
                "status": self.status,
                "completed_at": self.completed_at,
                "target_kind": "device" if self.device else "web",
                "target_id": None if self.device else self.target_id,
                "device_target_id": self.target_id if self.device else None,
                "context_pack": {"target": target},
            }
        if "INSERT INTO findings" in query:
            self.insert_args = args
            if args[3] in self.fingerprints:
                return None
            self.fingerprints.add(args[3])
            self.stored_evidence = args[8]
            return {"id": self.finding_id, "status": "active", "created_at": None}
        if "FROM findings" in query:
            return {"id": self.finding_id, "status": "active", "created_at": None,
                    "last_verified_at": "verified" if self.verification_count else None,
                    "verification_count": self.verification_count, "evidence": self.stored_evidence}
        raise AssertionError(query)

    async def fetch(self, query, *args):
        if "FROM http_transactions" in query:
            return [{"url": url} for url in self.observed_urls]
        if "FROM hunt_actions" in query and "result_summary" in query:
            assert "device.http.probe" in query
            return [{"result_summary": summary} for summary in self.device_results]
        if "FROM hunt_actions" in query:
            return [{"id": action_id} for action_id in args[1]] if self.expose_evidence else []
        raise AssertionError(query)

    async def execute(self, query, *args):
        if query.lstrip().startswith(("UPDATE targets", "UPDATE device_targets")):
            return "UPDATE 1"
        if "FOR NO KEY UPDATE" in query:
            self.locks.append("device_target" if "FROM device_targets" in query else "target")
            return "SELECT 1"
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
    evidence = uuid.uuid4()
    first = _create(connection, evidence_action_id=evidence)
    second = _create(connection, evidence_action_id=uuid.uuid4())
    assert first["finding_id"] == second["finding_id"]
    assert first["created"] is True and second["created"] is False
    assert second["observation"]["operation"] == "existing"
    # The record is returned unchanged and says the newly cited evidence was not attached.
    assert second["evidence_attached"] is False and "findings.update" in second["message"]
    assert json.loads(connection.stored_evidence)["source_action_ids"] == [str(evidence)]
    same = _create(connection, evidence_action_id=evidence)
    assert same["created"] is False and same["evidence_attached"] is True and "message" not in same


def test_a_duplicate_of_a_verified_finding_returns_it_instead_of_refusing():
    connection = _Connection()
    _create(connection, evidence_action_id=uuid.uuid4())
    connection.verification_count = 1
    again = _create(connection, evidence_action_id=uuid.uuid4())
    assert again["created"] is False and again["finding_id"] == str(connection.finding_id)
    assert again["verification_history"] is True and again["proof_state"] is None
    assert again["evidence_attached"] is False and "verification history" in again["message"]
    assert "findings.update" not in again["message"]


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


@pytest.mark.parametrize("observed,path,expected", [
    # The inventory's own service is among those evidenced: a relative path stays on it.
    (("https://example.test/a", "https://example.test:8443/b"), "/other", "https://example.test/other"),
    (("http://example.test/login", "https://example.test/login"), "/login", "https://example.test/login"),
    # Only another service is evidenced: the relative path follows it.
    (("https://example.test:8443/admin",), "/admin", "https://example.test:8443/admin"),
])
def test_a_relative_path_prefers_the_inventory_service_when_it_is_evidenced(observed, path, expected):
    assert _finding_url("https://example.test", path, observed) == expected


@pytest.mark.parametrize("locator,observed,path,expected", [
    ("192.168.1.20", ("http://192.168.1.20:8080/admin",), "/admin", "http://192.168.1.20:8080/admin"),
    ("192.168.1.20", ("http://192.168.1.20:8080/admin",), "http://192.168.1.20:8080/admin",
     "http://192.168.1.20:8080/admin"),
    ("router.local", ("https://router.local/status",), "/status", "https://router.local/status"),
    ("2001:db8::5", ("http://[2001:db8::5]:8080/admin",), "/admin", "http://[2001:db8::5]:8080/admin"),
    ("[2001:db8::5]", ("http://[2001:0db8:0::5]:8080/admin",), "/admin", "http://[2001:db8::5]:8080/admin"),
    ("2001:db8::5", ("https://[2001:db8::5]/x",), "https://[2001:db8::5]/admin", "https://[2001:db8::5]/admin"),
])
def test_a_device_locator_is_a_host_whose_evidenced_service_takes_the_finding(locator, observed, path, expected):
    assert _finding_url(locator, path, observed) == expected


@pytest.mark.parametrize("locator,observed,path", [
    ("192.168.1.20", ("http://192.168.1.20:8080/admin",), "http://192.168.1.21:8080/admin"),
    ("192.168.1.20", ("http://192.168.1.20:8080/admin",), "http://192.168.1.20:8081/admin"),
    ("192.168.1.20", (), "/admin"),
    ("192.168.1.20", ("http://192.168.1.20:8080/", "https://192.168.1.20/"), "/admin"),
    ("2001:db8::5", ("http://[2001:db8::5]:8080/",), "http://[2001:db8::6]:8080/admin"),
])
def test_a_device_finding_stays_on_an_evidenced_service_of_the_device(locator, observed, path):
    with pytest.raises(HuntFindingActionError):
        _finding_url(locator, path, observed)


def test_a_device_hunt_saves_a_path_finding_on_its_evidenced_service():
    connection = _Connection(target_url="192.168.1.20", device=True,
                             observed_urls=("http://192.168.1.20:8080/admin",))
    _create(connection, evidence_action_id=uuid.uuid4(), path="/admin")
    assert connection.insert_args[0] is None and connection.insert_args[1] == connection.target_id
    assert connection.insert_args[7] == "http://192.168.1.20:8080/admin"


def test_a_device_http_probe_cited_as_evidence_names_its_service():
    connection = _Connection(target_url="192.168.1.20", device=True, device_results=(
        {"ok": True, "data": {"origin": "http://192.168.1.20:8080", "path": "/admin"}},
        json.dumps({"ok": True, "data": {"origin": "http://192.168.1.20:8080"}}),
        {"ok": True, "data": {"origin": 7}}, "not json", None,
    ))
    _create(connection, evidence_action_id=uuid.uuid4(), path="/admin")
    assert connection.insert_args[7] == "http://192.168.1.20:8080/admin"


@pytest.mark.parametrize("admitted", [(123,), ({"origin": "https://example.test:8443"},), ("http://[::1",),
                                       "https://example.test:8443"])
def test_malformed_frozen_origins_are_refused_as_input_errors(admitted):
    connection = _Connection(target_url="https://example.test", admitted_origins=admitted)
    with pytest.raises(HuntFindingActionError, match="frozen"):
        _create(connection, evidence_action_id=uuid.uuid4(), path="https://example.test:8443/admin")


def test_a_malformed_archive_url_is_ignored_rather_than_refusing_the_finding():
    assert _finding_url("https://example.test", "/admin", ["http://[::1", "https://example.test:8443/admin"]) == (
        "https://example.test:8443/admin")


def test_a_host_asset_resolves_a_relative_path_like_its_absolute_url():
    origins = ["https://tv.test:8443"]
    assert _finding_url("host://tv.test", "https://tv.test:8443/status", [], origins) == "https://tv.test:8443/status"
    assert _finding_url("host://tv.test", "/status", [], origins) == "https://tv.test:8443/status"
    with pytest.raises(HuntFindingActionError, match="absolute URL"):
        _finding_url("host://tv.test", "/status", [], ["https://tv.test:8443", "http://tv.test:8081"])
    with pytest.raises(HuntFindingActionError):
        _finding_url("host://tv.test", "/status", [], [])


@pytest.mark.parametrize("device", [False, True])
def test_a_finding_write_locks_its_target_before_its_hunt(device):
    """Operator retractions lock the target, then the Hunt; a finding write takes the same order,
    so the two cannot deadlock."""
    connection = _Connection(target_url="192.168.1.20" if device else "https://example.test", device=device,
                             observed_urls=("http://192.168.1.20:8080/admin",) if device else ())
    _create(connection, evidence_action_id=uuid.uuid4())
    assert connection.locks[:3] == ["target", "device_target", "hunt"]


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
