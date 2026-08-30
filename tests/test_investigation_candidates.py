from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)
import asyncio
import os
import uuid

import pytest

from api import investigation_candidates as candidates
from api.runtime.capability_registry import CAPABILITY_REGISTRY


def test_web_and_device_candidate_boundaries_are_mutually_exclusive():
    web_run_id = str(uuid.uuid4())
    web = candidates.normalize_candidate(
        plane="web",
        target_id=str(uuid.uuid4()),
        agent_hunt_run_id=web_run_id,
        family="sql-injection",
        locus={"method": "get", "route": "/search", "parameter": "q"},
        title="SQLi candidate",
        claim="Repeated differential",
        severity="high",
        evidence_refs=["resp_1", "resp_1", "resp_2"],
    )
    device = candidates.normalize_candidate(
        plane="device",
        device_target_id=str(uuid.uuid4()),
        family="service exposure",
        locus={"transport": "tcp", "port": 23},
        title="Telnet exposure",
        claim="Port responded",
    )

    assert web["family"] == "sqli"
    assert web["canonical_locus"]["method"] == "GET"
    assert web["evidence_refs"] == ["resp_1", "resp_2"]
    assert web["agent_hunt_run_id"] == web_run_id
    assert device["target_id"] is None
    assert device["device_target_id"] is not None
    assert device["family"] == "device_service_exposure"
    assert device["verifier_contract_id"] == "device.service_exposure"


def test_device_verifier_contract_is_server_selected_for_every_supported_family():
    device_id = str(uuid.uuid4())
    expected = {
        "tls": "device.tls",
        "auth_bypass": "device.auth_bypass",
        "control_authorization": "device.control_authorization",
        "firmware_advisory": "device.firmware_advisory",
        "ssh_posture": "device.ssh_posture",
    }
    for family, contract in expected.items():
        normalized = candidates.normalize_candidate(
            plane="device",
            device_target_id=device_id,
            family=family,
            locus={"transport": "tcp", "port": 443},
            title=family,
            claim="candidate",
            verifier_contract_id="model.supplied.contract.must.not_win",
        )
        assert normalized["verifier_contract_id"] == contract


def test_candidate_fingerprint_is_stable_and_target_bound():
    target_a = str(uuid.uuid4())
    target_b = str(uuid.uuid4())
    locus_a = {"route": "/users/1", "method": "GET", "parameter": "id"}
    locus_b = {"parameter": "id", "method": "get", "route": "/users/1"}

    first = candidates.candidate_fingerprint(
        plane="web", target_ref=target_a, family="idor", locus=locus_a,
    )
    same = candidates.candidate_fingerprint(
        plane="web", target_ref=target_a, family="bola", locus=locus_b,
    )
    other_target = candidates.candidate_fingerprint(
        plane="web", target_ref=target_b, family="bola", locus=locus_b,
    )

    assert first == same
    assert first != other_target


def test_candidate_upsert_never_claims_authority():
    candidate_id = uuid.uuid4()

    class FakeConnection:
        def __init__(self):
            self.observation_args = None

        async def fetchrow(self, query, *args):
            assert "investigation_candidates" in query
            return {
                "id": candidate_id,
                "status": "new",
                "fingerprint": candidate["fingerprint"],
                "created_at": None,
                "updated_at": None,
                "inserted": True,
            }

        async def execute(self, query, *args):
            assert "investigation_candidate_observations" in query
            self.observation_args = args
            return "INSERT 0 1"

    candidate = candidates.normalize_candidate(
        plane="device",
        device_target_id=str(uuid.uuid4()),
        family="service_exposure",
        locus={"transport": "tcp", "port": 80},
        title="HTTP exposed",
        claim="Observed by Device Hunt",
    )
    connection = FakeConnection()
    result = asyncio.run(candidates.upsert_candidate(connection, candidate, created_by="test"))

    assert result["id"] == str(candidate_id)
    assert result["authoritative"] is False
    assert result["status"] == "new"
    assert result["inserted"] is True
    assert connection.observation_args[0] == candidate_id


def test_terminal_upsert_is_immutable_and_every_sighting_appends_an_observation():
    source = open(candidates.__file__, encoding="utf-8").read()
    assert source.count("investigation_candidates.status IN ('verified','refuted','expired')") >= 5
    assert "INSERT INTO investigation_candidate_observations" in source
    assert "agent_hunt_run_id" in source

    migration_path = os.path.join(os.path.dirname(__file__), "..", "api", "retest_contract.py")
    migration = open(migration_path, encoding="utf-8").read()
    assert "CREATE TABLE IF NOT EXISTS investigation_candidate_observations" in migration
    assert "REFERENCES agent_hunt_runs(id) ON DELETE SET NULL" in migration


def _candidate_row(*, status="new"):
    return {
        "id": uuid.uuid4(),
        "plane": "web",
        "target_id": uuid.uuid4(),
        "device_target_id": None,
        "family": "sqli",
        "canonical_locus": {"method": "GET", "route": "/search", "parameter": "q"},
        "title": "Original title",
        "claim": "Original claim",
        "claimed_severity": "medium",
        "evidence_refs": ["evidence-1"],
        "verifier_contract_id": "web.sqli",
        "source_kind": "hunt_v2",
        "status": status,
        "latest_verification_id": uuid.uuid4() if status == "inconclusive" else None,
    }


class _CandidateLifecycleConnection:
    def __init__(self, row):
        self.row = dict(row) if row is not None else None
        self.observations = []
        self.queries = []

    async def fetchrow(self, query, *args):
        self.queries.append((query, args))
        if query.lstrip().startswith("SELECT c.*"):
            return dict(self.row) if self.row is not None else None
        if "SET title=$2" in query:
            self.row.update({
                "title": args[1],
                "claim": args[2],
                "claimed_severity": args[3],
                "evidence_refs": args[4],
                "verifier_contract_id": args[5],
                "status": "new" if self.row["status"] in {"inconclusive", "blocked"} else self.row["status"],
                "latest_verification_id": None if self.row["status"] in {"inconclusive", "blocked"} else self.row["latest_verification_id"],
            })
            return dict(self.row)
        if "SET status='expired'" in query:
            self.row["status"] = "expired"
            return dict(self.row)
        raise AssertionError(query)

    async def execute(self, query, *args):
        assert "INSERT INTO investigation_candidate_observations" in query
        self.observations.append(args)
        return "INSERT 0 1"


def test_hunt_can_update_its_candidate_without_gaining_proof_authority():
    conn = _CandidateLifecycleConnection(_candidate_row(status="inconclusive"))
    result = asyncio.run(candidates.update_candidate_for_hunt(
        conn,
        hunt_run_id=str(uuid.uuid4()),
        candidate_id=str(conn.row["id"]),
        changes={"title": "Corrected title", "severity": "high"},
        created_by="hunt_v2:test",
    ))

    assert result == {
        "id": str(conn.row["id"]),
        "status": "new",
        "updated_fields": ["severity", "title"],
        "authoritative": False,
        "verified": False,
    }
    assert conn.row["title"] == "Corrected title"
    assert conn.row["latest_verification_id"] is None
    assert len(conn.observations) == 1
    observation_context = conn.observations[0][8]
    assert '"event": "candidate.updated"' in observation_context
    assert '"verification_state_mutated": false' in observation_context


@pytest.mark.parametrize("status", ["verification_queued", "verifying", "verified", "refuted"])
def test_hunt_cannot_edit_candidate_during_or_after_proof(status):
    conn = _CandidateLifecycleConnection(_candidate_row(status=status))
    with pytest.raises(candidates.CandidateLifecycleError):
        asyncio.run(candidates.update_candidate_for_hunt(
            conn,
            hunt_run_id=str(uuid.uuid4()),
            candidate_id=str(conn.row["id"]),
            changes={"title": "Must not change"},
            created_by="hunt_v2:test",
        ))
    assert conn.row["title"] == "Original title"
    assert conn.observations == []


def test_hunt_delete_is_soft_audited_and_idempotent():
    conn = _CandidateLifecycleConnection(_candidate_row())
    hunt_id = str(uuid.uuid4())
    first = asyncio.run(candidates.expire_candidate_for_hunt(
        conn, hunt_run_id=hunt_id, candidate_id=str(conn.row["id"]),
        created_by="hunt_v2:test",
    ))
    second = asyncio.run(candidates.expire_candidate_for_hunt(
        conn, hunt_run_id=hunt_id, candidate_id=str(conn.row["id"]),
        created_by="hunt_v2:test",
    ))

    assert first["status"] == "deleted"
    assert first["candidate_status"] == "expired"
    assert first["recoverable_audit_record"] is True
    assert second["idempotent_replay"] is True
    assert len(conn.observations) == 1
    assert '"event": "candidate.deleted"' in conn.observations[0][8]


def test_hunt_candidate_lifecycle_is_scoped_to_an_observing_run():
    conn = _CandidateLifecycleConnection(None)
    with pytest.raises(candidates.CandidateLifecycleError) as raised:
        asyncio.run(candidates.update_candidate_for_hunt(
            conn,
            hunt_run_id=str(uuid.uuid4()),
            candidate_id=str(uuid.uuid4()),
            changes={"title": "Cross-run edit"},
            created_by="hunt_v2:test",
        ))
    assert raised.value.code == "candidate_not_owned"


def test_candidate_read_api_exposes_lifecycle_without_promotion_authority():
    root = os.path.join(os.path.dirname(__file__), "..")
    api_source = api_tree_source()
    assert route_is_declared("GET", "/investigation/candidates")
    assert route_is_declared("GET", "/investigation/candidates/{candidate_id}")
    assert 'payload["authoritative"] = False' in api_source
    assert "FROM finding_verifications WHERE candidate_id=$1" in api_source
    assert "FROM evidence_instances WHERE candidate_id=$1" in api_source


def test_hunt_candidate_lifecycle_routes_are_declared_and_proof_constrained():
    assert route_is_declared("PATCH", "/hunts/{hunt_id}/candidates/{candidate_id}")
    assert route_is_declared("DELETE", "/hunts/{hunt_id}/candidates/{candidate_id}")
    update_model = definition_source("HuntCandidateUpdateRequest")
    for forbidden in (
        "verified", "proof_state", "latest_verification_verdict", "family", "locus",
    ):
        assert f"{forbidden}:" not in update_model
    update_handler = definition_source("update_hunt_candidate")
    delete_handler = definition_source("delete_hunt_candidate")
    assert "update_candidate_for_hunt" in update_handler
    assert "expire_candidate_for_hunt" in delete_handler
    assert "DELETE FROM investigation_candidates" not in delete_handler


def test_candidate_verification_is_an_approval_bound_canonical_capability():
    specification = CAPABILITY_REGISTRY.require("candidate.verify")
    assert specification.hunt_executor == "inline"
    assert specification.requires_active_approval
    assert specification.target_kinds == frozenset({"web", "api", "device"})
    assert specification.budget_cost == {"tool_wall_seconds": 180}

    verify_handler = route_source(
        "POST", "/hunts/{hunt_id}/candidates/{candidate_id}/verify"
    )
    assert '"candidate.verify"' in verify_handler
    assert "execute_hunt_capability(" in verify_handler
    assert "_execute_hunt_candidate_verification(" not in verify_handler


def test_deep_hunt_claim_persistence_is_candidate_only_and_legacy_rows_are_migrated():
    root = os.path.join(os.path.dirname(__file__), "..")
    persistence_source = definition_source("_persist_agent_suspected_finding")
    assert "upsert_candidate" in persistence_source
    assert "INSERT INTO findings" not in persistence_source

    migration_source = open(
        os.path.join(root, "api", "retest_contract.py"), encoding="utf-8"
    ).read()
    assert 'LEGACY_AUTONOMOUS_CANDIDATE_MIGRATION = "legacy_autonomous_candidates_v1"' in migration_source
    assert "Migrated to Investigation Candidates; this unverified claim is not a finding." in migration_source
