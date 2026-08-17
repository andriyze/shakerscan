import asyncio
import os
import uuid

from api import investigation_candidates as candidates


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


def test_candidate_read_api_exposes_lifecycle_without_promotion_authority():
    root = os.path.join(os.path.dirname(__file__), "..")
    api_source = open(os.path.join(root, "api", "api.py"), encoding="utf-8").read()
    assert '@app.get("/investigation/candidates")' in api_source
    assert '@app.get("/investigation/candidates/{candidate_id}")' in api_source
    assert 'payload["authoritative"] = False' in api_source
    assert "FROM finding_verifications WHERE candidate_id=$1" in api_source
    assert "FROM evidence_instances WHERE candidate_id=$1" in api_source


def test_deep_hunt_claim_persistence_is_candidate_only_and_legacy_rows_are_migrated():
    root = os.path.join(os.path.dirname(__file__), "..")
    api_source = open(os.path.join(root, "api", "api.py"), encoding="utf-8").read()
    start = api_source.index("async def _persist_agent_suspected_finding")
    end = api_source.index("\ndef _agent_new_state", start)
    persistence_source = api_source[start:end]
    assert "upsert_candidate" in persistence_source
    assert "INSERT INTO findings" not in persistence_source

    migration_source = open(
        os.path.join(root, "api", "retest_contract.py"), encoding="utf-8"
    ).read()
    assert 'LEGACY_AUTONOMOUS_CANDIDATE_MIGRATION = "legacy_autonomous_candidates_v1"' in migration_source
    assert "Migrated to Investigation Candidates; this unverified claim is not a finding." in migration_source
