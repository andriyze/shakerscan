import asyncio
import os
import uuid

from api import investigation_candidates as candidates


def test_web_and_device_candidate_boundaries_are_mutually_exclusive():
    web = candidates.normalize_candidate(
        plane="web",
        target_id=str(uuid.uuid4()),
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
    assert device["target_id"] is None
    assert device["device_target_id"] is not None


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
        async def fetchrow(self, query, *args):
            assert "investigation_candidates" in query
            return {
                "id": candidate_id,
                "status": "new",
                "fingerprint": args[13],
                "created_at": None,
                "updated_at": None,
            }

    candidate = candidates.normalize_candidate(
        plane="device",
        device_target_id=str(uuid.uuid4()),
        family="service_exposure",
        locus={"transport": "tcp", "port": 80},
        title="HTTP exposed",
        claim="Observed by Device Hunt",
    )
    result = asyncio.run(candidates.upsert_candidate(FakeConnection(), candidate, created_by="test"))

    assert result["id"] == str(candidate_id)
    assert result["authoritative"] is False
    assert result["status"] == "new"


def test_candidate_read_api_exposes_lifecycle_without_promotion_authority():
    root = os.path.join(os.path.dirname(__file__), "..")
    api_source = open(os.path.join(root, "api", "api.py"), encoding="utf-8").read()
    assert '@app.get("/investigation/candidates")' in api_source
    assert '@app.get("/investigation/candidates/{candidate_id}")' in api_source
    assert 'payload["authoritative"] = False' in api_source
    assert "FROM finding_verifications WHERE candidate_id=$1" in api_source
    assert "FROM evidence_instances WHERE candidate_id=$1" in api_source
