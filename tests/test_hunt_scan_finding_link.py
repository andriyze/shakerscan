"""A Hunt proof of an exposure the Scan already proved links to the Scan's finding, never a second row."""
import asyncio
import json
import uuid

from api.finding_routes import trusted_workflow_promotion as promotion

TARGET = uuid.uuid4()
SCAN_FINDING = uuid.uuid4()
HYPOTHESIS = uuid.uuid4()


def _rows(url="https://honey.example.test/id_rsa", tool="shakerscan_exposure_probe"):
    return [{"id": SCAN_FINDING, "status": "active", "tool": tool, "cwe": "CWE-538",
             "title": "Sensitive exposure: private key material", "url": url, "evidence": {}, "request": {}}]


def test_the_scan_finding_for_the_same_url_and_exposure_family_is_the_record():
    assert promotion.scan_record_for_hunt_proof(_rows(), family="data_exposure", route="/id_rsa")["id"] == SCAN_FINDING
    # Aliases of the family, a trailing slash, and an id segment normalize alike.
    assert promotion.scan_record_for_hunt_proof(
        _rows("https://h.test/backup/"), family="sensitive_data_exposure", route="/backup")
    assert promotion.scan_record_for_hunt_proof(_rows(), family="bola", route="/id_rsa") is None
    assert promotion.scan_record_for_hunt_proof(_rows(), family="data_exposure", route="/.env") is None
    assert promotion.scan_record_for_hunt_proof(_rows(tool="nuclei"), family="data_exposure", route="/id_rsa") is None


def test_a_hunt_proof_is_added_to_the_scan_finding_instead_of_a_new_row(monkeypatch):
    executed = []

    class Conn:
        async def fetchrow(self, query, *args):
            if "FROM hypotheses" in query:
                return {"id": HYPOTHESIS, "target_id": TARGET, "family": "data_exposure",
                        "title": "SSH key served publicly", "description": "", "severity_guess": "critical",
                        "metadata_json": {"dedupe_dimensions": {"route": "/id_rsa", "method": "GET"}}}
            if "FROM research_decisions" in query:
                return {"decision_id": uuid.uuid4(), "episode_id": uuid.uuid4(), "campaign_id": uuid.uuid4()}
            return None

        async def fetch(self, query, *args):
            assert "FROM findings" in query
            return _rows()

        async def fetchval(self, query, *args):
            raise AssertionError("no new finding row: " + query)

        async def execute(self, query, *args):
            executed.append((query, args))
            return "UPDATE 1"

    monkeypatch.setattr(promotion.family_proof, "promotion_gate", lambda _proof: (True, None))
    # The vulnerability keys differ (the Scan's probe classifies the file): the key match finds
    # nothing, as on a live install.
    monkeypatch.setattr(promotion, "_finding_vulnerability_key", lambda _row: None)
    proof = {"family": "data_exposure", "verdict": "verified", "proof_routes": ["/id_rsa"],
             "proof_methods": ["GET"], "stable_predicates": ["sensitive_value_present"]}
    promoted = asyncio.run(promotion.promote_trusted_workflow_finding(
        Conn(), target_uuid=TARGET, target_url="https://honey.example.test",
        hypothesis_id=str(HYPOTHESIS), workflow_id=str(uuid.uuid4()), proof=proof,
        first={}, replay={}, evidence_instance_id=None, tool_receipt_id=None,
    ))
    assert promoted is None
    assert proof["known_finding_id"] == str(SCAN_FINDING)
    link = next(args for query, args in executed if "hunt_corroboration" in query)
    assert link[0] == SCAN_FINDING
    added = json.loads(link[1])[0]
    assert added["source"] == "hunt" and added["hypothesis_id"] == str(HYPOTHESIS)
    assert any("status='dead'" in query for query, _ in executed)
