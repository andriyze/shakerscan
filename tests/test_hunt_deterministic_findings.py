import hashlib
import asyncio
import json
import uuid

from api.hunt.deterministic_findings import (
    _verified_xss_fingerprint,
    verified_xss_observations,
    materialize_verified_hunt_findings,
)
from scanner.findings import templated_finding_identity


def test_verified_xss_observations_accept_only_bound_content_free_proof():
    records = verified_xss_observations([
        {
            "kind": "xss_alert",
            "proof_state": "verified",
            "url": "https://app.example.test/search?q=%3Cscript%3E",
            "param": "q",
            "payload_sha256": "a" * 64,
            "message": "raw tool text must not survive",
        },
        {
            "kind": "xss_alert",
            "proof_state": "candidate",
            "url": "https://app.example.test/search?q=signal",
            "payload_sha256": "b" * 64,
        },
        {
            "kind": "xss_alert",
            "proof_state": "verified",
            "url": "https://other.example.test/search?q=proof",
            "payload_sha256": "c" * 64,
        },
    ], target_url="https://app.example.test")

    assert records == [{
        "url": "https://app.example.test/search?q=",
        "path": "/search",
        "param": "q",
        "payload_sha256": "a" * 64,
        "alert_type": None,
    }]


def test_verified_xss_observations_require_payload_receipt():
    assert verified_xss_observations([{
        "kind": "xss_alert",
        "proof_state": "verified",
        "url": "https://app.example.test/search?q=test",
    }], target_url="https://app.example.test") == []


def test_dom_xss_observations_keep_value_free_client_routes_distinct():
    records = verified_xss_observations([
        {
            "kind": "xss_alert",
            "proof_state": "verified",
            "url": "https://app.example.test/",
            "client_route": "/search?q=",
            "payload_sha256": "a" * 64,
        },
        {
            "kind": "xss_alert",
            "proof_state": "verified",
            "url": "https://app.example.test:443/",
            "client_route": "/profile?name=",
            "payload_sha256": "b" * 64,
        },
    ], target_url="https://app.example.test")

    assert [record["url"] for record in records] == [
        "https://app.example.test/#/search?q=",
        "https://app.example.test:443/#/profile?name=",
    ]
    assert len({
        _verified_xss_fingerprint(record, method="GET") for record in records
    }) == 2


def test_reflected_xss_uses_the_canonical_scan_fingerprint():
    proof = {
        "url": "https://app.example.test/search?q=",
        "path": "/search",
        "param": "q",
    }
    identity = templated_finding_identity({
        "cwe": "CWE-79",
        "tool": "dalfox",
        "url": proof["url"],
        "evidence": {"method": "GET", "param": "q"},
    })
    expected = "t:" + hashlib.sha256(identity.encode()).hexdigest()[:16]

    assert _verified_xss_fingerprint(proof, method="GET") == expected


def test_materialized_xss_has_execution_evidence_not_an_invented_impact_score():
    class DB:
        async def fetchval(self, query, *args):
            self.query, self.evidence = query, json.loads(args[4])
            return uuid.uuid4()
        async def execute(self, *args): pass

    db = DB()
    ids = asyncio.run(materialize_verified_hunt_findings(
        db, uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), "https://app.example.test",
        "xss.verify", uuid.uuid4(), {"path": "/search"}, [{
            "kind": "xss_alert", "proof_state": "verified", "param": "q",
            "url": "https://app.example.test/search?q=payload", "payload_sha256": "a" * 64,
        }],
    ))
    assert len(ids) == 1
    assert "'high',NULL" in db.query
    assert "8.1" not in db.query
    assert db.evidence["cvss"]["status"] == "not_assessed"
    assert db.evidence["execution_sink"]["parameter"] == "q"
    assert db.evidence["proof_state"] == "verified"
