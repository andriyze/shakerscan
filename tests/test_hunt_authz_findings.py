"""The existing authz proof must survive Hunt settlement as a queryable finding.

These are materialization/contract tests, not an autonomous discovery benchmark.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
import hashlib
import json
import uuid

import pytest

from api.hunt.deterministic_findings import materialize_verified_hunt_findings

ORIGIN = "https://app.example.test:8443"
HUNT, ACTION, TARGET, RECEIPT = (uuid.uuid4() for _ in range(4))


def proof(**overrides):
    return {
        "kind": "authz_differential", "proof_state": "verified",
        "proof_type": "cross_principal_replay", "method": "GET",
        "principal_contexts_distinct": True,
        "object_absent_from_secondary_listing": True, "responses_equivalent": True,
        "producer_url": ORIGIN + "/api/orders",
        "consumer_url": ORIGIN + "/api/orders/<owner-object>",
        "resource_id_sha256": hashlib.sha256(b"101").hexdigest(),
        "owner_status": 200, "attacker_status": 200,
        "accepted_principal_responses": {
            "owner_listing_status": 200, "attacker_listing_status": 200,
            "owner_replay_status": 200, "attacker_replay_status": 200,
        },
        "sensitive_field_names": ["email"], "secret_values_visible": False,
        **overrides,
    }


class DB:
    def __init__(self):
        self.writes = []
        self.finding_id = uuid.uuid4()

    async def fetchval(self, query, *args):
        self.writes.append((query, args))
        return self.finding_id

    async def execute(self, query, *args):
        self.writes.append((query, args))


def materialize(observations, *, capability="authz.verify", target_url=ORIGIN, target_kind="api"):
    db = DB()
    result = asyncio.run(materialize_verified_hunt_findings(
        db, HUNT, ACTION, TARGET, target_url, capability, RECEIPT,
        {"proof_state": "verified", "severity": "critical"}, observations,
        target_kind=target_kind,
    ))
    return result, db


def test_verified_authz_becomes_an_attributed_deterministic_finding():
    ids, db = materialize([proof()])
    assert ids == [str(db.finding_id)]
    query, args = db.writes[0]
    assert "hunt_run_id" in query and args[:2] == (TARGET, HUNT)
    evidence = json.loads(args[4])
    assert evidence["canonical_capability"] == "authz.verify"
    assert evidence["hunt_id"] == str(HUNT)
    assert evidence["source_action_id"] == str(ACTION)
    assert evidence["tool_receipt_id"] == str(RECEIPT)
    assert evidence["distinct_principal_control"] is True
    assert evidence["object_id_absent_from_attacker_listing"] is True
    assert evidence["responses_equivalent"] is True
    assert any("INSERT INTO finding_verifications" in sql for sql, _ in db.writes)
    assert "UPDATE targets" in db.writes[-1][0]


@pytest.mark.parametrize("overrides", [
    {"proof_state": "inconclusive"}, {"proof_type": "selected_object_comparison"},
    {"mode": "selected_object"}, {"principal_contexts_distinct": False},
    {"object_absent_from_secondary_listing": False}, {"responses_equivalent": False},
    {"owner_status": 500}, {"attacker_status": 403}, {"attacker_status": True},
    {"resource_id_sha256": "not-a-digest"}, {"accepted_principal_responses": {}},
    {"consumer_url": "https://other.example.test/api/orders/1"},
    {"consumer_url": "https://app.example.test/api/orders/1"},
    {"producer_url": "https://other.example.test/api/orders"},
    {"consumer_url": "https://user:secret@app.example.test:8443/api/orders/1"},
    {"consumer_url": ORIGIN + "/api/orders/1#fragment"},
])
def test_incomplete_cross_access_or_unbound_proof_never_becomes_a_finding(overrides):
    ids, db = materialize([proof(**overrides)])
    assert ids == [] and db.writes == []


def test_failed_secondary_listing_cannot_supply_an_absence_control():
    item = proof()
    item["accepted_principal_responses"]["attacker_listing_status"] = 500
    ids, db = materialize([item])
    assert ids == [] and not db.writes


def test_other_capability_cannot_launder_an_authz_observation():
    ids, db = materialize([proof()], capability="http.request")
    assert ids == [] and not db.writes


def test_raw_fields_are_not_copied_and_duplicate_proofs_do_not_duplicate_findings():
    item = proof(raw_body="PRIVATE BODY", headers={"Authorization": "PRIVATE TOKEN"})
    ids, db = materialize([item, deepcopy(item)])
    assert len(ids) == 1
    evidence = json.loads(db.writes[0][1][4])
    assert "PRIVATE" not in json.dumps(evidence)
    assert evidence["proof_state"] == "verified"


def test_device_web_interface_uses_existing_device_finding_and_verification_tables():
    ids, db = materialize([proof()], target_kind="device")
    assert len(ids) == 1
    assert all("device_target_id" in sql for sql, _ in db.writes)
    assert "UPDATE device_targets" in db.writes[-1][0]


def test_http_worker_materializes_inside_settlement_and_retains_the_ids():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / "api/worker.py").read_text()
    http = source.split("async def process_canonical_http_capability_job(", 1)[1].split("async def process_job(", 1)[0]
    assert http.index("terminalize_hunt_capability(") < http.index("await materialize_verified_hunt_findings(")
    assert http.index("await materialize_verified_hunt_findings(") < http.index("await reservation_store.persist_terminal(")
    assert "verified_finding_ids=verified_finding_ids" in http
    assert '"verified_finding_ids": verified_finding_ids' in http
    assert 'authz_base if capability_name == "authz.verify" else target_url' in http


def test_http_summary_keeps_accounting_and_persisted_finding_identity():
    from types import SimpleNamespace
    from api.hunt.http_outcome import http_action_result
    row = http_action_result(
        status="success", error=None, partial=False, timed_out=False,
        observations=[proof()], parser_errors=[], requested={"http_requests": 4},
        terminal=SimpleNamespace(actual={"http_requests": 4}, status="committed"),
        reconciled={"http_requests": 9}, reservation_id="reservation-1", receipt_id=RECEIPT,
        session=None, verified_finding_ids=["finding-1"],
    )
    assert row["verified_finding_ids"] == ["finding-1"]
    assert row["budget_consumed"] == {"http_requests": 4}
    assert row["budget_accounting"]["used_after_reconciliation"] == {"http_requests": 9}
    assert row["receipt_id"] == str(RECEIPT)
    assert "observations" not in row and row["record_count"] == 1
