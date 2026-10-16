"""Pinned fingerprints: the finding-detail evidence additions (2.11) keep every finding's identity.

The brief needed more evidence (the BOLA object's id key, the XSS client route, the request-body
differential's origin). Fields in the templated identity (a parameter key, a CWE-79 client route,
the finding URL) re-key the stored row on upgrade: verified BOLA and XSS findings would open
duplicates and lose their triage. Each pinned value below is the fingerprint the release/2.11.0
finalizer (before the brief) produced for the same observation; the current finding must still
carry it among its identity keys. Unit fixtures: synthetic observations, no live scan.
"""

from __future__ import annotations

from api.scan.action_plan import ScanActionPlan
from api.scan.finalizer import canonical_authz_findings, finalize_scan_report
from api.scan.finding_identity import canonical_finding_fingerprint, finding_identity_keys
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action

# Fingerprints the release/2.11.0 finalizer gave these observations (computed with that code).
PINNED_BOLA = "t:7f0fe5373e5e3354"
PINNED_XSS_ALERT = "t:be67366ad469721e"
PINNED_REQUEST_XSS = "be859cdab6a50fd0"
PINNED_REQUEST_SQLI = "6113367c77c275d2"

BOLA_OBSERVATION = {
    "kind": "authz_differential", "proof_state": "verified",
    "proof_type": "cross_principal_replay", "principal_contexts_distinct": True,
    "object_absent_from_secondary_listing": True, "responses_equivalent": True,
    "consumer_url": "https://app.example.test/api/orders/7",
    "producer_url": "https://app.example.test/api/orders",
    "resource_id_sha256": "0" * 64, "owner_status": 200, "attacker_status": 200,
    "accepted_principal_responses": {"primary": 200, "secondary": 200},
    # Present on the observation since before 2.11; the brief now shows them.
    "object_id_key": "order_id", "object_id_location": "path",
    "sensitive_field_names": ["email", "address"],
}


def _report(capability: str, rows: tuple[dict, ...]) -> dict:
    action = _action("verify.x", 0, capability_name=capability)
    final = _action("finalize.report", 1, dependencies=(action.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64, target_binding_digest="a" * 64,
        actions=(action, final),
    )
    return finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results={action.action_id: _result_with_observation_count(action, len(rows))},
        observations={action.action_id: rows},
    )


def test_a_verified_bola_finding_keeps_its_fingerprint_and_shows_the_object_facts():
    (finding,) = canonical_authz_findings([BOLA_OBSERVATION], receipt={"receipt_id": "r"})
    assert canonical_finding_fingerprint(finding) == PINNED_BOLA
    assert PINNED_BOLA in finding_identity_keys(finding)
    assert "object_id_key" not in finding["evidence"], "a top-level object_id_key joins the identity"
    assert finding["evidence"]["object"] == {
        "id_key": "order_id", "id_location": "path", "sensitive_field_names": ["email", "address"],
    }
    from api.finding_detail import build_finding_detail
    where = {row["label"]: row["value"] for row in build_finding_detail(finding)["where"]}
    assert where["Object id"] == "order_id in path"
    assert where["Sensitive fields"] == "email, address"


def test_a_verified_xss_alert_keeps_its_fingerprint_with_a_client_route():
    report = _report("xss.verify", ({
        "kind": "xss_alert", "proof_state": "verified", "url": "https://app.example.test/search",
        "param": "q", "alert_type": "alert", "client_route": "/results?q=",
    },))
    (finding,) = report["findings"]
    assert canonical_finding_fingerprint(finding) == PINNED_XSS_ALERT
    assert "client_route" not in finding["evidence"], "a top-level client_route joins a CWE-79 identity"
    assert finding["evidence"]["browser_alert"] == {"alert_type": "alert", "client_route": "/results?q="}


def test_request_body_differentials_keep_their_fingerprints_and_their_origin():
    for capability, family, proof, pinned in (
        ("xss.request_verify", "xss", "reflected_candidate_only", PINNED_REQUEST_XSS),
        ("sqli.request_verify", "sqli", "db_error_candidate_only", PINNED_REQUEST_SQLI),
    ):
        report = _report(capability, ({
            "kind": "request_body_verification", "family": family, "candidate_id": "c",
            "request_ref_id": "r", "method": "POST", "origin": "https://app.example.test",
            "request_class": "json_body", "field_path": "comment",
            "proof_status": proof, "finding_verdict": "suspected",
        },))
        (finding,) = report["findings"]
        assert finding["url"] is None
        assert canonical_finding_fingerprint(finding) == pinned
        assert finding["evidence"]["origin"] == "https://app.example.test"
        from api.finding_detail import build_finding_detail
        brief = build_finding_detail(finding)
        assert "https://app.example.test" in brief["summary"]
