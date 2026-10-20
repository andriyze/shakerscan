"""A missing-header finding is never evidenced by an error page.

Unit fixture modelled on recorded scan evidence from an API service whose root answers 404 while
/info and /version answer 200 without the headers: each template finding carried the root's 404
as its "recorded response", and its page said the origin "answered 404 without" the header and
told the reader to curl the 404 root.
"""

from __future__ import annotations

from api.finding_detail import build_finding_detail
from api.scan.action_plan import ScanActionPlan
from api.scan.finalizer import finalize_scan_report
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action

ORIGIN = "http://api.fixture.invalid:2375"


def _report(root_status: int):
    baseline = _action("baseline.http", 0, capability_name="http.request")
    templates = _action("passive.templates", 1, dependencies=(baseline.action_id,),
                        capability_name="templates.passive_batch")
    final = _action("finalize.report", 2, dependencies=(templates.action_id,))
    plan = ScanActionPlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64, target_binding_digest="a" * 64,
                          actions=(baseline, templates, final))
    matches = tuple({
        "kind": "template_match", "template_id": "http-missing-security-headers",
        "name": "HTTP Missing Security Headers", "severity": "info",
        "matched_at": f"{ORIGIN}{path}", "matcher_name": "x-content-type-options",
    } for path in ("/info", "/version"))
    observations = {
        baseline.action_id: ({
            "kind": "http_observation",
            "request": {"method": "GET", "origin": ORIGIN, "path": "/"},
            "response": {"status": root_status, "security_headers": {"server": "Docker/19.03.12 (linux)"},
                         "selected_headers": {}},
        },),
        templates.action_id: matches,
    }
    results = {baseline.action_id: _result_with_observation_count(baseline, 1),
               templates.action_id: _result_with_observation_count(templates, len(matches))}
    report = finalize_scan_report(plan=plan, target_url=ORIGIN, action_results=results, observations=observations)
    return [item for item in report["findings"]
            if item["evidence"].get("template_id") == "http-missing-security-headers"]


def test_an_error_root_is_not_attached_as_the_recorded_response():
    findings = _report(404)
    assert findings, "the template finding on /info and /version is kept"
    for finding in findings:
        assert "observed_response" not in finding["evidence"]
        assert finding["proof_state"] != "verified"


def test_an_application_root_is_still_attached():
    findings = _report(200)
    assert findings and findings[0]["evidence"]["observed_response"]["response_status"] == 200


def _recorded_finding(observed_status):
    return {"tool": "nuclei", "severity": "info", "url": f"{ORIGIN}/", "proof_state": "suspected",
            "title": "Missing HTTP response header: X-Content-Type-Options",
            "evidence": {"template_id": "http-missing-security-headers", "header_name": "x-content-type-options",
                         "matched_at": f"{ORIGIN}/", "matched_urls": [f"{ORIGIN}/info", f"{ORIGIN}/version"],
                         "matched_url_count": 2,
                         "observed_response": {"request_line": f"GET {ORIGIN}/", "response_status": observed_status,
                                               "observed_headers": {"server": "fixture/1.0, Docker/19.03.12 (linux)"},
                                               "header_absent": "x-content-type-options"}}}


def test_a_stored_error_response_is_not_shown_and_the_commands_use_a_matched_page():
    brief = build_finding_detail(_recorded_finding(404))
    assert "404" not in brief["summary"]
    assert not [fact for fact in brief["observed"] if fact["label"] in {"Response status", "Request"}]
    assert f"{ORIGIN}/info" in brief["reproduce"]["command"]
    assert f"{ORIGIN}/info" in brief["verify"]["command"]


def test_without_a_recorded_response_the_commands_use_a_matched_page():
    finding = _recorded_finding(200)
    del finding["evidence"]["observed_response"]
    brief = build_finding_detail(finding)
    assert f"{ORIGIN}/info" in brief["reproduce"]["command"]


def test_an_application_response_is_still_the_evidence():
    brief = build_finding_detail(_recorded_finding(200))
    assert "answered 200" in brief["summary"]
    assert any(fact["label"] == "Response status" and fact["value"] == "200" for fact in brief["observed"])
