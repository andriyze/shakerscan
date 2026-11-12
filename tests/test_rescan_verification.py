"""A later Scan that re-checked an open passive finding's own URL and no longer saw it proves it fixed.

The exposure probe now records, per URL it read, the status and the class it matched (``examined``
on its attempt record); the finalizer collects those reads and each origin's baseline response
(``check_coverage``). For an open exposure or missing-header finding the Scan did not report
again, a read of the same URL that the check could judge and that no longer matched is a
``likely_fixed`` verification (mode ``scan_rescan``). Nothing else is: an unread URL, a service's
answer, a soft-404 set-aside read, the same class again, an error page or another principal.

Rows are unit fixtures under fixture hostnames; the exposure batch runs over a fake transport.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
import uuid

import scan.action_adapter as action_adapter_module
from runtime.models import ScanPolicy
from runtime.request_replay_executor import ReplayTransportResult
from scan.action_plan import ScanActionPlan
from scan.finalizer import scan_check_coverage
from scan.rescan_verification import rescan_verdict, rescan_verdicts

from tests.test_exposure_probe_batch_controls import DOTENV, _manifest
from tests.test_scan_action_adapter import Backend, _action, _dispatcher, _lease, _noop

ORIGIN = "https://app.example.test"
SITE = "http://shop.fixture.invalid"


def _exposure(path: str, exposure_class: str = "environment_secret_file") -> dict:
    url = SITE + path
    return {"id": uuid.uuid4(), "tool": "shakerscan_exposure_probe", "url": url, "target_url": SITE,
            "evidence": {"exposure_class": exposure_class, "request_url": url, "response_status": 200,
                         "matched_signature": "fixture", "discovered_via": "seed_path"}}


def _header(header: str = "content-security-policy", *, principal: str = "anonymous", path: str = "/") -> dict:
    return {"id": uuid.uuid4(), "tool": "http_baseline", "url": SITE, "target_url": SITE,
            "evidence": {"check": f"missing_header_{header}", "header": header, "url": SITE,
                         "observed_response": {"request_line": f"GET {SITE}{path}", "response_status": 200,
                                               "principal": principal, "header_absent": header}}}


def _coverage(exposure=(), headers=()) -> dict:
    return {"schema_version": "scan-check-coverage/v1", "exposure": list(exposure), "baseline_headers": list(headers)}


def _read(path, status, exposure_class=None):
    return {"url": SITE + path, "response_status": status, "exposure_class": exposure_class}


def _baseline(path="/", status=200, present=(), principal="anonymous"):
    return {"request_line": f"GET {SITE}{path}", "response_status": status, "principal": principal,
            "present_headers": sorted(present)}


# --- the decision ------------------------------------------------------------------------------

def test_an_exposure_read_again_without_its_class_is_fixed():
    finding = _exposure("/.env")
    for status, seen in ((404, None), (200, None), (403, None), (302, None), (200, "directory_listing")):
        proof = rescan_verdict(finding, _coverage([_read("/.env", status, seen)]))
        assert proof is not None and proof["response_status"] == status, (status, seen)
        assert proof["request"] == f"GET {SITE}/.env" and proof["expected_exposure_class"] == "environment_secret_file"


def test_an_exposure_is_not_fixed_by_a_scan_that_did_not_judge_its_url():
    finding = _exposure("/.env")
    assert rescan_verdict(finding, _coverage([_read("/.env", 200, "environment_secret_file")])) is None
    assert rescan_verdict(finding, _coverage([_read("/.env.local", 404)])) is None  # another URL
    assert rescan_verdict(finding, _coverage()) is None  # the check did not run
    for status in (408, 429, 502, 503, 504):
        assert rescan_verdict(finding, _coverage([_read("/.env", status)])) is None


def test_a_missing_header_seen_on_the_same_page_is_fixed():
    finding = _header()
    proof = rescan_verdict(finding, _coverage(headers=[_baseline(present={"content-security-policy"})]))
    assert proof == {
        "check": "http.header_check", "request": f"GET {SITE}/", "response_status": 200,
        "header": "content-security-policy", "header_present": True,
        "reason": "The Scan's baseline request to the same page now answered with the header.",
    }
    landing = _header(path="/login")
    assert rescan_verdict(landing, _coverage(headers=[_baseline("/login", 200, {"content-security-policy"})]))


def test_a_header_is_not_fixed_without_the_same_page_answering_with_it():
    finding = _header()
    assert rescan_verdict(finding, _coverage(headers=[_baseline(present={"referrer-policy"})])) is None
    assert rescan_verdict(finding, _coverage(headers=[_baseline(status=500, present={"content-security-policy"})])) is None
    assert rescan_verdict(finding, _coverage(headers=[_baseline("/other", present={"content-security-policy"})])) is None
    signed_in = _header(principal="primary")
    assert rescan_verdict(signed_in, _coverage(headers=[_baseline(present={"content-security-policy"})])) is None


def test_findings_the_check_cannot_repeat_exactly_are_never_closed_by_a_rescan():
    archive = _exposure("/site.zip", "backup_or_source_artifact")
    archive["evidence"]["matched_signature"] = "backup_archive_magic"
    sqli = {"id": uuid.uuid4(), "tool": "sqlmap", "url": SITE + "/q", "evidence": {"type": "sqli"}}
    everything = _coverage([_read("/site.zip", 404), _read("/q", 404)], [_baseline(present={"x"})])
    assert rescan_verdicts([archive, sqli], everything) == []
    assert rescan_verdicts([_exposure("/.env")], {"exposure": [_read("/.env", 404)]}) == []  # no schema


# --- the coverage record -----------------------------------------------------------------------

def test_the_coverage_keeps_only_reads_the_check_could_judge():
    def attempt(url, status, cls=None, **extra):
        return {"kind": "candidate_attempt", "family": "sensitive_exposure",
                "examined": {"request_url": url, "response_status": status, "exposure_class": cls, **extra}}

    observations = {
        "verify.exposure": [
            attempt(SITE + "/.env", 404), attempt(SITE + "/.git/config", 200, "version_control_exposure"),
            attempt(SITE + "/slow", None), attempt(SITE + "/busy", 503),
            attempt(SITE + "/catchall", 200, None, indistinguishable_from_absent=True),
            {"kind": "sensitive_exposure_proof", "request_url": SITE + "/x"},
        ],
        "other": [attempt(SITE + "/elsewhere", 404)],
        "baseline.http": [{
            "kind": "http_observation",
            "request": {"origin": SITE, "method": "GET", "path": "/"},
            "response": {"status": 200, "security_headers": {"content-security-policy": "default-src 'self'"},
                         "selected_headers": {"server": "nginx", "referrer-policy": ""}},
        }],
    }
    coverage = scan_check_coverage(observations, {"verify.exposure": "exposure.verify_batch",
                                                  "other": "templates.passive_batch", "baseline.http": "http.request"})
    assert coverage["exposure"] == [
        {"url": SITE + "/.env", "response_status": 404, "exposure_class": None},
        {"url": SITE + "/.git/config", "response_status": 200, "exposure_class": "version_control_exposure"},
    ]
    assert coverage["baseline_headers"] == [{
        "request_line": f"GET {SITE}/", "response_status": 200, "principal": "anonymous",
        "present_headers": ["content-security-policy", "server"],
    }]


def test_the_exposure_batch_records_what_each_read_examined(monkeypatch):
    class Transport:
        async def send(self, request, *, target, timeout_seconds, follow_redirects):
            status, body = (200, DOTENV) if request.url == f"{ORIGIN}/.env" else (404, b"not found")
            return ReplayTransportResult(
                status_code=status, connected_address="192.0.2.10", final_url=request.url,
                response_headers={"Content-Type": "text/plain"}, response_body=body, elapsed_ms=5,
            )

    scan_id = str(uuid.uuid4())
    manifest = _manifest(scan_id, ("/app",))
    monkeypatch.setattr(action_adapter_module, "PinnedAiohttpReplayTransport", lambda **_: Transport())
    action = _action("verify.exposure", "exposure.verify_batch", 0, capability_args={
        "endpoint_manifest_ref": manifest.reference().canonical_dict(), "slice": {"start": 0, "count": 100},
        "profile": "balanced", "proof_policy": "deterministic_proof_contract_required",
    })
    action = replace(action, requested_budget={"http_requests": 180, "tool_wall_seconds": 180}, action_digest=None)
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=action.target_binding_digest, actions=(action,))
    backend = Backend(manifests={manifest.manifest_id: manifest})
    receipt = asyncio.run(_dispatcher(plan, backend, policy=ScanPolicy())(action, _lease(plan, action), _noop))
    observations = [dict(item) for item in receipt.observations] if hasattr(receipt, "observations") else []
    if not observations:
        observations = [dict(item) for item in backend.observations.get(action.action_id, ())]
    examined = {item["examined"]["request_url"]: item["examined"] for item in observations
                if item.get("kind") == "candidate_attempt" and item.get("examined")}
    assert examined[f"{ORIGIN}/.env"] == {"request_url": f"{ORIGIN}/.env", "response_status": 200,
                                         "exposure_class": "environment_secret_file"}
    assert examined[f"{ORIGIN}/.git/config"]["response_status"] == 404
    assert examined[f"{ORIGIN}/.git/config"]["exposure_class"] is None
